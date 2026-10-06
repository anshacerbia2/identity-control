package securitynotify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/securityref"
)

// A person's own notification addresses (ADR-IAM-007 §5.2, TDD-identity-control-008 1.2.0).

// The address limits.
const (
	MaxAddresses     = 5
	maxProofAttempts = 5
	proofDigits      = 8
	maxAddressLength = 254
	// ProofPurpose is what a proof code is sealed for.
	ProofPurpose = "deliver"
)

// The address errors a route answers with.
var (
	ErrInvalidAddress = errors.New("securitynotify: the address is not one bare email address")
	ErrAddressHeld    = errors.New("securitynotify: the address is held already")
	ErrTooMany        = errors.New("securitynotify: the Principal holds the most addresses allowed")
	ErrNoSuchAddress  = errors.New("securitynotify: no such address")
	ErrNotPending     = errors.New("securitynotify: the address is not waiting for a proof")
	ErrWrongCode      = errors.New("securitynotify: the code is wrong, expired or used up")
	ErrLastAddress    = errors.New("securitynotify: the last active address cannot be removed")
)

// Sealer seals a proof code for its request and opens it for the dispatcher: *securityref.Codec.
type Sealer interface {
	Seal(kind securityref.Kind, principal id.UUID, purpose, realm, kernelID string) (string, error)
	Open(handle string, kind securityref.Kind, principal id.UUID, purpose string) (securityref.Ref, error)
}

// Address is one of a person's addresses, as the person reads it.
type Address struct {
	AddressID  id.UUID    `json:"address_id"`
	Channel    string     `json:"channel"`
	Address    string     `json:"address"`
	Origin     string     `json:"origin"`
	State      string     `json:"state"`
	AddedAt    time.Time  `json:"added_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// Addresses serves a person's own addresses.
type Addresses struct {
	tx      Transactor
	sealer  Sealer
	ttl     time.Duration
	newID   func() (id.UUID, error)
	newCode func() (string, error)
	now     func() time.Time
}

// NewAddresses builds the service. ttl is how long a proof code is good for: the securityref lifetime,
// which also bounds the seal.
func NewAddresses(tx Transactor, sealer Sealer, ttl time.Duration) (*Addresses, error) {
	if tx == nil || sealer == nil || ttl <= 0 {
		return nil, errors.New("securitynotify: a transactor, a sealer and a positive proof lifetime are required")
	}
	return &Addresses{tx: tx, sealer: sealer, ttl: ttl, newID: id.NewV7, newCode: proofCode, now: time.Now}, nil
}

func proofCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", proofDigits, n.Int64()), nil
}

// proofHash binds a code to its address, so a code proves the address it was sent to and no other.
func proofHash(addressID id.UUID, code string) string {
	sum := sha256.Sum256([]byte(addressID.String() + "|" + code))
	return hex.EncodeToString(sum[:])
}

// normalized parses one bare addr-spec: no display name, no list.
func normalized(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxAddressLength {
		return "", ErrInvalidAddress
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Name != "" || parsed.Address != raw {
		return "", ErrInvalidAddress
	}
	return raw, nil
}

// Mask shows enough of an address for its owner to recognise it: a***@example.com.
func Mask(address string) string {
	local, domain, found := strings.Cut(address, "@")
	if !found || local == "" {
		return "***"
	}
	return local[:1] + "***@" + domain
}

const listOwnStatement = `SELECT address_id::text, channel, address, origin, state, added_at, verified_at
FROM identity.notification_address
WHERE principal_id = $1 AND state <> 'removed'
ORDER BY added_at, address_id`

// List reads the person's held and pending addresses.
func (a *Addresses) List(ctx context.Context, principal id.UUID) ([]Address, error) {
	out := []Address{}
	err := a.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, listOwnStatement, principal.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				v       Address
				address string
			)
			if err := rows.Scan(&address, &v.Channel, &v.Address, &v.Origin, &v.State, &v.AddedAt, &v.VerifiedAt); err != nil {
				return err
			}
			if v.AddressID, err = id.Parse(address); err != nil {
				return err
			}
			v.AddedAt = v.AddedAt.UTC()
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("securitynotify: list addresses: %w", err)
	}
	return out, nil
}

// lockOwnStatement locks the person's held and pending addresses, so two changes at once are told
// against one set.
const lockOwnStatement = `SELECT address_id::text, address, state
FROM identity.notification_address
WHERE principal_id = $1 AND state <> 'removed'
ORDER BY added_at, address_id
FOR UPDATE`

type held struct {
	id      id.UUID
	address string
	state   string
}

func lockOwn(ctx context.Context, tx db.Tx, principal id.UUID) ([]held, error) {
	rows, err := tx.Query(ctx, lockOwnStatement, principal.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []held
	for rows.Next() {
		var (
			h   held
			raw string
		)
		if err := rows.Scan(&raw, &h.address, &h.state); err != nil {
			return nil, err
		}
		if h.id, err = id.Parse(raw); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

const insertPendingStatement = `INSERT INTO identity.notification_address
    (address_id, principal_id, channel, address, origin, state, proof_hash, proof_expires_at)
VALUES ($1, $2, 'email', $3, 'added', 'pending', $4, $5)`

const insertCommandRequestStatement = `INSERT INTO identity.security_notification
    (notification_id, principal_id, event, source_key, occurred_at, details, recipients, state, sealed_secret)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::uuid[], CASE WHEN cardinality($7::uuid[]) = 0 THEN 'no_address' ELSE 'requested' END, $8)
ON CONFLICT (source_key) DO NOTHING`

func (a *Addresses) request(ctx context.Context, tx db.Tx, principal id.UUID, event, sourceKey string,
	details map[string]string, recipients []id.UUID, sealed *string) error {
	notificationID, err := a.newID()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return err
	}
	ids := make([]string, len(recipients))
	for i, r := range recipients {
		ids[i] = r.String()
	}
	_, err = tx.Exec(ctx, insertCommandRequestStatement, notificationID.String(), principal.String(), event, sourceKey,
		a.now().UTC(), string(encoded), ids, sealed)
	return err
}

// Add records a pending address and requests its proof code, sent to that address alone.
func (a *Addresses) Add(ctx context.Context, principal id.UUID, raw string) (Address, error) {
	address, err := normalized(raw)
	if err != nil {
		return Address{}, err
	}
	addressID, err := a.newID()
	if err != nil {
		return Address{}, err
	}
	code, err := a.newCode()
	if err != nil {
		return Address{}, err
	}
	sealed, err := a.sealer.Seal(securityref.KindNotificationProof, principal, ProofPurpose, "", code)
	if err != nil {
		return Address{}, fmt.Errorf("securitynotify: seal the proof code: %w", err)
	}
	now := a.now().UTC()
	err = a.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		existing, err := lockOwn(ctx, tx, principal)
		if err != nil {
			return err
		}
		if len(existing) >= MaxAddresses {
			return ErrTooMany
		}
		for _, h := range existing {
			if strings.EqualFold(h.address, address) {
				return ErrAddressHeld
			}
		}
		if _, err := tx.Exec(ctx, insertPendingStatement, addressID.String(), principal.String(), address,
			proofHash(addressID, code), now.Add(a.ttl)); err != nil {
			return err
		}
		return a.request(ctx, tx, principal, EventAddressProof, "command:address:"+addressID.String()+":proof",
			map[string]string{"address": Mask(address)}, []id.UUID{addressID}, &sealed)
	})
	if err != nil {
		return Address{}, fmt.Errorf("securitynotify: add an address: %w", err)
	}
	return Address{AddressID: addressID, Channel: "email", Address: address, Origin: "added", State: "pending", AddedAt: now}, nil
}

const readProofStatement = `SELECT proof_hash, proof_expires_at, proof_attempts, address
FROM identity.notification_address
WHERE address_id = $1 AND principal_id = $2 AND state = 'pending'`

const failedAttemptStatement = `UPDATE identity.notification_address SET proof_attempts = proof_attempts + 1 WHERE address_id = $1`

const activateStatement = `UPDATE identity.notification_address
SET state = 'active', verified_at = now(), proof_hash = NULL, proof_expires_at = NULL
WHERE address_id = $1`

// Verify proves a pending address with its code. A wrong code counts an attempt and is committed, so
// guessing is bounded across requests.
func (a *Addresses) Verify(ctx context.Context, principal, addressID id.UUID, code string) error {
	var wrong bool
	err := a.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		existing, err := lockOwn(ctx, tx, principal)
		if err != nil {
			return err
		}
		var before []id.UUID
		found := false
		for _, h := range existing {
			switch {
			case h.id == addressID:
				found = true
			case h.state == "active":
				before = append(before, h.id)
			}
		}
		if !found {
			return ErrNoSuchAddress
		}
		rows, err := tx.Query(ctx, readProofStatement, addressID.String(), principal.String())
		if err != nil {
			return err
		}
		var (
			hash     *string
			expires  *time.Time
			attempts int
			address  string
			pending  = rows.Next()
		)
		if pending {
			err = rows.Scan(&hash, &expires, &attempts, &address)
		}
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
		if err != nil {
			return err
		}
		if !pending || hash == nil || expires == nil {
			return ErrNotPending
		}
		given := proofHash(addressID, strings.TrimSpace(code))
		if attempts >= maxProofAttempts || !a.now().Before(*expires) ||
			subtle.ConstantTimeCompare([]byte(given), []byte(*hash)) != 1 {
			wrong = true
			_, err := tx.Exec(ctx, failedAttemptStatement, addressID.String())
			return err
		}
		if _, err := tx.Exec(ctx, activateStatement, addressID.String()); err != nil {
			return err
		}
		return a.request(ctx, tx, principal, EventAddressChanged, "command:address:"+addressID.String()+":added",
			map[string]string{"change": "added", "address": Mask(address), "actor": ActorSelf}, before, nil)
	})
	if err != nil {
		return fmt.Errorf("securitynotify: verify an address: %w", err)
	}
	if wrong {
		return ErrWrongCode
	}
	return nil
}

const removeStatement = `UPDATE identity.notification_address
SET state = 'removed', removed_at = now(), proof_hash = NULL, proof_expires_at = NULL
WHERE address_id = $1`

// Remove removes an address. Removing an active one notifies every address held before, the removed
// one included; a pending one was never told anything and tells no one. The last active address
// stays.
func (a *Addresses) Remove(ctx context.Context, principal, addressID id.UUID) error {
	err := a.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		existing, err := lockOwn(ctx, tx, principal)
		if err != nil {
			return err
		}
		var (
			target *held
			active []id.UUID
		)
		for i, h := range existing {
			if h.id == addressID {
				target = &existing[i]
			}
			if h.state == "active" {
				active = append(active, h.id)
			}
		}
		if target == nil {
			return ErrNoSuchAddress
		}
		if target.state == "active" && len(active) == 1 {
			return ErrLastAddress
		}
		if _, err := tx.Exec(ctx, removeStatement, addressID.String()); err != nil {
			return err
		}
		if target.state != "active" {
			return nil
		}
		return a.request(ctx, tx, principal, EventAddressChanged, "command:address:"+addressID.String()+":removed",
			map[string]string{"change": "removed", "address": Mask(target.address), "actor": ActorSelf}, active, nil)
	})
	if err != nil {
		return fmt.Errorf("securitynotify: remove an address: %w", err)
	}
	return nil
}
