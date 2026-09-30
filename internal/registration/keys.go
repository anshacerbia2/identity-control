package registration

// A confidential or workload client's public keys: registered with the client, rotated by adding the
// next before the previous is removed, and revoked at once when one leaks (TDD-identity-control-003
// §Client Key Records, §Client Key Rotation, ADR-IAM-001 §5.12).
//
// identity.client_key is desired state for the keys. Every change is made inside one transaction
// that holds the registration's row lock: the rows are written, the kernel client's JWKS is rebuilt
// from the active and retiring rows, and only then does the transaction commit. A kernel that
// refuses or cannot be reached rolls the rows back, so the table never records a key the kernel was
// not given. A lost response after the kernel applied the change leaves the kernel ahead of the
// table, and the same request sent again converges them, because the JWKS written is a function of
// the rows alone.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// Key states.
const (
	KeyActive   = "active"
	KeyRetiring = "retiring"
	KeyRevoked  = "revoked"
)

var (
	// ErrNotKeyed is a key operation on a public client or a resource, which hold no key.
	ErrNotKeyed = errors.New("registration: only a confidential or workload client holds keys")

	// ErrNotActive is a key operation on a registration that is not active.
	ErrNotActive = errors.New("registration: the registration is not active")

	// ErrKeyInUse is a key already registered, to this client or any other. One key pair never
	// authenticates two clients, and a revoked key is never registered again.
	ErrKeyInUse = errors.New("registration: the key is already registered")

	// ErrRotationInProgress is a second rotation while a key is still retiring: one overlap at a time.
	ErrRotationInProgress = errors.New("registration: a key is still retiring; one rotation at a time")

	// ErrKeyNotLive is a revocation of a key that is already revoked, or not this client's.
	ErrKeyNotLive = errors.New("registration: the key is not an active or retiring key of this registration")
)

// Key is one registered public key, as the API reports it. It carries the public key only: nothing
// else was ever submitted.
type Key struct {
	ID               id.UUID         `json:"key_id"`
	Registration     id.UUID         `json:"registration_id"`
	KID              string          `json:"kid"`
	Thumbprint       string          `json:"thumbprint"`
	PublicJWK        json.RawMessage `json:"public_jwk"`
	State            string          `json:"state"`
	RegisteredBy     id.UUID         `json:"registered_by"`
	RegisteredAt     time.Time       `json:"registered_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	RetiringAt       *time.Time      `json:"retiring_at"`
	RevokedAt        *time.Time      `json:"revoked_at"`
	RevokedBy        *id.UUID        `json:"revoked_by"`
	RevocationReason string          `json:"revocation_reason,omitempty"`
}

// keyed reports whether a profile authenticates with a registered key.
func keyed(profile string) bool { return profile == ProfileConfidential || profile == ProfileWorkload }

const thumbprintOwnerStatement = `SELECT registration_id::text, state FROM identity.client_key WHERE thumbprint = $1`

const insertKeyStatement = `INSERT INTO identity.client_key
    (key_id, registration_id, kid, thumbprint, public_jwk, state, registered_by, registered_at, expires_at)
VALUES ($1, $2, $3, $4, $5::jsonb, 'active', $6, $7, $8)`

// insertKey records a validated key as its registration's active key.
func (s *Service) insertKey(ctx context.Context, tx db.Tx, registrationID id.UUID, key PublicKey, by id.UUID, now time.Time) error {
	keyID, err := s.newID()
	if err != nil {
		return fmt.Errorf("registration: mint key_id: %w", err)
	}
	jwk, err := json.Marshal(map[string]string{"kty": "RSA", "kid": key.JWK.KID, "use": "sig", "alg": "PS256",
		"n": key.JWK.N, "e": key.JWK.E})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, insertKeyStatement, keyID.String(), registrationID.String(), key.JWK.KID, key.Thumbprint,
		string(jwk), by.String(), now, now.Add(s.cfg.KeyLifetime)); err != nil {
		return fmt.Errorf("registration: record the key: %w", err)
	}
	return nil
}

// thumbprintOwner is the registration a key is registered to and its state there, or a nil
// registration when no client holds it.
func thumbprintOwner(ctx context.Context, tx db.Tx, thumbprint string) (id.UUID, string, error) {
	rows, err := tx.Query(ctx, thumbprintOwnerStatement, thumbprint)
	if err != nil {
		return id.UUID{}, "", fmt.Errorf("registration: check the key: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return id.UUID{}, "", rows.Err()
	}
	var raw, state string
	if err := rows.Scan(&raw, &state); err != nil {
		return id.UUID{}, "", err
	}
	owner, err := id.Parse(raw)
	return owner, state, err
}

const liveKeysStatement = `SELECT kid, public_jwk->>'n', public_jwk->>'e' FROM identity.client_key
WHERE registration_id = $1 AND state IN ('active', 'retiring')
ORDER BY state = 'active' DESC, registered_at DESC`

// liveKeys is the JWKS the kernel client should hold: the active key, then the retiring one.
func liveKeys(ctx context.Context, tx db.Tx, registrationID id.UUID) ([]keycloak.JWK, error) {
	rows, err := tx.Query(ctx, liveKeysStatement, registrationID.String())
	if err != nil {
		return nil, fmt.Errorf("registration: read the keys: %w", err)
	}
	defer rows.Close()
	keys := []keycloak.JWK{}
	for rows.Next() {
		var key keycloak.JWK
		if err := rows.Scan(&key.KID, &key.N, &key.E); err != nil {
			return nil, fmt.Errorf("registration: scan a key: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

const keysStatement = `SELECT key_id::text, kid, thumbprint, public_jwk::text, state, registered_by::text, registered_at,
       expires_at, retiring_at, revoked_at, revoked_by::text, coalesce(revocation_reason, '')
FROM identity.client_key
WHERE registration_id = $1
ORDER BY registered_at DESC, key_id DESC`

func readKeys(ctx context.Context, tx db.Tx, registrationID id.UUID) ([]Key, error) {
	rows, err := tx.Query(ctx, keysStatement, registrationID.String())
	if err != nil {
		return nil, fmt.Errorf("registration: read the keys: %w", err)
	}
	defer rows.Close()
	keys := []Key{}
	for rows.Next() {
		var (
			key                         Key
			rawID, jwk, rawRegisteredBy string
			rawRevokedBy                *string
			registeredAt, expiresAt     time.Time
			retiringAt, revokedAt       *time.Time
		)
		if err := rows.Scan(&rawID, &key.KID, &key.Thumbprint, &jwk, &key.State, &rawRegisteredBy, &registeredAt,
			&expiresAt, &retiringAt, &revokedAt, &rawRevokedBy, &key.RevocationReason); err != nil {
			return nil, fmt.Errorf("registration: scan a key: %w", err)
		}
		if key.ID, err = id.Parse(rawID); err != nil {
			return nil, err
		}
		if key.RegisteredBy, err = id.Parse(rawRegisteredBy); err != nil {
			return nil, err
		}
		if rawRevokedBy != nil {
			revokedBy, err := id.Parse(*rawRevokedBy)
			if err != nil {
				return nil, err
			}
			key.RevokedBy = &revokedBy
		}
		key.Registration = registrationID
		key.PublicJWK = json.RawMessage(jwk)
		key.RegisteredAt, key.ExpiresAt = registeredAt.UTC(), expiresAt.UTC()
		key.RetiringAt, key.RevokedAt = utc(retiringAt), utc(revokedAt)
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	at := t.UTC()
	return &at
}

const lockRegistrationStatement = `SELECT profile, state, coalesce(kc_client_id, '') FROM identity.client_registration
WHERE registration_id = $1 AND realm = $2
FOR UPDATE`

// lockKeyed takes the registration's row lock and returns its kernel client, refusing a registration
// that is unknown, holds no key, or is not active. Every key change runs under this lock, so two
// changes to one client's keys are applied one after the other, never interleaved.
func (s *Service) lockKeyed(ctx context.Context, tx db.Tx, registrationID id.UUID) (keycloak.ClientUUID, error) {
	rows, err := tx.Query(ctx, lockRegistrationStatement, registrationID.String(), string(s.cfg.Realm))
	if err != nil {
		return "", fmt.Errorf("registration: lock the registration: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", ErrNotFound
	}
	var profile, state, client string
	if err := rows.Scan(&profile, &state, &client); err != nil {
		return "", err
	}
	switch {
	case !keyed(profile):
		return "", ErrNotKeyed
	case state != "active" || client == "":
		return "", ErrNotActive
	}
	return keycloak.ClientUUID(client), nil
}

// writeKeys gives the kernel client the JWKS the rows now describe. It runs inside the transaction
// that changed the rows, so a refusal rolls them back.
func (s *Service) writeKeys(ctx context.Context, tx db.Tx, registrationID id.UUID, client keycloak.ClientUUID) error {
	keys, err := liveKeys(ctx, tx, registrationID)
	if err != nil {
		return err
	}
	if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, client, keycloak.ClientPatch{Keys: &keys})
	}); err != nil {
		return fmt.Errorf("registration: write the client's keys: %w", err)
	}
	return nil
}

// Keys lists a registration's keys, newest first, revoked ones included: a revoked key is the
// record of which key pair stopped authenticating the client, and when.
func (s *Service) Keys(ctx context.Context, registrationID id.UUID) ([]Key, error) {
	var keys []Key
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := s.read(ctx, tx, registrationID); err != nil {
			return err
		}
		var err error
		keys, err = readKeys(ctx, tx, registrationID)
		return err
	})
	return keys, err
}

const retireActiveKeyStatement = `UPDATE identity.client_key SET state = 'retiring', retiring_at = $2
WHERE registration_id = $1 AND state = 'active'`

const retiringCountStatement = `SELECT count(*) FROM identity.client_key WHERE registration_id = $1 AND state = 'retiring'`

// AddKey registers the next key, which starts a rotation: the new key becomes active, the previous
// active key becomes retiring for IDENTITY_CLIENT_KEY_ROTATION_OVERLAP, and the kernel accepts both
// in between. It reports whether the key was added now, or was already this client's active key,
// which is how a retry of a rotation whose response was lost is answered.
func (s *Service) AddKey(ctx context.Context, registrationID id.UUID, submittedKey json.RawMessage, by id.UUID) ([]Key, bool, error) {
	if by.IsNil() {
		return nil, false, fmt.Errorf("%w: the registering Principal is required", ErrInvalid)
	}
	key, err := parsePublicKey(submittedKey)
	if err != nil {
		return nil, false, err
	}
	var (
		keys  []Key
		added bool
	)
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		added = false
		client, err := s.lockKeyed(ctx, tx, registrationID)
		if err != nil {
			return err
		}
		owner, state, err := thumbprintOwner(ctx, tx, key.Thumbprint)
		switch {
		case err != nil:
			return err
		case owner == registrationID && state == KeyActive:
			keys, err = readKeys(ctx, tx, registrationID)
			return err
		case !owner.IsNil():
			return ErrKeyInUse
		}
		var retiring int
		if err := tx.QueryRow(ctx, retiringCountStatement, registrationID.String()).Scan(&retiring); err != nil {
			return fmt.Errorf("registration: read the retiring key: %w", err)
		}
		if retiring > 0 {
			return ErrRotationInProgress
		}
		now := s.now()
		// The previous key retires before the next is recorded: at most one key is active.
		if _, err := tx.Exec(ctx, retireActiveKeyStatement, registrationID.String(), now.Add(s.cfg.RotationOverlap)); err != nil {
			return fmt.Errorf("registration: retire the previous key: %w", err)
		}
		if err := s.insertKey(ctx, tx, registrationID, key, by, now); err != nil {
			return err
		}
		if err := s.writeKeys(ctx, tx, registrationID, client); err != nil {
			return err
		}
		added = true
		keys, err = readKeys(ctx, tx, registrationID)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	if added {
		s.logger.InfoContext(ctx, "a client key was registered; the previous key is retiring",
			slog.String("registration_id", registrationID.String()), slog.String("kid", key.JWK.KID))
	}
	return keys, added, nil
}

const revokeKeyStatement = `UPDATE identity.client_key
SET state = 'revoked', revoked_at = $3, revoked_by = $4, revocation_reason = $5
WHERE registration_id = $1 AND key_id = $2 AND state IN ('active', 'retiring')`

// RevokeKey removes one key from the client at once, for a key that leaked. Revoking a client's last
// key is permitted: the client stops authenticating until a key is registered, which is the
// containment a compromised key calls for.
func (s *Service) RevokeKey(ctx context.Context, registrationID, keyID, by id.UUID, reason string) ([]Key, error) {
	if by.IsNil() || strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("%w: a revocation names the Principal revoking the key and a reason", ErrInvalid)
	}
	var keys []Key
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		client, err := s.lockKeyed(ctx, tx, registrationID)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, revokeKeyStatement, registrationID.String(), keyID.String(), s.now(), by.String(),
			strings.TrimSpace(reason))
		if err != nil {
			return fmt.Errorf("registration: revoke the key: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrKeyNotLive
		}
		if err := s.writeKeys(ctx, tx, registrationID, client); err != nil {
			return err
		}
		keys, err = readKeys(ctx, tx, registrationID)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.logger.WarnContext(ctx, "a client key was revoked",
		slog.String("registration_id", registrationID.String()), slog.String("key_id", keyID.String()))
	return keys, nil
}

const dueRegistrationsStatement = `SELECT DISTINCT k.registration_id::text
FROM identity.client_key k
JOIN identity.client_registration r ON r.registration_id = k.registration_id
WHERE r.realm = $1 AND r.state = 'active'
  AND ((k.state = 'retiring' AND k.retiring_at <= $2) OR (k.state IN ('active', 'retiring') AND k.expires_at <= $2))
LIMIT 100`

// The reasons a scheduled removal records. Neither names a Principal: nobody decided it at the time.
const (
	overlapEnded  = "the rotation overlap ended"
	lifetimeEnded = "the key's lifetime ended"
)

// The reasons are parameters, never spliced into the statement: one of them carries an apostrophe.
const expireKeysStatement = `UPDATE identity.client_key
SET state = 'revoked', revoked_at = $2,
    revocation_reason = CASE WHEN expires_at <= $2 THEN $3::text ELSE $4::text END
WHERE registration_id = $1
  AND ((state = 'retiring' AND retiring_at <= $2) OR (state IN ('active', 'retiring') AND expires_at <= $2))`

// ExpireKeys removes every key whose rotation overlap or lifetime has ended, from the kernel client
// and then from the rows, and returns how many it removed. The schedule runs it before each sweep,
// so a retiring key is removed at most one IDENTITY_REGISTRATION_RECONCILE_INTERVAL after its
// overlap ends, without anyone remembering to. One registration's failure does not stop the others.
func (s *Service) ExpireKeys(ctx context.Context) (int, error) {
	now := s.now()
	var due []id.UUID
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		due = nil
		rows, err := tx.Query(ctx, dueRegistrationsStatement, string(s.cfg.Realm), now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			registrationID, err := id.Parse(raw)
			if err != nil {
				return err
			}
			due = append(due, registrationID)
		}
		return rows.Err()
	}); err != nil {
		return 0, fmt.Errorf("registration: find expired keys: %w", err)
	}

	removed := 0
	for _, registrationID := range due {
		var count int64
		err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			client, err := s.lockKeyed(ctx, tx, registrationID)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, expireKeysStatement, registrationID.String(), now, lifetimeEnded, overlapEnded)
			if err != nil {
				return fmt.Errorf("registration: expire keys: %w", err)
			}
			if count = tag.RowsAffected(); count == 0 {
				return nil
			}
			return s.writeKeys(ctx, tx, registrationID, client)
		})
		if err != nil {
			s.logger.ErrorContext(ctx, "an expired client key could not be removed; it is retried on the next pass",
				slog.String("registration_id", registrationID.String()), slog.String("error", err.Error()))
			continue
		}
		if count > 0 {
			s.logger.InfoContext(ctx, "expired client keys removed",
				slog.String("registration_id", registrationID.String()), slog.Int64("keys", count))
		}
		removed += int(count)
	}
	return removed, nil
}
