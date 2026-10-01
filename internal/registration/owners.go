package registration

// Registration ownership (ADR-IAM-003, TDD-identity-control-003 §Registration Ownership): the people
// who may act on a client registration besides a provider. An owner is an active human Principal,
// counted only while its mapping is active, so a Principal retired or quarantined confers nothing
// from the next request. A provider grants and revokes ownership, each with a reason, and nothing is
// deleted: a revoked ownership is the record of who could act on a client, and until when.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// MinProductionOwners is how many active owners a production registration keeps (ADR-IAM-003 §5.1).
const MinProductionOwners = 2

var (
	// ErrOwnerNotEligible is an ownership granted to a Principal that is not an active person.
	ErrOwnerNotEligible = errors.New("registration: an owner must be an active human Principal")

	// ErrAlreadyOwner is a second active ownership of the same Principal.
	ErrAlreadyOwner = errors.New("registration: the Principal already owns this registration")

	// ErrOwnerNotFound is a revocation naming no active ownership.
	ErrOwnerNotFound = errors.New("registration: the Principal holds no active ownership of this registration")

	// ErrTooFewOwners is a revocation that would leave a production registration fewer than
	// MinProductionOwners.
	ErrTooFewOwners = errors.New("registration: a production registration keeps at least two owners; grant another first")
)

// Owner is one ownership, active or revoked.
type Owner struct {
	ID           id.UUID    `json:"ownership_id"`
	Registration id.UUID    `json:"registration_id"`
	Principal    id.UUID    `json:"principal_id"`
	GrantedBy    id.UUID    `json:"granted_by"`
	GrantReason  string     `json:"grant_reason"`
	GrantedAt    time.Time  `json:"granted_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokedBy    *id.UUID   `json:"revoked_by"`
	RevokeReason string     `json:"revoke_reason,omitempty"`

	// Active is whether the ownership confers anything now: not revoked, and its Principal an
	// active person.
	Active bool `json:"active"`
}

// OwnershipChange is a grant or a revocation: which registration and Principal, who asks, and why.
type OwnershipChange struct {
	RegistrationID id.UUID
	Principal      id.UUID
	ChangedBy      id.UUID
	Reason         string
}

func (c OwnershipChange) validate() error {
	switch {
	case c.RegistrationID.IsNil() || c.Principal.IsNil() || c.ChangedBy.IsNil():
		return fmt.Errorf("%w: an ownership change names the registration, the Principal and who asks", ErrInvalid)
	case strings.TrimSpace(c.Reason) == "":
		return fmt.Errorf("%w: an ownership change requires a reason", ErrInvalid)
	}
	return nil
}

// activeOwner is the predicate every ownership read shares: not revoked, and the owner's mapping an
// active human one.
const activeOwner = `o.revoked_at IS NULL AND EXISTS (
    SELECT 1 FROM identity.principal_mapping m
    WHERE m.principal_id = o.principal_id AND m.subject_type = 'human' AND m.state = 'active')`

const ownsStatement = `SELECT EXISTS (
    SELECT 1 FROM identity.registration_owner o
    JOIN identity.client_registration r ON r.registration_id = o.registration_id
    WHERE o.registration_id = $1 AND o.principal_id = $2 AND r.realm = $3 AND ` + activeOwner + `)`

// Owns reports whether the Principal holds an active ownership of the registration.
func (s *Service) Owns(ctx context.Context, principal, registrationID id.UUID) (bool, error) {
	var owns bool
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, ownsStatement, registrationID.String(), principal.String(), string(s.cfg.Realm)).Scan(&owns)
	})
	if err != nil {
		return false, fmt.Errorf("registration: read ownership: %w", err)
	}
	return owns, nil
}

var mineStatement = `SELECT r.registration_id::text, ` + registrationColumns + `
FROM identity.client_registration r
JOIN identity.registration_owner o ON o.registration_id = r.registration_id
WHERE r.realm = $1 AND o.principal_id = $2 AND ` + activeOwner + `
ORDER BY r.registration_id`

// Mine lists the registrations the Principal owns, in creation order.
func (s *Service) Mine(ctx context.Context, principal id.UUID) ([]Registration, error) {
	var out []Registration
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		out = []Registration{}
		rows, err := tx.Query(ctx, mineStatement, string(s.cfg.Realm), principal.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw string
				row scannedRow
			)
			if err := rows.Scan(append([]any{&raw}, row.targets()...)...); err != nil {
				return err
			}
			if row.registration.ID, err = id.Parse(raw); err != nil {
				return err
			}
			registration, err := row.finish()
			if err != nil {
				return err
			}
			out = append(out, registration)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("registration: list owned registrations: %w", err)
	}
	return out, nil
}

const ownersStatement = `SELECT o.ownership_id::text, o.principal_id::text, o.granted_by::text, o.grant_reason, o.granted_at,
       o.revoked_at, coalesce(o.revoked_by::text, ''), coalesce(o.revoke_reason, ''), ` + activeOwner + `
FROM identity.registration_owner o
WHERE o.registration_id = $1
ORDER BY o.granted_at DESC`

func readOwners(ctx context.Context, tx db.Tx, registrationID id.UUID) ([]Owner, error) {
	rows, err := tx.Query(ctx, ownersStatement, registrationID.String())
	if err != nil {
		return nil, fmt.Errorf("registration: read owners: %w", err)
	}
	defer rows.Close()
	owners := []Owner{}
	for rows.Next() {
		var (
			owner                                    Owner
			ownershipID, principal, grantedBy, revBy string
		)
		if err := rows.Scan(&ownershipID, &principal, &grantedBy, &owner.GrantReason, &owner.GrantedAt,
			&owner.RevokedAt, &revBy, &owner.RevokeReason, &owner.Active); err != nil {
			return nil, fmt.Errorf("registration: scan an owner: %w", err)
		}
		for _, field := range []struct {
			raw  string
			into *id.UUID
		}{{ownershipID, &owner.ID}, {principal, &owner.Principal}, {grantedBy, &owner.GrantedBy}} {
			if *field.into, err = id.Parse(field.raw); err != nil {
				return nil, err
			}
		}
		if revBy != "" {
			parsed, err := id.Parse(revBy)
			if err != nil {
				return nil, err
			}
			owner.RevokedBy = &parsed
		}
		owner.Registration = registrationID
		owner.GrantedAt = owner.GrantedAt.UTC()
		owners = append(owners, owner)
	}
	return owners, rows.Err()
}

// Owners lists a registration's ownerships, newest first, revoked ones included.
func (s *Service) Owners(ctx context.Context, registrationID id.UUID) ([]Owner, error) {
	var owners []Owner
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := s.read(ctx, tx, registrationID); err != nil {
			return err
		}
		var err error
		owners, err = readOwners(ctx, tx, registrationID)
		return err
	})
	return owners, err
}

const lockOwnedRegistrationStatement = `SELECT state FROM identity.client_registration
WHERE registration_id = $1 AND realm = $2
FOR UPDATE`

const eligibleOwnerStatement = `SELECT EXISTS (
    SELECT 1 FROM identity.principal_mapping
    WHERE principal_id = $1 AND subject_type = 'human' AND state = 'active')`

const grantOwnerStatement = `WITH inserted AS (
    INSERT INTO identity.registration_owner (ownership_id, registration_id, principal_id, granted_by, grant_reason)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (registration_id, principal_id) WHERE revoked_at IS NULL DO NOTHING
    RETURNING ownership_id)
SELECT count(*) FROM inserted`

// lockState reads a registration's state under its row lock, so ownership changes to one
// registration apply one after the other.
func (s *Service) lockState(ctx context.Context, tx db.Tx, registrationID id.UUID) (string, error) {
	rows, err := tx.Query(ctx, lockOwnedRegistrationStatement, registrationID.String(), string(s.cfg.Realm))
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
	var state string
	if err := rows.Scan(&state); err != nil {
		return "", err
	}
	return state, nil
}

// GrantOwner makes the Principal an owner of the registration. It is refused for a Principal that is
// not an active person, for a retired registration, and for a Principal that already owns it.
func (s *Service) GrantOwner(ctx context.Context, change OwnershipChange) ([]Owner, error) {
	if err := change.validate(); err != nil {
		return nil, err
	}
	ownershipID, err := s.newID()
	if err != nil {
		return nil, fmt.Errorf("registration: mint ownership_id: %w", err)
	}
	var owners []Owner
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		state, err := s.lockState(ctx, tx, change.RegistrationID)
		if err != nil {
			return err
		}
		if state == StateRetired {
			return fmt.Errorf("%w: a retired registration takes no new owner", ErrInvalidTransition)
		}
		var eligible bool
		if err := tx.QueryRow(ctx, eligibleOwnerStatement, change.Principal.String()).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return ErrOwnerNotEligible
		}
		var inserted int
		if err := tx.QueryRow(ctx, grantOwnerStatement, ownershipID.String(), change.RegistrationID.String(),
			change.Principal.String(), change.ChangedBy.String(), strings.TrimSpace(change.Reason)).Scan(&inserted); err != nil {
			return err
		}
		if inserted == 0 {
			return ErrAlreadyOwner
		}
		owners, err = readOwners(ctx, tx, change.RegistrationID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return owners, nil
}

// remainingOwnersStatement counts the active owners other than the Principal, and whether the
// Principal is itself an active owner: revoking an ownership that confers nothing leaves the active
// owners as they were, so only the revocation of an active one is held to the minimum.
const remainingOwnersStatement = `SELECT
    count(*) FILTER (WHERE o.principal_id <> $2),
    coalesce(bool_or(o.principal_id = $2), false)
FROM identity.registration_owner o
WHERE o.registration_id = $1 AND ` + activeOwner

const revokeOwnerStatement = `UPDATE identity.registration_owner
SET revoked_at = $3, revoked_by = $4, revoke_reason = $5
WHERE registration_id = $1 AND principal_id = $2 AND revoked_at IS NULL`

// RevokeOwner ends the Principal's ownership. In production it is refused when it would leave fewer
// than MinProductionOwners active owners.
func (s *Service) RevokeOwner(ctx context.Context, change OwnershipChange) ([]Owner, error) {
	if err := change.validate(); err != nil {
		return nil, err
	}
	var owners []Owner
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := s.lockState(ctx, tx, change.RegistrationID); err != nil {
			return err
		}
		if s.cfg.Production {
			var (
				remaining int
				counted   bool
			)
			if err := tx.QueryRow(ctx, remainingOwnersStatement, change.RegistrationID.String(),
				change.Principal.String()).Scan(&remaining, &counted); err != nil {
				return err
			}
			if counted && remaining < MinProductionOwners {
				return ErrTooFewOwners
			}
		}
		tag, err := tx.Exec(ctx, revokeOwnerStatement, change.RegistrationID.String(), change.Principal.String(),
			s.now(), change.ChangedBy.String(), strings.TrimSpace(change.Reason))
		if err != nil {
			return fmt.Errorf("registration: revoke the ownership: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrOwnerNotFound
		}
		owners, err = readOwners(ctx, tx, change.RegistrationID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return owners, nil
}
