package registration

// Application developer standing (ADR-IAM-003 §5.3, TDD-identity-control-003 §Application
// Developers): a person a provider allows to create non-production registrations, who becomes
// their first owner. The standing is held as an ownership is: granted and revoked by a provider
// with a reason, held only by an active human Principal, and never deleted.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

var (
	// ErrNotDeveloper is a registration by a caller that is neither a provider nor an active
	// application developer.
	ErrNotDeveloper = errors.New("registration: creating a registration requires provider authority or application developer standing")

	// ErrAlreadyDeveloper is a second active grant to the same Principal.
	ErrAlreadyDeveloper = errors.New("registration: the Principal already holds application developer standing")

	// ErrDeveloperNotFound is a revocation naming no active grant.
	ErrDeveloperNotFound = errors.New("registration: the Principal holds no application developer standing")

	// ErrDeveloperScope is a registration an application developer may not create. Its message
	// names the rule.
	ErrDeveloperScope = errors.New("registration: outside what an application developer may register")
)

// The audience classes an application developer registers. privileged carries the provider-scope
// claim surface, and workload is registered through the workload path.
var developerAudienceClasses = []string{"internal", "external"}

// Developer is one grant of application developer standing, active or revoked.
type Developer struct {
	ID           id.UUID    `json:"grant_id"`
	Principal    id.UUID    `json:"principal_id"`
	GrantedBy    id.UUID    `json:"granted_by"`
	GrantReason  string     `json:"grant_reason"`
	GrantedAt    time.Time  `json:"granted_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokedBy    *id.UUID   `json:"revoked_by"`
	RevokeReason string     `json:"revoke_reason,omitempty"`

	// Active is whether the grant confers anything now: not revoked, and its Principal an active
	// person.
	Active bool `json:"active"`
}

// DeveloperChange is a grant or a revocation of the standing: which Principal, who asks, and why.
type DeveloperChange struct {
	Principal id.UUID
	ChangedBy id.UUID
	Reason    string
}

func (c DeveloperChange) validate() error {
	switch {
	case c.Principal.IsNil() || c.ChangedBy.IsNil():
		return fmt.Errorf("%w: a standing change names the Principal and who asks", ErrInvalid)
	case strings.TrimSpace(c.Reason) == "":
		return fmt.Errorf("%w: a standing change requires a reason", ErrInvalid)
	}
	return nil
}

// activeDeveloper is the predicate every standing read shares, as activeOwner is for ownership.
const activeDeveloper = `d.revoked_at IS NULL AND EXISTS (
    SELECT 1 FROM identity.principal_mapping m
    WHERE m.principal_id = d.principal_id AND m.subject_type = 'human' AND m.state = 'active')`

const isDeveloperStatement = `SELECT EXISTS (
    SELECT 1 FROM identity.application_developer d WHERE d.principal_id = $1 AND ` + activeDeveloper + `)`

const developersStatement = `SELECT d.grant_id::text, d.principal_id::text, d.granted_by::text, d.grant_reason,
       d.granted_at, d.revoked_at, coalesce(d.revoked_by::text, ''), coalesce(d.revoke_reason, ''), ` + activeDeveloper + `
FROM identity.application_developer d
ORDER BY d.granted_at DESC
LIMIT 500`

const grantDeveloperStatement = `WITH inserted AS (
    INSERT INTO identity.application_developer (grant_id, principal_id, granted_by, grant_reason)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (principal_id) WHERE revoked_at IS NULL DO NOTHING
    RETURNING grant_id)
SELECT count(*) FROM inserted`

const revokeDeveloperStatement = `UPDATE identity.application_developer
SET revoked_at = now(), revoked_by = $2, revoke_reason = $3
WHERE principal_id = $1 AND revoked_at IS NULL`

// ownsAllStatement counts the audience entries that are resources the Principal owns, among the
// active registrations of the realm.
var ownsAllStatement = `SELECT count(DISTINCT r.client_key)
FROM identity.client_registration r
JOIN identity.registration_owner o ON o.registration_id = r.registration_id
WHERE r.realm = $1 AND r.profile = 'resource' AND r.state <> 'retired'
  AND r.client_key = ANY($3::text[]) AND o.principal_id = $2 AND ` + activeOwner

const firstOwnerReason = "registered it as an application developer"

func isDeveloper(ctx context.Context, tx db.Tx, principal id.UUID) (bool, error) {
	var developer bool
	if err := tx.QueryRow(ctx, isDeveloperStatement, principal.String()).Scan(&developer); err != nil {
		return false, fmt.Errorf("registration: read application developer standing: %w", err)
	}
	return developer, nil
}

// IsApplicationDeveloper reports whether the Principal holds active application developer standing.
func (s *Service) IsApplicationDeveloper(ctx context.Context, principal id.UUID) (bool, error) {
	var developer bool
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		developer, err = isDeveloper(ctx, tx, principal)
		return err
	})
	return developer, err
}

// ApplicationDevelopers lists the grants, newest first, revoked ones included.
func (s *Service) ApplicationDevelopers(ctx context.Context) ([]Developer, error) {
	var developers []Developer
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, developersStatement)
		if err != nil {
			return fmt.Errorf("registration: read application developers: %w", err)
		}
		defer rows.Close()
		developers = []Developer{}
		for rows.Next() {
			var (
				developer                          Developer
				grantID, principal, grantedBy, rev string
			)
			if err := rows.Scan(&grantID, &principal, &grantedBy, &developer.GrantReason, &developer.GrantedAt,
				&developer.RevokedAt, &rev, &developer.RevokeReason, &developer.Active); err != nil {
				return fmt.Errorf("registration: scan an application developer: %w", err)
			}
			for _, field := range []struct {
				raw  string
				into *id.UUID
			}{{grantID, &developer.ID}, {principal, &developer.Principal}, {grantedBy, &developer.GrantedBy}} {
				if *field.into, err = id.Parse(field.raw); err != nil {
					return err
				}
			}
			if rev != "" {
				parsed, err := id.Parse(rev)
				if err != nil {
					return err
				}
				developer.RevokedBy = &parsed
			}
			developer.GrantedAt = developer.GrantedAt.UTC()
			developers = append(developers, developer)
		}
		return rows.Err()
	})
	return developers, err
}

// GrantApplicationDeveloper gives the Principal the standing. It is refused for a Principal that is
// not an active person, and for one that already holds it.
func (s *Service) GrantApplicationDeveloper(ctx context.Context, change DeveloperChange) error {
	if err := change.validate(); err != nil {
		return err
	}
	grantID, err := s.newID()
	if err != nil {
		return fmt.Errorf("registration: mint grant_id: %w", err)
	}
	return s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var eligible bool
		if err := tx.QueryRow(ctx, eligibleOwnerStatement, change.Principal.String()).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return ErrOwnerNotEligible
		}
		var inserted int
		if err := tx.QueryRow(ctx, grantDeveloperStatement, grantID.String(), change.Principal.String(),
			change.ChangedBy.String(), strings.TrimSpace(change.Reason)).Scan(&inserted); err != nil {
			return fmt.Errorf("registration: grant application developer standing: %w", err)
		}
		if inserted == 0 {
			return ErrAlreadyDeveloper
		}
		return nil
	})
}

// RevokeApplicationDeveloper ends the Principal's standing. The registrations it created keep their
// owners: ownership is revoked on its own.
func (s *Service) RevokeApplicationDeveloper(ctx context.Context, change DeveloperChange) error {
	if err := change.validate(); err != nil {
		return err
	}
	return s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, revokeDeveloperStatement, change.Principal.String(), change.ChangedBy.String(),
			strings.TrimSpace(change.Reason))
		if err != nil {
			return fmt.Errorf("registration: revoke application developer standing: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrDeveloperNotFound
		}
		return nil
	})
}

// developerScope refuses what an application developer may not register, before anything is read
// or written. The audience's ownership is checked in the transaction that records the registration.
func (s *Service) developerScope(req Request) error {
	if s.cfg.Production {
		return fmt.Errorf("%w: a production registration is requested, then approved by a provider: POST /v1/registration-requests",
			ErrDeveloperScope)
	}
	return developerBounds(req)
}

// developerBounds is what an application developer may register, wherever it is registered.
func developerBounds(req Request) error {
	refuse := func(rule string) error { return fmt.Errorf("%w: %s", ErrDeveloperScope, rule) }
	switch {
	case req.Profile == ProfileWorkload:
		return refuse("a workload is created by a provider through /v1/workloads")
	case !slices.Contains(developerAudienceClasses, req.AudienceClass):
		return refuse("an application developer registers the internal or external audience class; privileged and workload are a provider's")
	}
	return nil
}

// claimAsDeveloper checks, inside the transaction that records the registration, that the caller
// still holds the standing and owns every resource its audience names, and records the caller as the
// registration's first owner.
func (s *Service) claimAsDeveloper(ctx context.Context, tx db.Tx, req Request, registrationID id.UUID) error {
	developer, err := isDeveloper(ctx, tx, req.RegisteredBy)
	if err != nil {
		return err
	}
	if !developer {
		return ErrNotDeveloper
	}
	if err := s.ownsAudience(ctx, tx, req); err != nil {
		return err
	}
	ownershipID, err := s.newID()
	if err != nil {
		return fmt.Errorf("registration: mint ownership_id: %w", err)
	}
	if _, err := tx.Exec(ctx, grantOwnerStatement, ownershipID.String(), registrationID.String(),
		req.RegisteredBy.String(), req.RegisteredBy.String(), firstOwnerReason); err != nil {
		return fmt.Errorf("registration: record the first owner: %w", err)
	}
	return nil
}

func uniqueStrings(values []string) []string {
	out := []string{}
	for _, value := range values {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

// Standing is what a caller may do with registrations beyond what it owns, as a console needs to
// know before it offers anything: whether it holds application developer standing, and whether this
// deployment is production, where a developer creates nothing.
type Standing struct {
	ApplicationDeveloper bool   `json:"application_developer"`
	Environment          string `json:"environment"`
}

// Standing reads the Principal's standing.
func (s *Service) Standing(ctx context.Context, principal id.UUID) (Standing, error) {
	developer, err := s.IsApplicationDeveloper(ctx, principal)
	if err != nil {
		return Standing{}, err
	}
	environment := "non-production"
	if s.cfg.Production {
		environment = "production"
	}
	return Standing{ApplicationDeveloper: developer, Environment: environment}, nil
}
