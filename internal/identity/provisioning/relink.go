package provisioning

// Portability (TDD-identity-control-001 §Data Model, §Reconciliation Sweep): a Principal outlives
// its Keycloak user. The user can be deleted in the console, or lost with a realm rebuilt from
// nothing, and the principal_id every domain keys on, with every Membership held under it, must
// survive that. The sweep finds such a mapping and reports it; only an operator's :relink, with a
// reason, returns it to pending, where recovery adopts or recreates a user carrying the same
// principal_id.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

var (
	// ErrUserStillExists refuses a relink while the mapped user exists: relinking would only find
	// that same user again, and would hide whatever made someone think it was gone.
	ErrUserStillExists = errors.New("provisioning: the mapped Keycloak user still exists")

	// ErrReasonRequired refuses a relink that names no reason.
	ErrReasonRequired = errors.New("provisioning: a relink requires a reason")
)

// RelinkRequest is an operator returning an active mapping whose user is gone to pending.
type RelinkRequest struct {
	PrincipalID id.UUID
	RelinkedBy  id.UUID
	Reason      string
}

// RelinkResult is where the mapping ended: active under a new user when recovery completed at
// once, pending when it did not and the scheduled recovery will.
type RelinkResult struct {
	PrincipalID id.UUID `json:"principal_id"`
	State       State   `json:"state"`
}

const mappingCountStatement = `SELECT count(*) FROM identity.principal_mapping WHERE principal_id = $1`

const relinkStatement = `UPDATE identity.principal_mapping
SET keycloak_user_id = NULL, state = 'pending', version = version + 1
WHERE principal_id = $1 AND state = 'active' AND keycloak_user_id = $2`

const relinkRecordStatement = `INSERT INTO identity.principal_relink
    (relink_id, principal_id, previous_keycloak_user_id, relinked_by, reason)
VALUES ($1, $2, $3, $4, $5)`

const resolveFindingStatement = `UPDATE identity.principal_finding
SET resolved_at = now(), resolution = $2
WHERE principal_id = $1 AND resolved_at IS NULL`

// Relink returns an active mapping whose Keycloak user no longer exists to pending, records who did
// it and why, and runs recovery for it at once.
func (p *Provisioner) Relink(ctx context.Context, req RelinkRequest) (RelinkResult, error) {
	if strings.TrimSpace(req.Reason) == "" {
		return RelinkResult{}, ErrReasonRequired
	}
	if req.RelinkedBy.IsNil() {
		return RelinkResult{}, errors.New("provisioning: the relinking Principal is required")
	}

	mapping, err := p.find(ctx, req.PrincipalID)
	if err != nil {
		return RelinkResult{}, err
	}
	if mapping.SubjectType == keycloak.SubjectWorkload {
		return RelinkResult{}, ErrWorkloadPath
	}
	if mapping.State != StateActive || !mapping.State.CanTransitionTo(StatePending) {
		return RelinkResult{}, fmt.Errorf("%w: a %s mapping cannot be relinked", ErrInvalidTransition, mapping.State)
	}

	callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
	_, getErr := p.kernel.GetUser(callCtx, mapping.Realm, mapping.KeycloakUserID)
	cancel()
	switch {
	case getErr == nil:
		return RelinkResult{}, ErrUserStillExists
	case !errors.Is(getErr, keycloak.ErrNotFound):
		// Unreachable, or refused: an unknown answer is not an absent user.
		return RelinkResult{}, fmt.Errorf("provisioning: confirm the mapped user is gone: %w", getErr)
	}

	relinkID, err := p.newID()
	if err != nil {
		return RelinkResult{}, fmt.Errorf("provisioning: mint relink_id: %w", err)
	}
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, relinkStatement, mapping.PrincipalID.String(), string(mapping.KeycloakUserID))
		if err != nil {
			return fmt.Errorf("provisioning: return the mapping to pending: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: the mapping changed while it was being relinked", ErrInvalidTransition)
		}
		if _, err := tx.Exec(ctx, relinkRecordStatement, relinkID.String(), mapping.PrincipalID.String(),
			string(mapping.KeycloakUserID), req.RelinkedBy.String(), req.Reason); err != nil {
			return fmt.Errorf("provisioning: record the relink: %w", err)
		}
		_, err = tx.Exec(ctx, resolveFindingStatement, mapping.PrincipalID.String(), "relinked")
		return err
	}); err != nil {
		return RelinkResult{}, err
	}
	p.logger.WarnContext(ctx, "an active mapping was relinked; its Keycloak user was gone",
		slog.String("principal_id", mapping.PrincipalID.String()))

	mapping.KeycloakUserID, mapping.State = "", StatePending
	if err := p.recoverOne(ctx, mapping); err != nil {
		// The mapping is pending and durable. The scheduled recovery finishes what this did not.
		p.logger.WarnContext(ctx, "recovery after the relink did not complete; the scheduled recovery will retry",
			slog.String("principal_id", mapping.PrincipalID.String()), slog.String("error", err.Error()))
	}
	after, err := p.find(ctx, mapping.PrincipalID)
	if err != nil {
		return RelinkResult{}, err
	}
	return RelinkResult{PrincipalID: after.PrincipalID, State: after.State}, nil
}

func (p *Provisioner) find(ctx context.Context, principalID id.UUID) (Mapping, error) {
	var mapping Mapping
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, mappingCountStatement, principalID.String()).Scan(&count); err != nil {
			return fmt.Errorf("provisioning: find mapping: %w", err)
		}
		if count == 0 {
			return ErrNotFound
		}
		var err error
		mapping, err = p.repo.Find(ctx, tx, principalID)
		return err
	})
	return mapping, err
}

// DanglingFinding is an active Principal whose Keycloak user is gone.
type DanglingFinding struct {
	PrincipalID id.UUID   `json:"principal_id"`
	DetectedAt  time.Time `json:"detected_at"`
}

// activeBeforeStatement is every active mapping in the realm activated before the enumeration
// began. One activated during it may point at a user the enumeration's pages had already passed.
const activeBeforeStatement = `SELECT principal_id::text, keycloak_user_id FROM identity.principal_mapping
WHERE realm = $1 AND state = 'active' AND activated_at < $2`

const insertDanglingStatement = `INSERT INTO identity.principal_finding
    (finding_id, principal_id, finding_class, keycloak_user_id)
VALUES ($1, $2, 'dangling', $3)
ON CONFLICT (principal_id) WHERE resolved_at IS NULL DO NOTHING`

// danglingPages bounds one enumeration. A realm larger than this is read over several sweeps
// by nothing yet, so the sweep refuses it rather than report users past the bound as missing.
const danglingPages = 1000

// FindDangling enumerates the realm's users and records a finding for every active mapping whose
// user is not among them. It never relinks: a user deleted on purpose, by an administrator removing
// someone's access, must not come back within one interval with nobody having decided it. A mapping
// whose user is present again has its open finding resolved. An enumeration that fails part way
// records nothing, because an unread page is not a missing user.
func (p *Provisioner) FindDangling(ctx context.Context) (int, error) {
	if p.cfg.Realm == "" {
		return 0, errors.New("provisioning: a realm is required to find dangling mappings")
	}
	started := time.Now().UTC()
	present := map[keycloak.UserID]bool{}
	for page := 0; ; page++ {
		if page == danglingPages {
			return 0, errors.New("provisioning: the realm holds more users than one enumeration reads")
		}
		callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
		users, err := p.kernel.ListUsers(callCtx, p.cfg.Realm, keycloak.Page{First: page * p.cfg.RecoveryBatch, Max: p.cfg.RecoveryBatch})
		cancel()
		if err != nil {
			return 0, fmt.Errorf("provisioning: enumerate users: %w", err)
		}
		for _, user := range users {
			present[user.ID] = true
		}
		if len(users) < p.cfg.RecoveryBatch {
			break
		}
	}

	found := 0
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, activeBeforeStatement, string(p.cfg.Realm), started)
		if err != nil {
			return fmt.Errorf("provisioning: read active mappings: %w", err)
		}
		type active struct {
			principal string
			user      string
		}
		var mappings []active
		for rows.Next() {
			var m active
			if err := rows.Scan(&m.principal, &m.user); err != nil {
				rows.Close()
				return err
			}
			mappings = append(mappings, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, m := range mappings {
			if present[keycloak.UserID(m.user)] {
				if _, err := tx.Exec(ctx, resolveFindingStatement, m.principal, "user_present"); err != nil {
					return err
				}
				continue
			}
			findingID, err := p.newID()
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, insertDanglingStatement, findingID.String(), m.principal, m.user)
			if err != nil {
				return fmt.Errorf("provisioning: record a dangling mapping: %w", err)
			}
			found++
			if tag.RowsAffected() == 1 {
				p.logger.ErrorContext(ctx, "an active Principal's Keycloak user is gone; relinking it is an operator's decision",
					slog.String("principal_id", m.principal))
			}
		}
		return nil
	})
	return found, err
}

const openDanglingStatement = `SELECT principal_id::text, detected_at FROM identity.principal_finding
WHERE resolved_at IS NULL ORDER BY detected_at`

// Dangling lists the open dangling-mapping findings.
func (p *Provisioner) Dangling(ctx context.Context) ([]DanglingFinding, error) {
	out := []DanglingFinding{}
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, openDanglingStatement)
		if err != nil {
			return fmt.Errorf("provisioning: read dangling mappings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw     string
				finding DanglingFinding
			)
			if err := rows.Scan(&raw, &finding.DetectedAt); err != nil {
				return err
			}
			if finding.PrincipalID, err = id.Parse(raw); err != nil {
				return err
			}
			out = append(out, finding)
		}
		return rows.Err()
	})
	return out, err
}

// Reconcile runs pending recovery and the dangling-mapping sweep, as the schedule does.
func (p *Provisioner) Reconcile(ctx context.Context) (recovered, dangling int, err error) {
	if recovered, err = p.RecoverPending(ctx); err != nil {
		return 0, 0, err
	}
	dangling, err = p.FindDangling(ctx)
	return recovered, dangling, err
}
