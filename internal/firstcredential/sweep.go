package firstcredential

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// DefaultSweepInterval is how often the lapse sweep runs unless configured. The sweep takes an issuance
// up to one interval before its lapse, so a temporary password is removed by its lapse, never after,
// and the 24 hours STD-IAM-001 2.8.0 §3.1 allows hold.
const DefaultSweepInterval = 5 * time.Minute

// sweepBatch bounds one sweep's kernel calls.
const sweepBatch = 50

// setWindow is how long after its recorded issue a password credential can still be the one the
// issuance set: the kernel call follows the record within one call timeout. A password created later
// is one the person chose, and the sweep never deletes it.
func (s *Service) setWindow() time.Duration { return s.cfg.CallTimeout + time.Minute }

// dueStatement reads open issuances that lapse before the next sweep, oldest first. No row is locked: the outcome's
// primary key lets one sweep record it, and every kernel call the sweep makes is safe to repeat.
const dueStatement = `SELECT i.issuance_id::text, i.principal_id::text, i.issued_at, coalesce(m.keycloak_user_id, '')
FROM identity.temporary_password_issuance i
JOIN identity.principal_mapping m ON m.principal_id = i.principal_id
WHERE i.lapses_at <= $1 AND m.realm = $3
  AND NOT EXISTS (SELECT 1 FROM identity.temporary_password_outcome o WHERE o.issuance_id = i.issuance_id)
ORDER BY i.lapses_at, i.issuance_id
LIMIT $2`

// SweepResult counts what one sweep ended.
type SweepResult struct {
	Lapsed int
	Used   int
}

type due struct {
	issuance  id.UUID
	principal id.UUID
	issuedAt  time.Time
	user      keycloak.UserID
}

// Sweep ends every issuance past its lapse (ADR-IAM-010 §5.2):
//   - the user no longer owes UPDATE_PASSWORD: the person replaced the value, and it is used;
//   - otherwise the password the issuance set is deleted, and it is lapsed.
//
// Only a password credential created within the set window of the issuance is deleted, so a password
// the person chose in the moment between the two reads is kept. The authenticator guard's
// last_authenticator rule does not apply: the person never held this credential
// (TDD-identity-control-005 §Authenticator Guard).
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var (
		result SweepResult
		list   []due
	)
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, dueStatement, s.now().UTC().Add(s.cfg.SweepInterval), sweepBatch, string(s.cfg.Realm))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				d                   due
				issuance, principal string
				user                string
			)
			if err := rows.Scan(&issuance, &principal, &d.issuedAt, &user); err != nil {
				return err
			}
			if d.issuance, err = id.Parse(issuance); err != nil {
				return err
			}
			if d.principal, err = id.Parse(principal); err != nil {
				return err
			}
			d.user = keycloak.UserID(user)
			list = append(list, d)
		}
		return rows.Err()
	})
	if err != nil {
		return result, fmt.Errorf("firstcredential: read the lapsed issuances: %w", err)
	}
	var failures []error
	for _, d := range list {
		outcome, err := s.lapse(ctx, d)
		if err != nil {
			failures = append(failures, err)
			s.logger.WarnContext(ctx, "a lapsed temporary password could not be removed; the next sweep retries",
				slog.String("issuance_id", d.issuance.String()), slog.String("error", err.Error()))
			continue
		}
		s.recordOutcome(ctx, d.issuance, outcome)
		switch outcome {
		case OutcomeUsed:
			result.Used++
		case OutcomeLapsed:
			result.Lapsed++
			// ADR-IAM-010 §6 Operational: an issuance that lapses unused is reported to its provider.
			s.logger.WarnContext(ctx, "a temporary password lapsed unused and was removed",
				slog.String("issuance_id", d.issuance.String()), slog.String("principal_id", d.principal.String()))
		}
	}
	return result, errors.Join(failures...)
}

func (s *Service) lapse(ctx context.Context, d due) (string, error) {
	if d.user == "" {
		// The mapping lost its kernel user: nothing holds the value.
		return OutcomeLapsed, nil
	}
	callCtx, cancel := s.call(ctx)
	actions, err := s.kernel.UserRequiredActions(callCtx, s.cfg.Realm, d.user)
	cancel()
	switch {
	case errors.Is(err, keycloak.ErrNotFound):
		return OutcomeLapsed, nil
	case err != nil:
		return "", err
	case !keycloak.OwesPassword(actions):
		return OutcomeUsed, nil
	}
	callCtx, cancel = s.call(ctx)
	credentials, err := s.kernel.UserCredentials(callCtx, s.cfg.Realm, d.user)
	cancel()
	if err != nil {
		return "", err
	}
	latest := d.issuedAt.Add(s.setWindow())
	for _, credential := range credentials {
		if credential.Type != keycloak.PasswordCredential || credential.Created.After(latest) {
			continue
		}
		callCtx, cancel = s.call(ctx)
		err := s.kernel.DeleteCredential(callCtx, s.cfg.Realm, d.user, credential.ID)
		cancel()
		if err != nil && !errors.Is(err, keycloak.ErrNotFound) {
			return "", err
		}
	}
	return OutcomeLapsed, nil
}

// usedStatement records the person's own password change as the use of every open issuance of the
// Principal issued before it.
const usedStatement = `INSERT INTO identity.temporary_password_outcome (issuance_id, outcome, recorded_at)
SELECT i.issuance_id, 'used', $3
FROM identity.temporary_password_issuance i
JOIN identity.principal_mapping m ON m.principal_id = i.principal_id
WHERE m.keycloak_user_id = $1 AND m.realm = $2 AND i.issued_at <= $3
  AND NOT EXISTS (SELECT 1 FROM identity.temporary_password_outcome o WHERE o.issuance_id = i.issuance_id)
ON CONFLICT (issuance_id) DO NOTHING`

// FromKernelEvent records an issuance used when the kernel event record shows the person's own
// password change: a user UPDATE_CREDENTIAL naming the password (TDD-identity-control-008 §Technical
// Context). It runs in the kernel event sweep's transaction, for an event recorded the first time.
func (s *Service) FromKernelEvent(ctx context.Context, tx db.Tx, realm keycloak.Realm, e keycloak.KernelEvent) error {
	if e.Kind != keycloak.KindUserEvent || e.Error != "" || e.Type != "UPDATE_CREDENTIAL" ||
		e.Details["credential_type"] != keycloak.PasswordCredential || e.UserID == "" {
		return nil
	}
	if _, err := tx.Exec(ctx, usedStatement, e.UserID, string(realm), e.Time.UTC()); err != nil {
		return fmt.Errorf("firstcredential: record a temporary password used: %w", err)
	}
	return nil
}
