package workload

// Rebuilding a workload's client (TDD-identity-control-004 1.5.0 §Rebuilding a Workload's Client).
// A workload's client deleted in the console took its service-account user, and with it the
// workload's identity in the kernel. An operator's reconcile refuses to recreate it, because the new
// client's service-account user would carry no principal_id. The rebuild recreates it under the same
// principal_id and keys, writes the workload's identity on the new service-account user, and binds
// the mapping to it, all inside one transaction; a client created on the way to a failure is deleted
// again.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/anshacerbia2/foundation-platform/db"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

// ErrClientPresent is a rebuild of a workload whose client the kernel still holds.
var ErrClientPresent = errors.New("workload: the workload's client still exists; there is nothing to rebuild")

// rebindStatement points a workload's mapping at its rebuilt client's service-account user. The old
// user is in the predicate, so a mapping that moved meanwhile is left alone.
const rebindStatement = `UPDATE identity.principal_mapping
SET keycloak_user_id = $2, username = $3, version = version + 1
WHERE principal_id = $1 AND subject_type = 'workload' AND state = 'active' AND keycloak_user_id = $4`

const rebuildRelinkStatement = `INSERT INTO identity.principal_relink
    (relink_id, principal_id, previous_keycloak_user_id, relinked_by, reason)
VALUES ($1, $2, $3, $4, $5)`

const resolveDanglingStatement = `UPDATE identity.principal_finding
SET resolved_at = now(), resolution = 'relinked'
WHERE principal_id = $1 AND finding_class = 'dangling' AND resolved_at IS NULL`

const workloadUserStatement = `SELECT coalesce(keycloak_user_id, '') FROM identity.principal_mapping
WHERE principal_id = $1 AND subject_type = 'workload' AND state = 'active' FOR UPDATE`

// Rebuild recreates an active or orphaned workload's deleted client, with a reason.
func (s *Service) Rebuild(ctx context.Context, req LifecycleRequest) (Workload, error) {
	if req.automatic {
		return Workload{}, fmt.Errorf("%w: a rebuild is never automatic", ErrInvalid)
	}
	if err := req.validate(); err != nil {
		return Workload{}, err
	}
	current, err := s.Get(ctx, req.PrincipalID)
	if err != nil {
		return Workload{}, err
	}
	if current.State != StateActive && current.State != StateOrphaned {
		return Workload{}, fmt.Errorf("%w: only an active or orphaned workload's client is rebuilt; this one is %s",
			ErrInvalidTransition, current.State)
	}
	_, client, err := s.registrar.Client(ctx, current.RegistrationID)
	if err != nil {
		return Workload{}, err
	}
	if client != "" {
		_, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.Client, error) {
			return s.clients.GetClient(ctx, s.cfg.Realm, client)
		})
		switch {
		case err == nil:
			return Workload{}, ErrClientPresent
		case !errors.Is(err, keycloak.ErrNotFound):
			// Unreachable, or refused: an unknown answer is not an absent client.
			return Workload{}, fmt.Errorf("workload: confirm the client is gone: %w", err)
		}
	}
	relinkID, err := s.newID()
	if err != nil {
		return Workload{}, fmt.Errorf("workload: mint relink_id: %w", err)
	}

	var created keycloak.ClientUUID
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lock(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		if locked.State != StateActive && locked.State != StateOrphaned {
			return fmt.Errorf("%w: only an active or orphaned workload's client is rebuilt; this one is %s",
				ErrInvalidTransition, locked.State)
		}
		var previous string
		if err := tx.QueryRow(ctx, workloadUserStatement, req.PrincipalID.String()).Scan(&previous); err != nil {
			return fmt.Errorf("workload: read the workload's mapping: %w", err)
		}
		if created, err = s.registrar.RebuildWorkloadClientWithin(ctx, tx, req.change(locked.RegistrationID)); err != nil {
			return err
		}
		serviceAccount, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.User, error) {
			return s.clients.ServiceAccountUser(ctx, s.cfg.Realm, created)
		})
		if err != nil {
			return fmt.Errorf("workload: read the rebuilt client's service-account user: %w", err)
		}
		if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
			return struct{}{}, s.users.WriteWorkloadIdentity(ctx, s.cfg.Realm, serviceAccount.ID, req.PrincipalID, locked.Owner)
		}); err != nil {
			return fmt.Errorf("workload: write the workload's identity: %w", err)
		}
		tag, err := tx.Exec(ctx, rebindStatement, req.PrincipalID.String(), string(serviceAccount.ID), serviceAccount.Username, previous)
		if err != nil {
			return fmt.Errorf("workload: bind the mapping: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: the workload's mapping changed while its client was rebuilt", ErrInvalidTransition)
		}
		if _, err := tx.Exec(ctx, rebuildRelinkStatement, relinkID.String(), req.PrincipalID.String(), previous,
			req.ChangedBy.String(), strings.TrimSpace(req.Reason)); err != nil {
			return fmt.Errorf("workload: record the move to the new user: %w", err)
		}
		if _, err := tx.Exec(ctx, resolveDanglingStatement, req.PrincipalID.String()); err != nil {
			return fmt.Errorf("workload: resolve the dangling mapping: %w", err)
		}
		return nil
	})
	if err != nil {
		if created != "" {
			if discardErr := s.registrar.DiscardClient(ctx, created); discardErr != nil {
				s.logger.ErrorContext(ctx, "a rebuild failed and the client it created could not be deleted; "+
					"delete it before rebuilding again", slog.String("principal_id", req.PrincipalID.String()),
					slog.String("error", discardErr.Error()))
			}
		}
		if errors.Is(err, registration.ErrClientHeld) {
			return Workload{}, ErrClientPresent
		}
		return Workload{}, err
	}
	s.logger.WarnContext(ctx, "a workload's deleted client was rebuilt under the same principal_id",
		slog.String("principal_id", req.PrincipalID.String()), slog.String("by", req.ChangedBy.String()))
	return s.Get(ctx, req.PrincipalID)
}
