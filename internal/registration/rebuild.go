package registration

// Rebuilding a workload's client (TDD-identity-control-004 1.5.0 §Rebuilding a Workload's Client). A
// workload's client deleted in the console is not recreated by an operator's reconcile, because a new
// client's service-account user carries no principal_id. The workload rebuilds it instead, and these
// are the registration's half: create the client from desired state inside the workload's
// transaction, and remove it again when that transaction fails.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anshacerbia2/foundation-platform/db"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// ErrClientHeld is a rebuild while a Keycloak client carries the registration's client_key: the
// client is not gone, or a failed rebuild left one an operator must look at.
var ErrClientHeld = errors.New("registration: a Keycloak client carries the client_key")

// rebuiltFindingStatement closes the registration's open 'missing' finding as 'recreated', by the
// Principal and reason of the rebuild, as an operator's recreation of any other client closes it.
const rebuiltFindingStatement = `UPDATE identity.registration_finding
SET finding_class = 'recreated', desired = $2::jsonb, converged_at = now(), resolved_by = $3, resolution_reason = $4
WHERE registration_id = $1 AND converged_at IS NULL AND finding_class = 'missing'`

// RebuildWorkloadClientWithin creates an active workload registration's client again from desired
// state, holding its active and retiring keys, and records it, in the workload's transaction. It
// returns the new client. A client created here and not committed is the caller's to discard with
// DiscardClient once the transaction is rolled back.
func (s *Service) RebuildWorkloadClientWithin(ctx context.Context, tx db.Tx, change StateChange) (keycloak.ClientUUID, error) {
	if err := change.validate(); err != nil {
		return "", err
	}
	if change.Automatic {
		return "", fmt.Errorf("%w: a rebuild is never automatic", ErrInvalid)
	}
	locked, err := s.lockLifecycle(ctx, tx, change.RegistrationID)
	if err != nil {
		return "", err
	}
	if err := ownerOfLifecycle(locked.profile, true); err != nil {
		return "", err
	}
	if locked.state != StateActive {
		return "", fmt.Errorf("%w: only an active registration's client is rebuilt; this one is %s", ErrInvalidTransition, locked.state)
	}
	registration, err := s.read(ctx, tx, change.RegistrationID)
	if err != nil {
		return "", err
	}
	keys, err := liveKeys(ctx, tx, change.RegistrationID)
	if err != nil {
		return "", err
	}
	scopeID, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (string, error) {
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, ManagedScope(registration.AudienceClass, registration.PrivilegedForm))
	})
	if err != nil {
		return "", err
	}
	client, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.ClientUUID, error) {
		return s.kernel.CreateClient(ctx, s.cfg.Realm, spec(registration, keys))
	})
	switch {
	case errors.Is(err, keycloak.ErrConflict):
		return "", ErrClientHeld
	case err != nil:
		return "", fmt.Errorf("registration: rebuild %s: %w", registration.ClientKey, err)
	}
	if err := s.scope(ctx, registration, client, scopeID); err != nil {
		return client, err
	}
	if _, err := tx.Exec(ctx, relinkStatement, change.RegistrationID.String(), string(client)); err != nil {
		return client, fmt.Errorf("registration: record the rebuilt client: %w", err)
	}
	desired, err := json.Marshal(map[string]string{"client_key": registration.ClientKey, "client": string(client)})
	if err != nil {
		return client, err
	}
	if _, err := tx.Exec(ctx, rebuiltFindingStatement, change.RegistrationID.String(), string(desired),
		change.ChangedBy.String(), "rebuilt: "+strings.TrimSpace(change.Reason)); err != nil {
		return client, fmt.Errorf("registration: close the missing finding: %w", err)
	}
	return client, nil
}

// DiscardClient deletes a client a rebuild created and did not commit. A client already gone is the
// state wanted.
func (s *Service) DiscardClient(ctx context.Context, client keycloak.ClientUUID) error {
	_, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.kernel.DeleteClient(ctx, s.cfg.Realm, client)
	})
	if err != nil && !errors.Is(err, keycloak.ErrNotFound) {
		return err
	}
	return nil
}
