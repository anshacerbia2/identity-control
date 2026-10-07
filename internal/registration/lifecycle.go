package registration

// A registration stops in two steps (ADR-IAM-001 §5.13, TDD-identity-control-003 §Suspension,
// Restoration, and Retirement): a suspension that can be undone, and a retirement only after one.
//
// A suspension disables the client and sets its not-before, because the kernel accepts a disabled
// client's refresh tokens again once it is enabled, and the not-before is what ends them
// (identity-kernel compat run 36765561606). It is recorded before the kernel is changed: the record
// is desired state, convergeSuspension makes the kernel match it, and a kernel call that fails
// leaves a suspended registration the sweep converges.
//
// A restore and a retirement change the kernel inside the transaction that records them, holding
// the row lock, as a key change does. A restore that fails leaves the client suspended, and a
// deleted client cannot be converged back. Every failure errs toward the stop.

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

// Lifecycle states a registration moves between.
const (
	StateActive    = "active"
	StateSuspended = "suspended"
	StateRetired   = "retired"
)

var (
	// ErrInvalidTransition is a lifecycle action the registration's state does not allow. Its
	// message names the rule.
	ErrInvalidTransition = errors.New("registration: the transition is refused")

	// ErrWorkloadLifecycle is a lifecycle action on a workload's client. Deleting a client deletes
	// its service-account user, which carries the workload's identity, so the workload lifecycle
	// stops the client and its Principal together.
	ErrWorkloadLifecycle = errors.New("registration: a workload's client is stopped through its workload")

	// ErrResourceInUse is a retirement of a resource another registration names in its audience.
	ErrResourceInUse = errors.New("registration: the resource is in the audience of another registration")
)

// ResourceInUseError names the registrations whose audience holds a resource being retired.
type ResourceInUseError struct {
	Dependents []string
}

func (e *ResourceInUseError) Error() string {
	return fmt.Sprintf("%s: %s", ErrResourceInUse.Error(), strings.Join(e.Dependents, ", "))
}

func (e *ResourceInUseError) Unwrap() error { return ErrResourceInUse }

// StateChange is one lifecycle action: which registration, who asks, and why.
type StateChange struct {
	RegistrationID id.UUID
	ChangedBy      id.UUID
	Reason         string

	// Automatic is a change nobody asked for: the workload sweep suspending a workload orphaned past
	// its grace period (TDD-identity-control-003 1.34.0). It names no Principal, and only it may.
	Automatic bool
}

func (c StateChange) validate() error {
	if c.ChangedBy.IsNil() != c.Automatic || strings.TrimSpace(c.Reason) == "" {
		return fmt.Errorf("%w: a lifecycle action names the Principal asking, or is automatic, and gives a reason", ErrInvalid)
	}
	return nil
}

// actor is the changed_by column: the Principal who asked, or null for an automatic change.
func (c StateChange) actor() any {
	if c.Automatic {
		return nil
	}
	return c.ChangedBy.String()
}

const lockLifecycleStatement = `SELECT profile, state, coalesce(kc_client_id, ''), suspended_at, client_key
FROM identity.client_registration
WHERE registration_id = $1 AND realm = $2
FOR UPDATE`

const suspendStatement = `UPDATE identity.client_registration
SET state = 'suspended', suspended_at = $2, version = version + 1
WHERE registration_id = $1 AND state = 'active'`

const restoreStatement = `UPDATE identity.client_registration
SET state = 'active', version = version + 1
WHERE registration_id = $1 AND state = 'suspended'`

const retireStatement = `UPDATE identity.client_registration
SET state = 'retired', retired_at = $2, version = version + 1
WHERE registration_id = $1 AND state = $3`

const revokeRetiredKeysStatement = `UPDATE identity.client_key
SET state = 'revoked', revoked_at = $2, revoked_by = $3, revocation_reason = 'the registration was retired'
WHERE registration_id = $1 AND state <> 'revoked'`

// resolveRestoredStatement closes the open findings a restore settles. The restore wrote every
// compared field class from desired state and enabled the client, which is what an operator's
// reconcile of those findings does, so they are recorded resolved by the same caller and reason.
const resolveRestoredStatement = `UPDATE identity.registration_finding
SET converged_at = $2, resolved_by = $3, resolution_reason = $4
WHERE registration_id = $1 AND converged_at IS NULL AND field_class IS NOT NULL`

const insertStateChangeStatement = `INSERT INTO identity.registration_state_change
    (change_id, registration_id, from_state, to_state, changed_by, reason, changed_at, automatic)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// dependentsStatement is every active or suspended registration whose audience names the resource.
// A suspended one counts, because a restore would bring it back holding an audience that no longer
// exists.
const dependentsStatement = `SELECT client_key FROM identity.client_registration
WHERE realm = $1 AND state IN ('active', 'suspended') AND $2 = ANY(coalesce(audience, '{}'::text[]))
ORDER BY client_key`

// lockedRegistration is what a lifecycle action reads under the row lock.
type lockedRegistration struct {
	profile     string
	state       string
	client      keycloak.ClientUUID
	suspendedAt *time.Time
	clientKey   string
}

func (s *Service) lockLifecycle(ctx context.Context, tx db.Tx, registrationID id.UUID) (lockedRegistration, error) {
	rows, err := tx.Query(ctx, lockLifecycleStatement, registrationID.String(), string(s.cfg.Realm))
	if err != nil {
		return lockedRegistration{}, fmt.Errorf("registration: lock the registration: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return lockedRegistration{}, err
		}
		return lockedRegistration{}, ErrNotFound
	}
	var (
		locked lockedRegistration
		client string
	)
	if err := rows.Scan(&locked.profile, &locked.state, &client, &locked.suspendedAt, &locked.clientKey); err != nil {
		return lockedRegistration{}, fmt.Errorf("registration: scan the registration: %w", err)
	}
	locked.client = keycloak.ClientUUID(client)
	return locked, nil
}

func (s *Service) recordChange(ctx context.Context, tx db.Tx, change StateChange, from, to string, at time.Time) error {
	changeID, err := s.newID()
	if err != nil {
		return fmt.Errorf("registration: mint change_id: %w", err)
	}
	if _, err := tx.Exec(ctx, insertStateChangeStatement, changeID.String(), change.RegistrationID.String(), from, to,
		change.actor(), strings.TrimSpace(change.Reason), at, change.Automatic); err != nil {
		return fmt.Errorf("registration: record the change: %w", err)
	}
	return nil
}

// SuspensionNotBefore is the not-before a suspension sets: the second after it. The kernel compares
// issued-at in seconds, and a token issued in the same second as the not-before is not before it.
func SuspensionNotBefore(suspendedAt time.Time) int64 { return suspendedAt.Unix() + 1 }

// Suspend records the registration suspended, then disables its client and sets the not-before
// that ends the refresh tokens it was issued. A repeat records nothing and applies it again.
func (s *Service) Suspend(ctx context.Context, change StateChange) (Registration, error) {
	if err := change.validate(); err != nil {
		return Registration{}, err
	}
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return s.suspendWithin(ctx, tx, change, false)
	})
	if err != nil {
		return Registration{}, err
	}
	if err := s.convergeSuspension(ctx, change.RegistrationID); err != nil {
		return Registration{}, err
	}
	s.logger.WarnContext(ctx, "a client registration was suspended",
		slog.String("registration_id", change.RegistrationID.String()), slog.String("by", change.ChangedBy.String()))
	return s.Get(ctx, change.RegistrationID)
}

// suspendWithin records the registration suspended in the caller's transaction. Whether it is a
// workload's decides who may ask: the registration lifecycle refuses a workload's client, and the
// workload lifecycle stops nothing else.
func (s *Service) suspendWithin(ctx context.Context, tx db.Tx, change StateChange, workload bool) error {
	locked, err := s.lockLifecycle(ctx, tx, change.RegistrationID)
	if err != nil {
		return err
	}
	if err := ownerOfLifecycle(locked.profile, workload); err != nil {
		return err
	}
	switch {
	case locked.profile == ProfileResource:
		return fmt.Errorf("%w: a resource holds no credential and is issued no token; it is retired, not suspended",
			ErrInvalidTransition)
	case locked.state == StateSuspended:
		return nil
	case locked.state != StateActive:
		return fmt.Errorf("%w: only an active registration is suspended; this one is %s", ErrInvalidTransition, locked.state)
	}
	at := s.now()
	if _, err := tx.Exec(ctx, suspendStatement, change.RegistrationID.String(), at); err != nil {
		return fmt.Errorf("registration: suspend: %w", err)
	}
	return s.recordChange(ctx, tx, change, StateActive, StateSuspended, at)
}

// ownerOfLifecycle refuses a lifecycle action asked through the wrong path: a workload's client
// through the registration lifecycle, or any other client through the workload lifecycle.
func ownerOfLifecycle(profile string, workload bool) error {
	switch {
	case !workload && profile == ProfileWorkload:
		return ErrWorkloadLifecycle
	case workload && profile != ProfileWorkload:
		return fmt.Errorf("%w: the registration is not a workload's", ErrInvalidTransition)
	}
	return nil
}

// SuspendWorkloadWithin suspends a workload's registration in the workload lifecycle's transaction
// (TDD-identity-control-004 §Suspension, Restoration, and Retirement). The client is disabled by
// ConvergeSuspension once that transaction commits, as Suspend does for any other client.
func (s *Service) SuspendWorkloadWithin(ctx context.Context, tx db.Tx, change StateChange) error {
	if err := change.validate(); err != nil {
		return err
	}
	return s.suspendWithin(ctx, tx, change, true)
}

// ConvergeSuspension disables a suspended registration's client and sets its not-before. The
// workload lifecycle calls it after its transaction commits.
func (s *Service) ConvergeSuspension(ctx context.Context, registrationID id.UUID) error {
	return s.convergeSuspension(ctx, registrationID)
}

// Restore writes the registration's registered redirect URIs, keys and lifespan to its client,
// enables it, and records the registration active, in one transaction holding the row lock. A kernel
// call that fails rolls the restore back and leaves the client suspended; a commit lost after the
// call leaves an enabled client the sweep disables again. Either failure errs toward the suspension.
// A restore of an active registration changes nothing, so it can never lift a block the reconciler
// set on an active client.
func (s *Service) Restore(ctx context.Context, change StateChange) (Registration, error) {
	if err := change.validate(); err != nil {
		return Registration{}, err
	}
	restored := false
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		restored, err = s.restoreWithin(ctx, tx, change, false)
		return err
	})
	if err != nil {
		return Registration{}, err
	}
	if restored {
		s.logger.WarnContext(ctx, "a suspended client registration was restored",
			slog.String("registration_id", change.RegistrationID.String()), slog.String("by", change.ChangedBy.String()))
	}
	return s.Get(ctx, change.RegistrationID)
}

// RestoreWorkloadWithin restores a workload's registration, writing its client, in the workload
// lifecycle's transaction.
func (s *Service) RestoreWorkloadWithin(ctx context.Context, tx db.Tx, change StateChange) error {
	if err := change.validate(); err != nil {
		return err
	}
	_, err := s.restoreWithin(ctx, tx, change, true)
	return err
}

func (s *Service) restoreWithin(ctx context.Context, tx db.Tx, change StateChange, workload bool) (bool, error) {
	if change.Automatic {
		return false, fmt.Errorf("%w: only a suspension is ever automatic", ErrInvalid)
	}
	locked, err := s.lockLifecycle(ctx, tx, change.RegistrationID)
	if err != nil {
		return false, err
	}
	if err := ownerOfLifecycle(locked.profile, workload); err != nil {
		return false, err
	}
	switch {
	case locked.profile == ProfileResource:
		return false, fmt.Errorf("%w: a resource is never suspended, so it is never restored", ErrInvalidTransition)
	case locked.state == StateActive:
		return false, nil
	case locked.state != StateSuspended:
		return false, fmt.Errorf("%w: only a suspended registration is restored; this one is %s", ErrInvalidTransition, locked.state)
	}
	if _, err := tx.Exec(ctx, restoreStatement, change.RegistrationID.String()); err != nil {
		return false, fmt.Errorf("registration: restore: %w", err)
	}
	if err := s.recordChange(ctx, tx, change, StateSuspended, StateActive, s.now()); err != nil {
		return false, err
	}
	if locked.client == "" {
		return true, nil
	}
	patch, err := s.activePatch(ctx, tx, change.RegistrationID)
	if err != nil {
		return false, err
	}
	if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, locked.client, patch)
	}); err != nil {
		if errors.Is(err, keycloak.ErrNotFound) {
			return false, fmt.Errorf("%w: the client is missing from the kernel; a suspended registration whose client is gone is retired",
				ErrInvalidTransition)
		}
		return false, fmt.Errorf("registration: restore the client: %w", err)
	}
	if _, err := tx.Exec(ctx, resolveRestoredStatement, change.RegistrationID.String(), s.now(),
		change.ChangedBy.String(), "restored: "+strings.TrimSpace(change.Reason)); err != nil {
		return false, fmt.Errorf("registration: resolve the restored findings: %w", err)
	}
	return true, nil
}

// activePatch is an active registration's desired client: its redirect URIs, lifespan and keys as
// registered, and enabled. The redirect URIs and keys are written because the sweep compares a
// suspended registration for its suspension only, so a console change made meanwhile would
// otherwise come back to life with it.
func (s *Service) activePatch(ctx context.Context, tx db.Tx, registrationID id.UUID) (keycloak.ClientPatch, error) {
	registration, err := s.read(ctx, tx, registrationID)
	if err != nil {
		return keycloak.ClientPatch{}, err
	}
	enabled := true
	patch := keycloak.ClientPatch{Enabled: &enabled}
	redirects, lifespan := append([]string{}, registration.RedirectURIs...), registration.AccessTokenLifespan
	patch.RedirectURIs, patch.AccessTokenLifespan = &redirects, &lifespan
	if keyed(registration.Profile) {
		keys, err := liveKeys(ctx, tx, registrationID)
		if err != nil {
			return keycloak.ClientPatch{}, err
		}
		patch.Keys = &keys
	}
	return patch, nil
}

// convergeSuspension disables a suspended registration's client and sets its not-before, under the
// row lock, reading the state committed. It does nothing for any other state, so a suspension
// retried after a restore committed cannot disable the restored client. An absent client stays
// absent: the sweep holds it missing.
func (s *Service) convergeSuspension(ctx context.Context, registrationID id.UUID) error {
	return s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lockLifecycle(ctx, tx, registrationID)
		if err != nil {
			return err
		}
		if locked.state != StateSuspended || locked.client == "" {
			return nil
		}
		disabled := false
		notBefore := SuspensionNotBefore(*locked.suspendedAt)
		_, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
			return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, locked.client,
				keycloak.ClientPatch{Enabled: &disabled, NotBefore: &notBefore})
		})
		if err != nil && !errors.Is(err, keycloak.ErrNotFound) {
			return fmt.Errorf("registration: disable the suspended client: %w", err)
		}
		return nil
	})
}

// Retire removes a suspended registration's keys from its client, deletes the client, and records
// the registration retired, its keys revoked. A resource is retired from active, once no active or
// suspended registration names it in its audience. A repeat returns the retired registration.
func (s *Service) Retire(ctx context.Context, change StateChange) (Registration, error) {
	if err := change.validate(); err != nil {
		return Registration{}, err
	}
	retired := false
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		retired, err = s.retireWithin(ctx, tx, change, false)
		return err
	})
	if err != nil {
		return Registration{}, err
	}
	if retired {
		s.logger.WarnContext(ctx, "a client registration was retired and its client deleted",
			slog.String("registration_id", change.RegistrationID.String()), slog.String("by", change.ChangedBy.String()))
	}
	return s.Get(ctx, change.RegistrationID)
}

// RetireWorkloadWithin retires a suspended workload's registration, deleting its client and with it
// the service-account user, in the workload lifecycle's transaction, which retires the Principal too.
func (s *Service) RetireWorkloadWithin(ctx context.Context, tx db.Tx, change StateChange) error {
	if err := change.validate(); err != nil {
		return err
	}
	_, err := s.retireWithin(ctx, tx, change, true)
	return err
}

func (s *Service) retireWithin(ctx context.Context, tx db.Tx, change StateChange, workload bool) (bool, error) {
	if change.Automatic {
		return false, fmt.Errorf("%w: only a suspension is ever automatic", ErrInvalid)
	}
	locked, err := s.lockLifecycle(ctx, tx, change.RegistrationID)
	if err != nil {
		return false, err
	}
	if err := ownerOfLifecycle(locked.profile, workload); err != nil {
		return false, err
	}
	switch {
	case locked.state == StateRetired:
		return false, nil
	case locked.profile == ProfileResource:
		if locked.state != StateActive {
			return false, fmt.Errorf("%w: only an active resource is retired; this one is %s", ErrInvalidTransition, locked.state)
		}
		dependents, err := s.dependents(ctx, tx, locked.clientKey)
		if err != nil {
			return false, err
		}
		if len(dependents) > 0 {
			return false, &ResourceInUseError{Dependents: dependents}
		}
	case locked.state != StateSuspended:
		return false, fmt.Errorf("%w: a client is suspended before it is retired; this one is %s", ErrInvalidTransition, locked.state)
	}

	if locked.client != "" {
		if keyed(locked.profile) {
			none := []keycloak.JWK{}
			if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, locked.client, keycloak.ClientPatch{Keys: &none})
			}); err != nil && !errors.Is(err, keycloak.ErrNotFound) {
				return false, fmt.Errorf("registration: remove the client's keys: %w", err)
			}
		}
		if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
			return struct{}{}, s.kernel.DeleteClient(ctx, s.cfg.Realm, locked.client)
		}); err != nil && !errors.Is(err, keycloak.ErrNotFound) {
			return false, fmt.Errorf("registration: delete the client: %w", err)
		}
	}

	at := s.now()
	tag, err := tx.Exec(ctx, retireStatement, change.RegistrationID.String(), at, locked.state)
	if err != nil {
		return false, fmt.Errorf("registration: retire: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, fmt.Errorf("registration: retire: the registration changed under its lock")
	}
	if _, err := tx.Exec(ctx, revokeRetiredKeysStatement, change.RegistrationID.String(), at,
		change.ChangedBy.String()); err != nil {
		return false, fmt.Errorf("registration: revoke the retired keys: %w", err)
	}
	return true, s.recordChange(ctx, tx, change, locked.state, StateRetired, at)
}

func (s *Service) dependents(ctx context.Context, tx db.Tx, resource string) ([]string, error) {
	rows, err := tx.Query(ctx, dependentsStatement, string(s.cfg.Realm), resource)
	if err != nil {
		return nil, fmt.Errorf("registration: read the resource's dependents: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var clientKey string
		if err := rows.Scan(&clientKey); err != nil {
			return nil, fmt.Errorf("registration: scan a dependent: %w", err)
		}
		out = append(out, clientKey)
	}
	return out, rows.Err()
}
