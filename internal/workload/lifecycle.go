package workload

// A workload stops the way a registration does (ADR-IAM-001 §5.13, TDD-identity-control-004
// §Suspension, Restoration, and Retirement): a suspension that can be undone, and a retirement only
// after one. The client and the Principal stop together, because deleting the client deletes its
// service-account user, which is the workload's Principal in the kernel. So the workload lifecycle
// holds the workload's row lock and changes its registration in the same transaction, and a
// retirement retires the Principal's mapping there too.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/registration"
)

// LifecycleRequest is one suspension, restoration or retirement: which workload, who asks, and why.
type LifecycleRequest struct {
	PrincipalID id.UUID
	ChangedBy   id.UUID
	Reason      string

	// automatic is the workload sweep's suspension of a workload orphaned past its grace period: it
	// names no Principal (TDD-identity-control-004 1.5.0 §Orphan Handling). Unexported, so no caller
	// outside the sweep can make a change nobody answers for.
	automatic bool
}

func (r LifecycleRequest) validate() error {
	if r.PrincipalID.IsNil() || r.ChangedBy.IsNil() != r.automatic {
		return fmt.Errorf("%w: a lifecycle action names the workload and the Principal asking", ErrInvalid)
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("%w: a lifecycle action requires a reason", ErrInvalid)
	}
	return nil
}

const suspendStatement = `UPDATE identity.workload
SET state = 'suspended', version = version + 1
WHERE principal_id = $1 AND state IN ('active', 'orphaned')`

const restoreStatement = `UPDATE identity.workload
SET state = 'active', orphaned_at = NULL, version = version + 1
WHERE principal_id = $1 AND state = 'suspended'`

const retireStatement = `UPDATE identity.workload
SET state = 'retired', version = version + 1
WHERE principal_id = $1 AND state = 'suspended'`

func (r LifecycleRequest) change(registrationID id.UUID) registration.StateChange {
	return registration.StateChange{RegistrationID: registrationID, ChangedBy: r.ChangedBy, Reason: r.Reason,
		Automatic: r.automatic}
}

// Suspend suspends the workload and its registration, then disables its client and sets its
// not-before. The record commits before the kernel changes, as a registration's suspension does: a
// kernel call that fails leaves a suspended registration the sweep disables. A repeat changes nothing.
func (s *Service) Suspend(ctx context.Context, req LifecycleRequest) (Workload, error) {
	if err := req.validate(); err != nil {
		return Workload{}, err
	}
	var registrationID id.UUID
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lock(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		registrationID = locked.RegistrationID
		switch locked.State {
		case StateSuspended:
			return nil
		case StateActive, StateOrphaned:
		default:
			return fmt.Errorf("%w: only an active or orphaned workload is suspended; this one is %s",
				ErrInvalidTransition, locked.State)
		}
		if err := s.registrar.SuspendWorkloadWithin(ctx, tx, req.change(locked.RegistrationID)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, suspendStatement, req.PrincipalID.String()); err != nil {
			return fmt.Errorf("workload: record the suspension: %w", err)
		}
		return nil
	})
	if err != nil {
		return Workload{}, err
	}
	if err := s.registrar.ConvergeSuspension(ctx, registrationID); err != nil {
		return Workload{}, err
	}
	s.logger.WarnContext(ctx, "a workload was suspended",
		slog.String("principal_id", req.PrincipalID.String()), slog.String("by", req.ChangedBy.String()))
	return s.Get(ctx, req.PrincipalID)
}

// Restore restores a suspended workload: its registration's keys, redirect URIs and lifespan written
// back and its client enabled, in the transaction that records it. Refused while the owner is not an
// active human Principal, because restoring an unowned credential is what an orphan is: reassign
// first.
func (s *Service) Restore(ctx context.Context, req LifecycleRequest) (Workload, error) {
	if err := req.validate(); err != nil {
		return Workload{}, err
	}
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lock(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		if locked.State != StateSuspended {
			return fmt.Errorf("%w: only a suspended workload is restored; this one is %s", ErrInvalidTransition, locked.State)
		}
		if err := s.ownerEligible(ctx, tx, locked.Owner); err != nil {
			return fmt.Errorf("%w: reassign the workload before restoring it", err)
		}
		if err := s.registrar.RestoreWorkloadWithin(ctx, tx, req.change(locked.RegistrationID)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, restoreStatement, req.PrincipalID.String()); err != nil {
			return fmt.Errorf("workload: record the restoration: %w", err)
		}
		return nil
	})
	if err != nil {
		return Workload{}, err
	}
	s.logger.WarnContext(ctx, "a suspended workload was restored",
		slog.String("principal_id", req.PrincipalID.String()), slog.String("by", req.ChangedBy.String()))
	return s.Get(ctx, req.PrincipalID)
}

// Retire retires a suspended workload: its client's keys removed and revoked and the client deleted,
// which deletes the service-account user, and the Principal's mapping retired, in one transaction.
// A repeat returns the retired workload.
func (s *Service) Retire(ctx context.Context, req LifecycleRequest) (Workload, error) {
	if err := req.validate(); err != nil {
		return Workload{}, err
	}
	retired := false
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lock(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		switch locked.State {
		case StateRetired:
			return nil
		case StateSuspended:
		default:
			return fmt.Errorf("%w: a workload is suspended before it is retired; this one is %s",
				ErrInvalidTransition, locked.State)
		}
		if err := s.registrar.RetireWorkloadWithin(ctx, tx, req.change(locked.RegistrationID)); err != nil {
			return err
		}
		if err := s.repo.RetireWorkload(ctx, tx, req.PrincipalID); err != nil {
			return fmt.Errorf("workload: retire the Principal: %w", err)
		}
		if _, err := tx.Exec(ctx, retireStatement, req.PrincipalID.String()); err != nil {
			return fmt.Errorf("workload: record the retirement: %w", err)
		}
		retired = true
		return nil
	})
	if err != nil {
		return Workload{}, err
	}
	if retired {
		s.logger.WarnContext(ctx, "a workload was retired and its client deleted",
			slog.String("principal_id", req.PrincipalID.String()), slog.String("by", req.ChangedBy.String()))
	}
	return s.Get(ctx, req.PrincipalID)
}
