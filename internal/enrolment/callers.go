package enrolment

// The BFF workloads admitted to the two enrolment routes, from a record (ADR-IAM-011 §5.8): the
// routes are anonymous as to the person and not as to the caller. identity.enrolment_caller names the
// workload's principal_id, as ADR-ORG-001 §5.11 names a reporter's, and a provider registers and
// retires it with a reason.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

var (
	// ErrInvalid means a registration or a retirement is incomplete.
	ErrInvalid = errors.New("enrolment: the request is invalid")
	// ErrNotWorkload means the principal_id is not an active workload Principal of this service.
	ErrNotWorkload = errors.New("enrolment: the principal_id is not an active workload")
	// ErrRegistered means the workload is registered already, active or retired: one record for good.
	ErrRegistered = errors.New("enrolment: the workload is registered already")
	// ErrNoCaller means no active registration names the workload.
	ErrNoCaller = errors.New("enrolment: no active enrolment caller has this principal_id")
)

// Caller is one registration.
type Caller struct {
	PrincipalID    id.UUID    `json:"principal_id"`
	Purpose        string     `json:"purpose"`
	RegisteredBy   id.UUID    `json:"registered_by"`
	RegisterReason string     `json:"register_reason"`
	RegisteredAt   time.Time  `json:"registered_at"`
	RetiredBy      *id.UUID   `json:"retired_by"`
	RetireReason   *string    `json:"retire_reason"`
	RetiredAt      *time.Time `json:"retired_at"`
}

// Callers is the registry.
type Callers struct{ tx Transactor }

// NewCallers builds the registry.
func NewCallers(tx Transactor) (*Callers, error) {
	if tx == nil {
		return nil, errors.New("enrolment: a transactor is required")
	}
	return &Callers{tx: tx}, nil
}

// admittedStatement is true for an active registration of an active workload Principal, read for
// every request: a retirement, or the workload's own, stops the next one.
const admittedStatement = `SELECT EXISTS (
    SELECT 1 FROM identity.enrolment_caller c
    JOIN identity.principal_mapping m ON m.principal_id = c.principal_id
    WHERE c.principal_id = $1 AND c.retired_at IS NULL AND m.subject_type = 'workload' AND m.state = 'active')`

// Admitted reports whether the workload may call the enrolment routes.
func (c *Callers) Admitted(ctx context.Context, principal id.UUID) (bool, error) {
	var admitted bool
	err := c.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, admittedStatement, principal.String()).Scan(&admitted)
	})
	return admitted, err
}

const callerColumns = `principal_id::text, purpose, registered_by::text, register_reason, registered_at,
       retired_by::text, retire_reason, retired_at`

const listCallersStatement = `SELECT ` + callerColumns + ` FROM identity.enrolment_caller ORDER BY registered_at, principal_id`

// List answers every registration, active and retired.
func (c *Callers) List(ctx context.Context) ([]Caller, error) {
	callers := []Caller{}
	err := c.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, listCallersStatement)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			caller, err := scanCaller(rows)
			if err != nil {
				return err
			}
			callers = append(callers, caller)
		}
		return rows.Err()
	})
	return callers, err
}

type scanner interface{ Scan(dest ...any) error }

func scanCaller(row scanner) (Caller, error) {
	var (
		caller                  Caller
		principal, by           string
		retiredBy, retireReason *string
	)
	if err := row.Scan(&principal, &caller.Purpose, &by, &caller.RegisterReason, &caller.RegisteredAt,
		&retiredBy, &retireReason, &caller.RetiredAt); err != nil {
		return Caller{}, err
	}
	var err error
	if caller.PrincipalID, err = id.Parse(principal); err != nil {
		return Caller{}, err
	}
	if caller.RegisteredBy, err = id.Parse(by); err != nil {
		return Caller{}, err
	}
	if retiredBy != nil {
		parsed, err := id.Parse(*retiredBy)
		if err != nil {
			return Caller{}, err
		}
		caller.RetiredBy = &parsed
	}
	caller.RetireReason = retireReason
	return caller, nil
}

// Change is who registers or retires a caller, and why.
type Change struct {
	Principal id.UUID
	Purpose   string
	By        id.UUID
	Reason    string
}

const workloadStatement = `SELECT EXISTS (SELECT 1 FROM identity.principal_mapping
    WHERE principal_id = $1 AND subject_type = 'workload' AND state = 'active')`

const registerStatement = `INSERT INTO identity.enrolment_caller (principal_id, purpose, registered_by, register_reason)
VALUES ($1, $2, $3, $4)
ON CONFLICT (principal_id) DO NOTHING
RETURNING ` + callerColumns

// Register admits a workload to the enrolment routes.
func (c *Callers) Register(ctx context.Context, change Change) (Caller, error) {
	purpose, reason := strings.TrimSpace(change.Purpose), strings.TrimSpace(change.Reason)
	if change.Principal.IsNil() || change.By.IsNil() || purpose == "" || reason == "" || len(purpose) > 500 {
		return Caller{}, ErrInvalid
	}
	var caller Caller
	err := c.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var workload bool
		if err := tx.QueryRow(ctx, workloadStatement, change.Principal.String()).Scan(&workload); err != nil {
			return err
		}
		if !workload {
			return ErrNotWorkload
		}
		rows, err := tx.Query(ctx, registerStatement, change.Principal.String(), purpose, change.By.String(), reason)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return ErrRegistered
		}
		caller, err = scanCaller(rows)
		return err
	})
	if err != nil {
		return Caller{}, fmt.Errorf("enrolment: register a caller: %w", err)
	}
	return caller, nil
}

const retireStatement = `UPDATE identity.enrolment_caller
SET retired_by = $2, retire_reason = $3, retired_at = now()
WHERE principal_id = $1 AND retired_at IS NULL
RETURNING ` + callerColumns

// Retire stops a workload's next enrolment request.
func (c *Callers) Retire(ctx context.Context, change Change) (Caller, error) {
	reason := strings.TrimSpace(change.Reason)
	if change.Principal.IsNil() || change.By.IsNil() || reason == "" {
		return Caller{}, ErrInvalid
	}
	var caller Caller
	err := c.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, retireStatement, change.Principal.String(), change.By.String(), reason)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return ErrNoCaller
		}
		caller, err = scanCaller(rows)
		return err
	})
	if err != nil {
		return Caller{}, fmt.Errorf("enrolment: retire a caller: %w", err)
	}
	return caller, nil
}
