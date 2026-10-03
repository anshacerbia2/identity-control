package securitystate

// Operating a parked operation (TDD-identity-control-005 §Operating the Executor). An unresolved
// operation is listed, and re-driven by a provider with a reason; nothing abandons one, because a
// suspension or a session termination is never discarded.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// Parked is an unresolved operation as an operator reads it.
type Parked struct {
	OperationID    id.UUID   `json:"operation_id"`
	PrincipalID    id.UUID   `json:"principal_id"`
	Type           string    `json:"operation_type"`
	Attempts       int       `json:"attempts"`
	LastErrorClass string    `json:"last_error_class,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

const parkedStatement = `SELECT operation_id::text, principal_id::text, operation_type, attempts,
       coalesce(last_error_class, ''), created_at
FROM identity.security_operation WHERE state = 'unresolved'
ORDER BY created_at, operation_id
LIMIT 100`

// Unresolved lists the parked operations, oldest first, at most 100.
func (s *Service) Unresolved(ctx context.Context) ([]Parked, error) {
	parked := []Parked{}
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, parkedStatement)
		if err != nil {
			return fmt.Errorf("securitystate: list the parked operations: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				p             Parked
				opID, subject string
			)
			if err := rows.Scan(&opID, &subject, &p.Type, &p.Attempts, &p.LastErrorClass, &p.CreatedAt); err != nil {
				return err
			}
			if p.OperationID, err = id.Parse(opID); err != nil {
				return err
			}
			if p.PrincipalID, err = id.Parse(subject); err != nil {
				return err
			}
			parked = append(parked, p)
		}
		return rows.Err()
	})
	return parked, err
}

const lockParkedStatement = `SELECT principal_id::text, operation_type, state FROM identity.security_operation
WHERE operation_id = $1 FOR UPDATE`

const redriveStatement = `UPDATE identity.security_operation
SET state = 'retrying', next_attempt_at = now(), redriven_at = attempts
WHERE operation_id = $1`

// Redrive returns an unresolved operation to the executor with a new attempt budget, records who
// did it and why, and follows it within the command budget. The operation keeps its identifier,
// its correlation and its history (STD-GLB-011 §3.9).
func (s *Service) Redrive(ctx context.Context, actor Actor, operationID id.UUID, reason string) (Operation, error) {
	switch {
	case actor.Principal.IsNil():
		return Operation{}, fmt.Errorf("%w: an actor is required", ErrInvalid)
	case strings.TrimSpace(reason) == "":
		return Operation{}, fmt.Errorf("%w: an administrative reason is required", ErrInvalid)
	}
	var opType string
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, lockParkedStatement, operationID.String())
		if err != nil {
			return fmt.Errorf("securitystate: read the operation: %w", err)
		}
		if !rows.Next() {
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			return ErrNotFound
		}
		var subject, state string
		err = rows.Scan(&subject, &opType, &state)
		rows.Close()
		if err != nil {
			return err
		}
		if state != StateUnresolved {
			return fmt.Errorf("%w: the operation is %s, and only an unresolved one is re-driven", ErrState, state)
		}
		if _, err := tx.Exec(ctx, redriveStatement, operationID.String()); err != nil {
			return fmt.Errorf("securitystate: re-drive: %w", err)
		}
		accessID, err := s.newID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, evidenceStatement, accessID.String(), actor.Principal.String(), subject,
			"operation.redrive", "POST /v1/security-operations/{operation_id}:redrive", reason, StateApplied,
			actor.Correlation, actor.Emergency); err != nil {
			return fmt.Errorf("securitystate: record the evidence: %w", err)
		}
		return nil
	})
	if err != nil {
		return Operation{}, err
	}
	s.metric.redrives.Add(ctx, 1, typed(opType))
	s.logger.WarnContext(ctx, "security operation re-driven", "operation_id", operationID.String(),
		"operation_type", opType, "actor_principal_id", actor.Principal.String())
	budget, cancel := context.WithTimeout(ctx, s.cfg.Budget)
	defer cancel()
	if _, err := s.execute(budget, &operationID); err != nil {
		s.logger.WarnContext(ctx, "inline execution of a re-driven operation did not finish",
			"operation_id", operationID.String(), "error", err.Error())
	}
	return s.Get(ctx, operationID)
}
