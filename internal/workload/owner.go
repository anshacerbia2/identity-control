package workload

// The owner's read (TDD-identity-control-004 1.7.0, ADR-IAM-003 §5.8): the owner lists the
// workloads it owns and reads each one, with its last review and the date the next is due, so the
// review it gives is of a record it has seen.
//
// The owner is the workload's owner_principal_id, counted only while that Principal's mapping is an
// active human one: activeOwner, the predicate the sweep orphans by. A retired, quarantined or
// suspended owner reads nothing from the next request.

import (
	"context"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// ownedStatement reads a workload only for its owner. The ownership is in the same query as the
// read, so a workload owned by someone else and one that does not exist are the same empty answer,
// reached the same way: the caller cannot tell them apart.
const ownedStatement = readStatement + ` AND w.owner_principal_id = $3 AND ` + activeOwner

const mineStatement = `SELECT ` + workloadColumns + `
FROM identity.workload w
JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE r.realm = $1 AND w.owner_principal_id = $2 AND ` + activeOwner + `
ORDER BY w.created_at, w.principal_id`

// Owned reads one workload for its owner. A workload the owner does not own, or any workload once
// the owner's mapping is no longer active, is ErrNotFound, as a workload that does not exist is.
func (s *Service) Owned(ctx context.Context, principalID, owner id.UUID) (Workload, error) {
	var found Workload
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		found, err = s.one(ctx, tx, ownedStatement, principalID.String(), string(s.cfg.Realm), owner.String())
		return err
	})
	return found, err
}

// Mine lists the workloads the Principal owns, in every state, oldest first. It is empty, never nil,
// for a Principal that owns none or whose mapping is no longer active.
func (s *Service) Mine(ctx context.Context, owner id.UUID) ([]Workload, error) {
	var out []Workload
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		out = []Workload{}
		rows, err := tx.Query(ctx, mineStatement, string(s.cfg.Realm), owner.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row scanned
			if err := rows.Scan(row.targets()...); err != nil {
				return err
			}
			found, err := row.finish()
			if err != nil {
				return err
			}
			found.ReviewDueAt = s.reviewDue(found)
			out = append(out, found)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("workload: list the owner's workloads: %w", err)
	}
	return out, nil
}
