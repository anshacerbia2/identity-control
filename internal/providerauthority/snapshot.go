package providerauthority

import (
	"context"
	"errors"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
)

// Status is what this projection was built from and how far it has applied.
type Status struct {
	// Bootstrapped is false until a snapshot has been applied. No activation is honored before it
	// (TDD-identity-control-006 §Freshness).
	Bootstrapped bool
	SnapshotMark int64
	AppliedMark  int64
}

// statusStatement reads the projection's one row, or reports none. One row always.
const statusStatement = `SELECT EXISTS (SELECT 1 FROM identity.provider_projection WHERE id = 1),
       coalesce((SELECT snapshot_mark FROM identity.provider_projection WHERE id = 1), 0),
       coalesce((SELECT applied_mark FROM identity.provider_projection WHERE id = 1), 0)`

// Status reads the projection's bootstrap and progress.
func (p *Projection) Status(ctx context.Context) (Status, error) {
	var s Status
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, statusStatement).Scan(&s.Bootstrapped, &s.SnapshotMark, &s.AppliedMark)
	})
	if err != nil {
		return Status{}, fmt.Errorf("providerauthority: reading the projection's status: %w", err)
	}
	return s, nil
}

// revokeAbsentStatement marks revoked every active grant the snapshot does not carry. The snapshot
// carries every unrevoked grant of the published scope, so one it omits was revoked, and the
// revocation is already in Organization's record. The version is kept: a late event at or below it
// is discarded, and only a newer one can change the grant.
const revokeAbsentStatement = `UPDATE identity.provider_grant
SET grant_status = 'revoked', activation_id = NULL, activation_ends_at = NULL, applied_at = now()
WHERE grant_status = 'active' AND NOT (grant_id = ANY ($1::uuid[]))`

const recordSnapshotStatement = `INSERT INTO identity.provider_projection (id, snapshot_mark, bootstrapped_at, applied_mark)
VALUES (1, $1, now(), $1)
ON CONFLICT (id) DO UPDATE
SET snapshot_mark   = excluded.snapshot_mark,
    bootstrapped_at = excluded.bootstrapped_at,
    applied_mark    = greatest(identity.provider_projection.applied_mark, excluded.snapshot_mark)`

// ReplaceFromSnapshot replaces the projection with a snapshot taken at mark, in one transaction:
// each grant applied by version, every active grant the snapshot omits marked revoked, and the mark
// recorded. An event delivered before or after is reconciled by version either way.
func (p *Projection) ReplaceFromSnapshot(ctx context.Context, mark int64, grants []Grant) error {
	if mark < 0 {
		return errors.New("providerauthority: a snapshot mark cannot be negative")
	}
	ids := make([]string, 0, len(grants))
	for _, grant := range grants {
		if err := grant.validate(); err != nil {
			return fmt.Errorf("providerauthority: snapshot row %s: %w", grant.GrantID, err)
		}
		if grant.GrantStatus != "active" {
			return fmt.Errorf("%w: a snapshot carries unrevoked grants only, and %s is %s",
				ErrMalformed, grant.GrantID, grant.GrantStatus)
		}
		ids = append(ids, grant.GrantID.String())
	}
	return p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, grant := range grants {
			if _, err := upsert(ctx, tx, grant); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, revokeAbsentStatement, ids); err != nil {
			return fmt.Errorf("providerauthority: revoking the grants the snapshot omits: %w", err)
		}
		if _, err := tx.Exec(ctx, recordSnapshotStatement, mark); err != nil {
			return fmt.Errorf("providerauthority: recording the snapshot mark: %w", err)
		}
		return nil
	})
}
