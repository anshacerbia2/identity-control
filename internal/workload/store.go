package workload

import (
	"context"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

const insertPendingStatement = `INSERT INTO identity.workload
    (principal_id, registration_id, display_name, purpose, workload_type, owner_principal_id, team_reference,
     state, created_by, idempotency_scope, idempotency_key, request_digest)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11)`

func insertPending(ctx context.Context, tx db.Tx, w Workload, scope, key, digest string) error {
	var team any
	if w.TeamReference != "" {
		team = w.TeamReference
	}
	if _, err := tx.Exec(ctx, insertPendingStatement, w.PrincipalID.String(), w.RegistrationID.String(), w.DisplayName,
		w.Purpose, w.WorkloadType, w.Owner.String(), team, w.CreatedBy.String(), scope, key, digest); err != nil {
		return fmt.Errorf("workload: record the pending workload: %w", err)
	}
	return nil
}

const mappingCountStatement = `SELECT count(*) FROM identity.principal_mapping WHERE principal_id = $1`

const activateStatement = `UPDATE identity.workload
SET state = 'active', activated_at = $2, version = version + 1
WHERE principal_id = $1 AND state = 'pending'`

// retirePendingStatement closes a workload refused before it became active. The row is kept, as
// every workload record is.
const retirePendingStatement = `UPDATE identity.workload
SET state = 'retired', version = version + 1
WHERE principal_id = $1 AND state = 'pending'`

const reassignStatement = `UPDATE identity.workload
SET owner_principal_id = $2, owner_recorded_at = $3, state = 'active', orphaned_at = NULL, version = version + 1
WHERE principal_id = $1`

const ownerChangeStatement = `INSERT INTO identity.workload_owner_change
    (change_id, principal_id, previous_owner, new_owner, changed_by, reason, changed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

// workloadColumns are one workload with its client_key, in the order scan reads them. The client_key
// is read from the registration, the one record of it.
const workloadColumns = `w.principal_id::text, w.registration_id::text, r.client_key, w.display_name, w.purpose,
       w.workload_type, w.owner_principal_id::text, coalesce(w.team_reference, ''), w.owner_recorded_at, w.state,
       w.orphaned_at, w.last_seen_at, w.created_by::text, w.created_at, w.activated_at,
       (SELECT max(v.reviewed_at) FROM identity.workload_review v WHERE v.principal_id = w.principal_id)`

const readStatement = `SELECT ` + workloadColumns + `
FROM identity.workload w
JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE w.principal_id = $1 AND r.realm = $2`

const lockStatement = readStatement + `
FOR UPDATE OF w`

const pendingStatement = `SELECT ` + workloadColumns + `, w.idempotency_scope, w.idempotency_key, w.request_digest
FROM identity.workload w
JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE w.state = 'pending' AND w.created_at < $1 AND r.realm = $2
ORDER BY w.created_at
LIMIT 100`

type scanned struct {
	workload                                  Workload
	principal, registration, owner, createdBy string
	ownerRecordedAt, createdAt                time.Time
	orphanedAt, lastSeenAt, activatedAt       *time.Time
	lastReviewedAt                            *time.Time
}

func (s *scanned) targets() []any {
	w := &s.workload
	return []any{&s.principal, &s.registration, &w.ClientKey, &w.DisplayName, &w.Purpose, &w.WorkloadType, &s.owner,
		&w.TeamReference, &s.ownerRecordedAt, &w.State, &s.orphanedAt, &s.lastSeenAt, &s.createdBy, &s.createdAt,
		&s.activatedAt, &s.lastReviewedAt}
}

func (s *scanned) finish() (Workload, error) {
	w := s.workload
	var err error
	for _, field := range []struct {
		raw  string
		into *id.UUID
	}{{s.principal, &w.PrincipalID}, {s.registration, &w.RegistrationID}, {s.owner, &w.Owner}, {s.createdBy, &w.CreatedBy}} {
		if *field.into, err = id.Parse(field.raw); err != nil {
			return Workload{}, fmt.Errorf("workload: stored identifier %q is unparseable: %w", field.raw, err)
		}
	}
	w.OwnerRecordedAt, w.CreatedAt = s.ownerRecordedAt.UTC(), s.createdAt.UTC()
	w.OrphanedAt, w.LastSeenAt, w.ActivatedAt = utc(s.orphanedAt), utc(s.lastSeenAt), utc(s.activatedAt)
	w.LastReviewedAt = utc(s.lastReviewedAt)
	return w, nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	at := t.UTC()
	return &at
}

// read goes through Query rather than QueryRow, so an absent workload is no row rather than a driver
// error this package is not allowed to name.
func (s *Service) read(ctx context.Context, tx db.Tx, principalID id.UUID) (Workload, error) {
	return s.one(ctx, tx, readStatement, principalID.String(), string(s.cfg.Realm))
}

// lock reads a workload under its row lock, so two changes to one workload apply one after the other.
func (s *Service) lock(ctx context.Context, tx db.Tx, principalID id.UUID) (Workload, error) {
	return s.one(ctx, tx, lockStatement, principalID.String(), string(s.cfg.Realm))
}

// one reads at most one workload; its statement takes the principal_id and the realm first.
func (s *Service) one(ctx context.Context, tx db.Tx, statement string, args ...any) (Workload, error) {
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return Workload{}, fmt.Errorf("workload: read: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Workload{}, fmt.Errorf("workload: read: %w", err)
		}
		return Workload{}, ErrNotFound
	}
	var row scanned
	if err := rows.Scan(row.targets()...); err != nil {
		return Workload{}, fmt.Errorf("workload: scan: %w", err)
	}
	found, err := row.finish()
	if err != nil {
		return Workload{}, err
	}
	found.ReviewDueAt = s.reviewDue(found)
	return found, nil
}

// reviewDue is when an active or orphaned workload's next owner review is due: the review interval
// after the latest review, or after activation when there is none.
func (s *Service) reviewDue(w Workload) *time.Time {
	if (w.State != StateActive && w.State != StateOrphaned) || w.ActivatedAt == nil {
		return nil
	}
	base := *w.ActivatedAt
	if w.LastReviewedAt != nil && w.LastReviewedAt.After(base) {
		base = *w.LastReviewedAt
	}
	due := base.Add(s.cfg.ReviewInterval).UTC()
	return &due
}

// pendingOlderThan reads pending workloads created before the cutoff, with the idempotency claim
// each creation holds, so recovery can complete it.
func pendingOlderThan(ctx context.Context, tx db.Tx, cutoff time.Time, realm string) ([]pendingWorkload, error) {
	rows, err := tx.Query(ctx, pendingStatement, cutoff, realm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pendingWorkload
	for rows.Next() {
		var (
			row     scanned
			pending pendingWorkload
		)
		if err := rows.Scan(append(row.targets(), &pending.scope, &pending.key, &pending.digest)...); err != nil {
			return nil, fmt.Errorf("workload: scan: %w", err)
		}
		if pending.Workload, err = row.finish(); err != nil {
			return nil, err
		}
		out = append(out, pending)
	}
	return out, rows.Err()
}
