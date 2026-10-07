package workload

// The workload sweep (TDD-identity-control-004 1.5.0): orphan handling, unused detection and overdue
// owner reviews, every IDENTITY_WORKLOAD_SWEEP_INTERVAL and on POST /v1/workloads:sweep.
//
// The owner is a Principal of this service, so its end is read from this service's own record: an
// owner whose mapping is retired, quarantined or suspended answers for nothing, and its workloads are
// orphaned. They keep working. The reminder and the escalation are log alerts until a notification
// channel and the Tenant's administrators are known here; thirty days suspends, reversibly.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// Stages an orphaned workload passes through.
const (
	StageReminder  = "reminder"
	StageEscalated = "escalated"
	StageSuspended = "suspended"
)

// orphanSuspensionReason is the reason an automatic suspension records, naming the rule.
const orphanSuspensionReason = "orphaned past IDENTITY_WORKLOAD_ORPHAN_SUSPEND_AFTER: no accountable owner " +
	"(TDD-identity-control-004 §Orphan Handling, NIST SP 800-53 AC-2(3)(b))"

// SweepResult is what one workload sweep did.
type SweepResult struct {
	Orphaned       int `json:"orphaned"`
	Reclaimed      int `json:"reclaimed"`
	Suspended      int `json:"suspended"`
	Unused         int `json:"unused"`
	ReviewsOverdue int `json:"reviews_overdue"`
}

// Condition is a workload in one of the sweep's conditions, as the listings report it. Since is when
// the condition began: orphaned at, last seen (or activated), or the review's due date.
type Condition struct {
	PrincipalID id.UUID    `json:"principal_id"`
	ClientKey   string     `json:"client_key"`
	DisplayName string     `json:"display_name"`
	Owner       id.UUID    `json:"owner_principal_id"`
	State       string     `json:"state"`
	Since       time.Time  `json:"since"`
	Stage       string     `json:"stage,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
}

// activeOwner is the predicate an owner answers for its workloads by: an active human mapping.
const activeOwner = `EXISTS (SELECT 1 FROM identity.principal_mapping m
    WHERE m.principal_id = w.owner_principal_id AND m.subject_type = 'human' AND m.state = 'active')`

const orphanStatement = `UPDATE identity.workload w
SET state = 'orphaned', orphaned_at = $2, version = w.version + 1
FROM identity.client_registration r
WHERE r.registration_id = w.registration_id AND r.realm = $1 AND w.state = 'active' AND NOT ` + activeOwner + `
RETURNING w.principal_id::text, w.owner_principal_id::text`

const reclaimStatement = `UPDATE identity.workload w
SET state = 'active', orphaned_at = NULL, version = w.version + 1
FROM identity.client_registration r
WHERE r.registration_id = w.registration_id AND r.realm = $1 AND w.state = 'orphaned' AND ` + activeOwner + `
RETURNING w.principal_id::text, w.owner_principal_id::text`

const conditionColumns = `SELECT w.principal_id::text, r.client_key, w.display_name, w.owner_principal_id::text, w.state`

const orphanedStatement = conditionColumns + `, w.orphaned_at
FROM identity.workload w JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE r.realm = $1 AND w.state = 'orphaned'
ORDER BY w.orphaned_at, w.principal_id`

// sinceSeen is when a workload last authenticated, or its activation when it never has.
const sinceSeen = `coalesce(w.last_seen_at, w.activated_at)`

// reviewDue is when a workload's next owner review is due: the interval after the latest review, or
// after activation.
const reviewDue = `(greatest(w.activated_at, coalesce((SELECT max(v.reviewed_at) FROM identity.workload_review v
    WHERE v.principal_id = w.principal_id), w.activated_at)) + $2::interval)`

const openUnusedStatement = `INSERT INTO identity.workload_finding (finding_id, principal_id, finding_class)
SELECT gen_random_uuid(), w.principal_id, 'unused'
FROM identity.workload w JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE r.realm = $1 AND w.state IN ('active', 'orphaned') AND ` + sinceSeen + ` < $3::timestamptz - $2::interval
ON CONFLICT (principal_id, finding_class) WHERE resolved_at IS NULL DO NOTHING
RETURNING principal_id::text`

const resolveSeenStatement = `UPDATE identity.workload_finding f
SET resolved_at = $3, resolution = CASE WHEN w.state IN ('active', 'orphaned') THEN 'seen' ELSE 'stopped' END
FROM identity.workload w JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE f.principal_id = w.principal_id AND r.realm = $1 AND f.finding_class = 'unused' AND f.resolved_at IS NULL
  AND (w.state NOT IN ('active', 'orphaned') OR ` + sinceSeen + ` >= $3::timestamptz - $2::interval)`

const unusedStatement = conditionColumns + `, ` + sinceSeen + `, w.last_seen_at
FROM identity.workload w JOIN identity.client_registration r ON r.registration_id = w.registration_id
JOIN identity.workload_finding f ON f.principal_id = w.principal_id AND f.finding_class = 'unused' AND f.resolved_at IS NULL
WHERE r.realm = $1
ORDER BY ` + sinceSeen + `, w.principal_id`

const openOverdueStatement = `INSERT INTO identity.workload_finding (finding_id, principal_id, finding_class)
SELECT gen_random_uuid(), w.principal_id, 'review_overdue'
FROM identity.workload w JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE r.realm = $1 AND w.state IN ('active', 'orphaned') AND w.activated_at IS NOT NULL AND ` + reviewDue + ` < $3
ON CONFLICT (principal_id, finding_class) WHERE resolved_at IS NULL DO NOTHING
RETURNING principal_id::text`

const resolveReviewedStatement = `UPDATE identity.workload_finding f
SET resolved_at = $3, resolution = CASE WHEN w.state IN ('active', 'orphaned') THEN 'reviewed' ELSE 'stopped' END
FROM identity.workload w JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE f.principal_id = w.principal_id AND r.realm = $1 AND f.finding_class = 'review_overdue' AND f.resolved_at IS NULL
  AND (w.state NOT IN ('active', 'orphaned') OR ` + reviewDue + ` >= $3)`

const overdueStatement = conditionColumns + `, ` + reviewDue + `
FROM identity.workload w JOIN identity.client_registration r ON r.registration_id = w.registration_id
JOIN identity.workload_finding f ON f.principal_id = w.principal_id AND f.finding_class = 'review_overdue' AND f.resolved_at IS NULL
WHERE r.realm = $1
ORDER BY 6, w.principal_id`

// Sweep runs one workload sweep: orphan and reclaim, suspend what was orphaned too long, and open and
// resolve unused and overdue-review findings. A failure suspending one workload does not stop the
// others; it is returned after the rest of the sweep ran.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	now := s.now()
	var result SweepResult
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		orphaned, err := pairs(ctx, tx, orphanStatement, string(s.cfg.Realm), now)
		if err != nil {
			return fmt.Errorf("workload: orphan the workloads of owners who ended: %w", err)
		}
		for _, p := range orphaned {
			s.logger.WarnContext(ctx, "a workload's owner no longer answers for it; it is orphaned and keeps working",
				slog.String("principal_id", p[0]), slog.String("owner_principal_id", p[1]))
		}
		reclaimed, err := pairs(ctx, tx, reclaimStatement, string(s.cfg.Realm))
		if err != nil {
			return fmt.Errorf("workload: reclaim the workloads of owners restored: %w", err)
		}
		for _, p := range reclaimed {
			s.logger.WarnContext(ctx, "an orphaned workload's owner is active again; the workload is active",
				slog.String("principal_id", p[0]), slog.String("owner_principal_id", p[1]))
		}
		result.Orphaned, result.Reclaimed = len(orphaned), len(reclaimed)
		return nil
	})
	if err != nil {
		return SweepResult{}, err
	}

	orphans, err := s.Orphaned(ctx)
	if err != nil {
		return result, err
	}
	var suspendErr error
	for _, orphan := range orphans {
		attrs := []slog.Attr{slog.String("principal_id", orphan.PrincipalID.String()), slog.String("client_key", orphan.ClientKey),
			slog.String("owner_principal_id", orphan.Owner.String()), slog.Time("orphaned_at", orphan.Since)}
		switch orphan.Stage {
		case StageSuspended:
			if _, err := s.Suspend(ctx, LifecycleRequest{PrincipalID: orphan.PrincipalID, Reason: orphanSuspensionReason,
				automatic: true}); err != nil {
				s.logger.ErrorContext(ctx, "an orphaned workload past its grace period could not be suspended",
					slog.String("principal_id", orphan.PrincipalID.String()), slog.String("error", err.Error()))
				suspendErr = err
				continue
			}
			result.Suspended++
			s.logger.LogAttrs(ctx, slog.LevelError, "an orphaned workload passed its grace period and is suspended; "+
				"reassign it, then restore it", attrs...)
		case StageEscalated:
			s.logger.LogAttrs(ctx, slog.LevelError, "an orphaned workload is past its escalation threshold; "+
				"its Tenant's administrators must reassign it", attrs...)
		default:
			s.logger.LogAttrs(ctx, slog.LevelWarn, "an orphaned workload needs a new owner", attrs...)
		}
	}

	unusedFor := intervalOf(s.cfg.UnusedThreshold)
	reviewEvery := intervalOf(s.cfg.ReviewInterval)
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, resolveSeenStatement, string(s.cfg.Realm), unusedFor, now); err != nil {
			return fmt.Errorf("workload: resolve unused findings: %w", err)
		}
		if _, err := ones(ctx, tx, openUnusedStatement, string(s.cfg.Realm), unusedFor, now); err != nil {
			return fmt.Errorf("workload: open unused findings: %w", err)
		}
		if _, err := tx.Exec(ctx, resolveReviewedStatement, string(s.cfg.Realm), reviewEvery, now); err != nil {
			return fmt.Errorf("workload: resolve overdue reviews: %w", err)
		}
		if _, err := ones(ctx, tx, openOverdueStatement, string(s.cfg.Realm), reviewEvery, now); err != nil {
			return fmt.Errorf("workload: open overdue reviews: %w", err)
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	unused, err := s.Unused(ctx)
	if err != nil {
		return result, err
	}
	for _, workload := range unused {
		s.logger.WarnContext(ctx, "a workload has not authenticated within the unused threshold; its owner decides "+
			"whether it is still needed", slog.String("principal_id", workload.PrincipalID.String()),
			slog.String("client_key", workload.ClientKey), slog.String("owner_principal_id", workload.Owner.String()),
			slog.Time("since", workload.Since))
	}
	overdue, err := s.ReviewsOverdue(ctx)
	if err != nil {
		return result, err
	}
	for _, workload := range overdue {
		level, message := slog.LevelWarn, "a workload's owner review is overdue"
		if workload.Stage == StageEscalated {
			level, message = slog.LevelError, "a workload's owner review is past its escalation threshold; its Tenant's "+
				"administrators must see it reviewed"
		}
		s.logger.LogAttrs(ctx, level, message, slog.String("principal_id", workload.PrincipalID.String()),
			slog.String("client_key", workload.ClientKey), slog.String("owner_principal_id", workload.Owner.String()),
			slog.Time("due_at", workload.Since))
	}
	result.Unused, result.ReviewsOverdue = len(unused), len(overdue)
	return result, suspendErr
}

// Orphaned lists the orphaned workloads, oldest first, each with its stage.
func (s *Service) Orphaned(ctx context.Context) ([]Condition, error) {
	now := s.now()
	return s.conditions(ctx, orphanedStatement, func(c *Condition) {
		switch age := now.Sub(c.Since); {
		case age >= s.cfg.OrphanSuspendAfter:
			c.Stage = StageSuspended
		case age >= s.cfg.OrphanEscalateAfter:
			c.Stage = StageEscalated
		default:
			c.Stage = StageReminder
		}
	})
}

// Unused lists the workloads with an open unused finding, longest unseen first.
func (s *Service) Unused(ctx context.Context) ([]Condition, error) {
	return s.conditions(ctx, unusedStatement, nil)
}

// ReviewsOverdue lists the workloads whose owner review is overdue, longest overdue first.
func (s *Service) ReviewsOverdue(ctx context.Context) ([]Condition, error) {
	now := s.now()
	return s.conditions(ctx, overdueStatement, func(c *Condition) {
		c.Stage = StageReminder
		if now.Sub(c.Since) >= s.cfg.OrphanEscalateAfter {
			c.Stage = StageEscalated
		}
	}, intervalOf(s.cfg.ReviewInterval))
}

func (s *Service) conditions(ctx context.Context, statement string, stage func(*Condition), extra ...any) ([]Condition, error) {
	out := []Condition{}
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, statement, append([]any{string(s.cfg.Realm)}, extra...)...)
		if err != nil {
			return fmt.Errorf("workload: read the workloads: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c                 Condition
				principal, owner  string
				targets           = []any{&principal, &c.ClientKey, &c.DisplayName, &owner, &c.State, &c.Since}
				lastSeen          *time.Time
				readsLastSeenTime = statement == unusedStatement
			)
			if readsLastSeenTime {
				targets = append(targets, &lastSeen)
			}
			if err := rows.Scan(targets...); err != nil {
				return fmt.Errorf("workload: scan: %w", err)
			}
			if c.PrincipalID, err = id.Parse(principal); err != nil {
				return err
			}
			if c.Owner, err = id.Parse(owner); err != nil {
				return err
			}
			c.Since, c.LastSeenAt = c.Since.UTC(), utc(lastSeen)
			if stage != nil {
				stage(&c)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// pairs runs a statement returning two text columns per row.
func pairs(ctx context.Context, tx db.Tx, statement string, args ...any) ([][2]string, error) {
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var p [2]string
		if err := rows.Scan(&p[0], &p[1]); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ones runs a statement returning one text column per row.
func ones(ctx context.Context, tx db.Tx, statement string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// intervalOf is a duration as PostgreSQL reads an interval, to the microsecond.
func intervalOf(d time.Duration) string {
	return fmt.Sprintf("%d microseconds", d.Microseconds())
}
