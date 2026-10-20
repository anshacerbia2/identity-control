package tenantcontext

// The consumer reconciles itself (TDD-identity-control-002 2.6.0 §The Consumer Reconciles Itself,
// ADR-ORG-001 §5.7 amended 2026-10-20). "The party that holds the copy runs the comparison": every
// IDENTITY_ORGANIZATION_RECONCILE_INTERVAL this service sends its report, the active Memberships of the
// desired state at the position it has applied, to Organization Control's POST /v1/projections/reconcile
// for its own consumer_id, as its own workload. Organization Control compares it with authority and
// publishes projection.repair.reconciled, which the delivery intake applies (repair.go). It records the
// run's age against the interval the registration declares, and alerts at one and two of them.
//
// One replica sends it per interval: the claim takes an advisory lock and runs only when no run of
// this kind started in the last half interval. Each run is recorded in identity.reconcile_run with
// sweep 'organization_reconcile'.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// SweepOrganizationReconcile is the identity.reconcile_run sweep this records.
const SweepOrganizationReconcile = "organization_reconcile"

// ReconcileFinding is one finding Organization Control's comparison answered, as much of it as this
// side reads: the repair itself arrives as projection.repair.reconciled.
type ReconcileFinding struct {
	Classification string  `json:"classification"`
	MembershipID   id.UUID `json:"membership_id"`
}

// ReconcileResult is Organization Control's answer to a report (TDD-organization-control-002
// §Reconciliation): the report's mark, when it ran, and what it found.
type ReconcileResult struct {
	ConsumerID string             `json:"consumer_id"`
	Mark       int64              `json:"mark"`
	RunAt      time.Time          `json:"run_at"`
	Findings   []ReconcileFinding `json:"findings"`
}

// ReconcileTarget sends a report to Organization Control's reconcile route: organization.Client.
type ReconcileTarget interface {
	Reconcile(ctx context.Context, report Report) (ReconcileResult, error)
}

// ErrNotDue is a run another replica already made within half an interval. It is not a failure.
var ErrNotDue = errors.New("tenantcontext: another replica reconciled this consumer within half an interval")

// SelfReconciler sends this consumer's report on its interval.
type SelfReconciler struct {
	desired  *Desired
	tx       Transactor
	target   ReconcileTarget
	interval time.Duration
	logger   *slog.Logger
	now      func() time.Time
}

// NewSelfReconciler builds it. The interval is the reconciliation_interval this consumer's
// registration declares.
func NewSelfReconciler(desired *Desired, tx Transactor, target ReconcileTarget, interval time.Duration,
	logger *slog.Logger) (*SelfReconciler, error) {
	if desired == nil || tx == nil || target == nil || interval <= 0 {
		return nil, errors.New("tenantcontext: the desired state, a transactor, a reconcile target and a positive interval are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SelfReconciler{desired: desired, tx: tx, target: target, interval: interval, logger: logger, now: time.Now}, nil
}

// SelfReconcileRun is one run.
type SelfReconcileRun struct {
	RunID    id.UUID
	Outcome  string
	Mark     int64
	Rows     int
	Findings int
	Extra    int
}

const selfReconcileLock = `SELECT pg_advisory_xact_lock(hashtext('identity.reconcile_run.organization_reconcile'))`

const selfReconcileRecentStatement = `SELECT EXISTS (SELECT 1 FROM identity.reconcile_run
WHERE sweep = 'organization_reconcile' AND started_at > $1)`

const insertSelfReconcileStatement = `INSERT INTO identity.reconcile_run (run_id, sweep, started_at)
VALUES ($1, 'organization_reconcile', $2)`

// selfReconcileAgeStatement is the age of the newest run Organization Control answered, null before
// the first. An unresolved run is not a reconciliation: "The key metric of a batch job is the last
// time it succeeded" (ADR-ORG-001 §5.7 [R8]).
const selfReconcileAgeStatement = `SELECT extract(epoch FROM now() - max(finished_at))::float8
FROM identity.reconcile_run WHERE sweep = 'organization_reconcile' AND outcome IN ('converged', 'drift')`

// Run claims, sends the report, and records the run: converged when Organization Control found
// nothing, drift when it found something, which its repair then carries, and unresolved when it did
// not answer or refused. A refusal is logged and the next interval sends again.
func (s *SelfReconciler) Run(ctx context.Context) (SelfReconcileRun, error) {
	runID, err := id.NewV7()
	if err != nil {
		return SelfReconcileRun{}, err
	}
	now := s.now()
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, selfReconcileLock); err != nil {
			return err
		}
		var recent bool
		if err := tx.QueryRow(ctx, selfReconcileRecentStatement, now.Add(-s.interval/2)).Scan(&recent); err != nil {
			return err
		}
		if recent {
			return ErrNotDue
		}
		_, err := tx.Exec(ctx, insertSelfReconcileStatement, runID.String(), now)
		return err
	})
	if errors.Is(err, ErrNotDue) {
		return SelfReconcileRun{}, err
	}
	if err != nil {
		return SelfReconcileRun{}, fmt.Errorf("tenantcontext: claiming the consumer's reconciliation: %w", err)
	}

	run := SelfReconcileRun{RunID: runID, Outcome: OutcomeUnresolved}
	report, runErr := s.desired.Report(ctx)
	if runErr == nil {
		run.Mark, run.Rows = report.Mark, len(report.Rows)
		var result ReconcileResult
		if result, runErr = s.target.Reconcile(ctx, report); runErr == nil {
			run.Findings = len(result.Findings)
			for _, finding := range result.Findings {
				if finding.Classification == "extra" {
					run.Extra++
				}
			}
			run.Outcome = OutcomeConverged
			if run.Findings > 0 {
				run.Outcome = OutcomeDrift
			}
		}
	}
	// Finished on a context of its own, so a run cut off by shutdown is still recorded unresolved.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.tx.InTx(finishCtx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, finishSweepRunStatement, runID.String(), s.now(), run.Outcome, run.Findings)
		return err
	}); err != nil && runErr == nil {
		runErr = fmt.Errorf("tenantcontext: finishing the consumer's reconciliation: %w", err)
	}
	return run, runErr
}

// Instrument registers the age gauge, identity.tenant_projection.organization_reconcile_age: seconds
// since the newest run Organization Control answered, warning past one interval and critical past two
// (ADR-ORG-001 §5.7). A state metric, read from the record when the reader collects (STD-GLB-003
// 1.1.0 §State Metrics). A nil meter registers nothing.
func (s *SelfReconciler) Instrument(meter metric.Meter) error {
	if meter == nil {
		return nil
	}
	_, err := meter.Float64ObservableGauge("identity.tenant_projection.organization_reconcile_age", metric.WithUnit("s"),
		metric.WithDescription("Seconds since Organization Control last answered this consumer's report: above one interval a warning, two critical"),
		metric.WithFloat64Callback(func(ctx context.Context, o metric.Float64Observer) error {
			var age *float64
			if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
				return tx.QueryRow(ctx, selfReconcileAgeStatement).Scan(&age)
			}); err != nil {
				return err
			}
			if age != nil {
				o.Observe(*age)
			}
			return nil
		}))
	return err
}
