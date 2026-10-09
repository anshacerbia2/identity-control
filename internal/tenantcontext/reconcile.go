package tenantcontext

// Reconciliation (TDD-identity-control-002 2.1.0 §Reconciliation). The snapshot adds and updates the
// desired state by version, and never withdraws: it holds active Memberships only, and its mark is
// not a boundary, so a Membership it omits may be one granted while it was read. The kernel sweep
// disables and empties an Organization the authority never created, and marks every known Tenant so
// its convergence records what it had to change.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go.opentelemetry.io/otel/metric"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// SnapshotRow is one row of Organization Control's snapshot: an active Membership and its Tenant
// (TDD-organization-control-002 1.8.0).
type SnapshotRow struct {
	MembershipID          id.UUID `json:"membership_id"`
	PrincipalID           id.UUID `json:"principal_id"`
	TenantID              id.UUID `json:"tenant_id"`
	MembershipStatus      string  `json:"membership_status"`
	MembershipVersion     int64   `json:"membership_version"`
	TenantStatus          string  `json:"tenant_status"`
	TenantVersion         int64   `json:"tenant_version"`
	TenantSecurityVersion int64   `json:"tenant_security_version"`
}

func (r SnapshotRow) membership() Membership {
	return Membership{MembershipID: r.MembershipID, PrincipalID: r.PrincipalID, TenantID: r.TenantID,
		MembershipStatus: r.MembershipStatus, MembershipVersion: r.MembershipVersion}
}

func (r SnapshotRow) tenant() Tenant {
	return Tenant{TenantID: r.TenantID, TenantStatus: r.TenantStatus, TenantVersion: r.TenantVersion,
		TenantSecurityVersion: r.TenantSecurityVersion}
}

// SnapshotSource reads Organization Control's snapshot, every page under one mark.
type SnapshotSource interface {
	OrganizationSnapshot(ctx context.Context) (mark int64, rows []SnapshotRow, err error)
}

// markSweepStatement marks a Tenant as a sweep's. It keeps a pending Tenant's schedule and priority,
// and sets sweep, which its convergence clears once it records what it changed.
const markSweepStatement = `INSERT INTO identity.tenant_convergence (tenant_id, marked_at, next_attempt_at, state, sweep)
VALUES ($1, now(), now(), 'pending', true)
ON CONFLICT (tenant_id) DO UPDATE
SET marked_at       = now(),
    next_attempt_at = CASE WHEN identity.tenant_convergence.state <> 'pending' THEN now()
        ELSE identity.tenant_convergence.next_attempt_at END,
    attempts        = CASE WHEN identity.tenant_convergence.state = 'unresolved' THEN 0
        ELSE identity.tenant_convergence.attempts END,
    state           = 'pending',
    sweep           = true`

// ApplySnapshot writes each row's Membership and Tenant where its version is greater than the one
// held, in one transaction, and marks every Tenant it names as a sweep's. A row older than the held
// state changes nothing.
func (d *Desired) ApplySnapshot(ctx context.Context, rows []SnapshotRow) error {
	for _, row := range rows {
		m, t := row.membership(), row.tenant()
		if err := m.validate(); err != nil {
			return err
		}
		if err := t.validate(); err != nil {
			return err
		}
	}
	return d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		tenants := map[id.UUID]bool{}
		for _, row := range rows {
			m, t := row.membership(), row.tenant()
			if _, err := tx.Exec(ctx, upsertMembershipStatement, m.MembershipID.String(), m.PrincipalID.String(),
				m.TenantID.String(), m.MembershipStatus, m.MembershipVersion, nil); err != nil {
				return fmt.Errorf("tenantcontext: writing the snapshot's Membership %s: %w", m.MembershipID, err)
			}
			if _, err := tx.Exec(ctx, upsertTenantStatement, t.TenantID.String(), t.TenantStatus, t.TenantVersion,
				t.TenantSecurityVersion, nil); err != nil {
				return fmt.Errorf("tenantcontext: writing the snapshot's Tenant %s: %w", t.TenantID, err)
			}
			tenants[t.TenantID] = true
		}
		for tenant := range tenants {
			if _, err := tx.Exec(ctx, markSweepStatement, tenant.String()); err != nil {
				return fmt.Errorf("tenantcontext: marking tenant %s: %w", tenant, err)
			}
		}
		return nil
	})
}

// Reconciler runs the sweep.
type Reconciler struct {
	desired  *Desired
	tx       Transactor
	kernel   keycloak.TenantOrganizations
	realm    keycloak.Realm
	snapshot SnapshotSource
	logger   *slog.Logger
	metric   shared
	now      func() time.Time
}

// NewReconciler builds the sweep. A nil snapshot source sweeps the kernel alone: a server not yet
// registered with Organization Control as this consumer has no snapshot to read.
func NewReconciler(desired *Desired, tx Transactor, kernel keycloak.TenantOrganizations, realm keycloak.Realm,
	snapshot SnapshotSource, logger *slog.Logger) (*Reconciler, error) {
	if desired == nil || tx == nil || kernel == nil || realm == "" {
		return nil, errors.New("tenantcontext: the desired state, a transactor, a kernel and a realm are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	metrics, err := newShared(nil)
	if err != nil {
		return nil, err
	}
	return &Reconciler{desired: desired, tx: tx, kernel: kernel, realm: realm, snapshot: snapshot, logger: logger,
		metric: metrics, now: time.Now}, nil
}

// sweepAgeStatement is the age of the newest finished Tenant context sweep, null before the first.
const sweepAgeStatement = `SELECT extract(epoch FROM now() - max(finished_at))::float8
FROM identity.reconcile_run WHERE sweep = 'tenant_context' AND finished_at IS NOT NULL`

// Instrument counts the sweep's marks and findings on the meter, and registers the sweep-age gauge
// (TDD-identity-control-002 2.5.0 §Sweep Runs). A nil meter records nothing.
func (r *Reconciler) Instrument(meter metric.Meter) error {
	if meter == nil {
		return nil
	}
	metrics, err := newShared(meter)
	if err != nil {
		return err
	}
	r.metric = metrics
	_, err = meter.Float64ObservableGauge("identity.tenant_projection.sweep_age", metric.WithUnit("s"),
		metric.WithDescription("Seconds since the newest finished Tenant context sweep: above one interval a warning, two critical"),
		metric.WithFloat64Callback(func(ctx context.Context, o metric.Float64Observer) error {
			var age *float64
			if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
				return tx.QueryRow(ctx, sweepAgeStatement).Scan(&age)
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

// SweepResult is what one sweep did.
type SweepResult struct {
	// RunID names the sweep's record in identity.reconcile_run, and Outcome is the outcome recorded
	// there: converged, drift or unresolved (TDD-identity-control-002 2.5.0 §Sweep Runs).
	RunID   id.UUID
	Outcome string

	Mark         int64
	SnapshotRows int
	// SnapshotErr is a snapshot that could not be read. The kernel half of the sweep runs anyway: a
	// server whose registration does not yet subscribe to these types is refused the snapshot, and its
	// kernel still deserves a sweep.
	SnapshotErr error
	Unknown     int
	Marked      int64
}

const knownTenantsStatement = `SELECT tenant_id::text FROM identity.tenant_desired`

const findingStatement = `INSERT INTO identity.projection_finding
    (finding_id, finding_class, tenant_id, principal_id, detail)
VALUES ($1, $2, $3, (SELECT principal_id FROM identity.principal_mapping
    WHERE keycloak_user_id = $4 AND realm = $5 AND $4 <> ''), $6)`

// The outcomes a sweep run records, as identity.reconcile_run's check allows them.
const (
	OutcomeConverged  = "converged"
	OutcomeDrift      = "drift"
	OutcomeUnresolved = "unresolved"
)

const insertSweepRunStatement = `INSERT INTO identity.reconcile_run (run_id, sweep, started_at)
VALUES ($1, 'tenant_context', $2)`

const finishSweepRunStatement = `UPDATE identity.reconcile_run
SET finished_at = $2, outcome = $3, findings = $4
WHERE run_id = $1 AND finished_at IS NULL`

// Sweep reconciles once, and records the run: the snapshot, then the kernel's Organizations, then
// every known Tenant marked. A sweep that cannot record its run does not run, so a sweep the gauge
// counts is one that happened.
func (r *Reconciler) Sweep(ctx context.Context) (SweepResult, error) {
	runID, err := id.NewV7()
	if err != nil {
		return SweepResult{}, err
	}
	if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, insertSweepRunStatement, runID.String(), r.now())
		return err
	}); err != nil {
		return SweepResult{}, fmt.Errorf("tenantcontext: recording the sweep run: %w", err)
	}
	result, sweepErr := r.sweep(ctx)
	result.RunID = runID
	switch {
	case sweepErr != nil || result.SnapshotErr != nil:
		result.Outcome = OutcomeUnresolved
	case result.Unknown > 0:
		result.Outcome = OutcomeDrift
	default:
		result.Outcome = OutcomeConverged
	}
	// Finished on a context of its own: a sweep cancelled part way is still recorded as unresolved.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := r.tx.InTx(finishCtx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, finishSweepRunStatement, runID.String(), r.now(), result.Outcome, result.Unknown)
		return err
	}); err != nil && sweepErr == nil {
		sweepErr = fmt.Errorf("tenantcontext: finishing the sweep run: %w", err)
	}
	return result, sweepErr
}

func (r *Reconciler) sweep(ctx context.Context) (SweepResult, error) {
	var result SweepResult
	if r.snapshot != nil {
		mark, rows, err := r.snapshot.OrganizationSnapshot(ctx)
		switch {
		case err != nil:
			result.SnapshotErr = err
			r.logger.WarnContext(ctx, "the Organization snapshot could not be read; the kernel is swept without it",
				slog.String("error", err.Error()))
		default:
			if err := r.desired.ApplySnapshot(ctx, rows); err != nil {
				return result, err
			}
			result.Mark, result.SnapshotRows = mark, len(rows)
		}
	}

	known := map[string]bool{}
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, knownTenantsStatement)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tenant string
			if err := rows.Scan(&tenant); err != nil {
				return err
			}
			known[tenant] = true
		}
		return rows.Err()
	})
	if err != nil {
		return result, fmt.Errorf("tenantcontext: reading the known Tenants: %w", err)
	}

	organizations, err := r.kernel.ListOrganizations(ctx, r.realm)
	if err != nil {
		return result, fmt.Errorf("tenantcontext: listing the kernel's Organizations: %w", err)
	}
	for _, org := range organizations {
		if known[org.Name] {
			continue
		}
		changed, err := r.withdraw(ctx, org)
		if err != nil {
			return result, err
		}
		if changed {
			result.Unknown++
		}
	}

	err = r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for tenant := range known {
			if _, err := tx.Exec(ctx, markSweepStatement, tenant); err != nil {
				return fmt.Errorf("tenantcontext: marking tenant %s: %w", tenant, err)
			}
			result.Marked++
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	r.metric.mark(ctx, markSweep, false, result.Marked)
	r.logger.InfoContext(ctx, "tenant context swept", slog.Int64("mark", result.Mark),
		slog.Int("snapshot_rows", result.SnapshotRows), slog.Int("unknown_organizations", result.Unknown),
		slog.Int64("tenants_marked", result.Marked))
	return result, nil
}

// withdraw disables and empties an Organization the authority never created, and records it when it
// changed something. One already disabled and empty is a finding already recorded.
func (r *Reconciler) withdraw(ctx context.Context, org keycloak.Organization) (bool, error) {
	members, err := r.kernel.OrganizationMembers(ctx, r.realm, org.ID)
	if err != nil {
		return false, fmt.Errorf("tenantcontext: listing the members of %s: %w", org.Name, err)
	}
	if !org.Enabled && len(members) == 0 {
		return false, nil
	}
	if org.Enabled {
		if err := r.kernel.SetOrganizationEnabled(ctx, r.realm, org.ID, false); err != nil {
			return false, fmt.Errorf("tenantcontext: disabling %s: %w", org.Name, err)
		}
	}
	for _, member := range members {
		if err := r.kernel.RemoveOrganizationMember(ctx, r.realm, org.ID, member); err != nil {
			return false, fmt.Errorf("tenantcontext: emptying %s: %w", org.Name, err)
		}
	}
	detail, _ := json.Marshal(map[string]any{"organization_id": org.ID, "name": org.Name, "was_enabled": org.Enabled,
		"members_removed": len(members)})
	err = r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		findingID, err := id.NewV7()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, findingStatement, findingID.String(), "unknown_organization", nil, "", string(r.realm),
			string(detail))
		return err
	})
	if err != nil {
		return false, fmt.Errorf("tenantcontext: recording the unknown Organization %s: %w", org.Name, err)
	}
	r.metric.finding(ctx, "unknown_organization")
	r.logger.ErrorContext(ctx, "an Organization the authority never created was disabled and emptied",
		slog.String("organization_id", org.ID), slog.Int("members_removed", len(members)))
	return true, nil
}
