package tenantcontext

// The consumer reconciles itself (TDD-identity-control-002 2.6.0, ADR-ORG-001 §5.7), against the real
// engine and a stand-in for Organization Control's reconcile route.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
)

type reconcileTarget struct {
	mu      sync.Mutex
	reports []Report
	result  ReconcileResult
	err     error
}

func (r *reconcileTarget) Reconcile(_ context.Context, report Report) (ReconcileResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, report)
	return r.result, r.err
}

type selfRun struct {
	outcome  string
	findings int
	finished bool
}

func selfRuns(t *testing.T, p *db.Pool) []selfRun {
	t.Helper()
	var out []selfRun
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT coalesce(outcome, ''), findings, finished_at IS NOT NULL
			FROM identity.reconcile_run WHERE sweep = 'organization_reconcile' ORDER BY started_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var run selfRun
			if err := rows.Scan(&run.outcome, &run.findings, &run.finished); err != nil {
				return err
			}
			out = append(out, run)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Each interval one run sends the report and records what Organization Control answered; a second
// replica within half an interval does not send it again; a refusal is recorded unresolved, is not
// counted as a reconciliation by the age, and the next interval sends again.
func TestTheConsumerReconcilesItselfOncePerInterval(t *testing.T) {
	p := pool(t)
	ctx := context.Background()
	clear := func() {
		if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM identity.reconcile_run WHERE sweep = 'organization_reconcile'`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	clear()
	t.Cleanup(clear)
	desired, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	tenant, membership := newID(t), newID(t)
	if _, err := desired.Apply(ctx, envelope(t, MembershipGranted, Membership{MembershipID: membership,
		PrincipalID: newID(t), TenantID: tenant, MembershipStatus: "active", MembershipVersion: 2}, 5)); err != nil {
		t.Fatal(err)
	}

	target := &reconcileTarget{}
	interval := 15 * time.Minute
	self, err := NewSelfReconciler(desired, p, target, interval, nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().Add(24 * time.Hour)
	self.now = func() time.Time { return clock }

	run, err := self.Run(ctx)
	if err != nil || run.Outcome != OutcomeConverged {
		t.Fatalf("the first run: %+v, %v; want converged", run, err)
	}
	sent := target.reports[0]
	found := false
	for _, row := range sent.Rows {
		found = found || (row.MembershipID == membership && row.MembershipVersion == 2)
	}
	if sent.ConsumerID != "identity-control" || !found {
		t.Errorf("the report sent %+v; want this consumer's report holding the active Membership", sent)
	}

	// Another replica's tick within half an interval sends nothing.
	clock = clock.Add(interval / 3)
	if _, err := self.Run(ctx); !errors.Is(err, ErrNotDue) || len(target.reports) != 1 {
		t.Errorf("a second run within half an interval: %v, %d reports sent", err, len(target.reports))
	}

	// The next interval finds something: drift, with the count.
	clock = clock.Add(interval)
	target.result = ReconcileResult{Findings: []ReconcileFinding{{Classification: "extra", MembershipID: membership},
		{Classification: "missing", MembershipID: newID(t)}}}
	if run, err := self.Run(ctx); err != nil || run.Outcome != OutcomeDrift || run.Findings != 2 || run.Extra != 1 {
		t.Errorf("a run with findings: %+v, %v; want drift with 2 findings, 1 extra", run, err)
	}

	// Refused: unresolved, and the error returned for the scheduler to log.
	clock = clock.Add(interval)
	target.err, target.result = errors.New("organization: refused"), ReconcileResult{}
	if run, err := self.Run(ctx); err == nil || run.Outcome != OutcomeUnresolved {
		t.Errorf("a refused run: %+v, %v; want unresolved and an error", run, err)
	}

	got := selfRuns(t, p)
	want := []selfRun{{OutcomeConverged, 0, true}, {OutcomeDrift, 2, true}, {OutcomeUnresolved, 0, true}}
	if len(got) != len(want) {
		t.Fatalf("runs recorded %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("run %d recorded %+v, want %+v", i, got[i], want[i])
		}
	}
	// The age reads the newest answered run, the drift one, not the refused one after it.
	var newestAnswered bool
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT max(finished_at) FROM identity.reconcile_run
			WHERE sweep = 'organization_reconcile' AND outcome IN ('converged', 'drift'))
			= (SELECT finished_at FROM identity.reconcile_run WHERE sweep = 'organization_reconcile' AND outcome = 'drift')`).
			Scan(&newestAnswered)
	}); err != nil {
		t.Fatal(err)
	}
	var age *float64
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, selfReconcileAgeStatement).Scan(&age)
	}); err != nil || age == nil || !newestAnswered {
		t.Errorf("the age reads %v (%v); the newest answered run is the drift one: %v", age, err, newestAnswered)
	}
}

func TestASelfReconcilerNeedsAPositiveInterval(t *testing.T) {
	desired := &Desired{}
	if _, err := NewSelfReconciler(desired, noTx{}, &reconcileTarget{}, 0, nil); err == nil {
		t.Error("a zero interval was accepted")
	}
}

type noTx struct{}

func (noTx) InTx(context.Context, func(context.Context, db.Tx) error) error { return nil }
