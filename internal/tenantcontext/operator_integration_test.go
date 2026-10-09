package tenantcontext

// The delivery-to-converged measure, sweep runs and the operator routes' reads and re-drive, against
// the real engine and the fake kernel (TDD-identity-control-002 2.5.0).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

func (h *convergerHarness) convergence(tenant id.UUID) (string, *time.Time, bool, int) {
	h.t.Helper()
	var (
		state     string
		delivered *time.Time
		sweep     bool
		attempts  int
	)
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, delivered_at, sweep, attempts FROM identity.tenant_convergence
		    WHERE tenant_id = $1`, tenant.String()).Scan(&state, &delivered, &sweep, &attempts)
	}); err != nil {
		h.t.Fatal(err)
	}
	return state, delivered, sweep, attempts
}

// collect gathers what a manual reader holds, by instrument name.
func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Aggregation {
	t.Helper()
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	out := map[string]metricdata.Aggregation{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			out[m.Name] = m.Data
		}
	}
	return out
}

// A delivery sets delivered_at, a later one keeps it, and the convergence that records the Tenant
// converged clears it and measures the delay from the first delivery.
func TestDeliveryToConvergedIsMeasuredFromTheFirstDelivery(t *testing.T) {
	h := newConvergerHarness(t)
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	conv, err := NewConverger(h.pool, h.kernel, h.conv.cfg, nil, meter)
	if err != nil {
		t.Fatal(err)
	}
	h.conv = conv
	if err := h.desired.Instrument(meter); err != nil {
		t.Fatal(err)
	}

	tenant := newID(t)
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	_, first, _, _ := h.convergence(tenant)
	if first == nil {
		t.Fatal("a delivery left delivered_at null")
	}
	time.Sleep(20 * time.Millisecond)
	h.deliver(string(TenantSuspended), Tenant{TenantID: tenant, TenantStatus: "suspended", TenantVersion: 2,
		TenantSecurityVersion: 2}, 2)
	if _, second, _, _ := h.convergence(tenant); second == nil || !second.Equal(*first) {
		t.Errorf("a second delivery moved delivered_at from %v to %v", first, second)
	}

	h.drain()
	state, delivered, _, _ := h.convergence(tenant)
	if state != "converged" || delivered != nil {
		t.Errorf("after convergence the Tenant is %s with delivered_at %v", state, delivered)
	}
	got := collect(t, reader)
	delay, ok := got["identity.tenant_projection.delivery_to_converged"].(metricdata.Histogram[float64])
	if !ok || len(delay.DataPoints) == 0 || delay.DataPoints[0].Count == 0 {
		t.Fatalf("no delivery-to-converged delay was recorded: %v", got)
	}
	for _, name := range []string{"identity.tenant_projection.marked", "identity.tenant_projection.converged",
		"identity.tenant_projection.unresolved"} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s was not recorded", name)
		}
	}

	// A sweep marks it again without a delivery: delivered_at stays null.
	sweep := h.reconciler(t)
	if err := sweep.Redrive(context.Background(), tenant, newID(t), "after the kernel was repaired"); err != nil {
		t.Fatal(err)
	}
	if state, delivered, swept, _ := h.convergence(tenant); state != "pending" || delivered != nil || !swept {
		t.Errorf("a re-drive left the Tenant %s, delivered_at %v, sweep %v", state, delivered, swept)
	}
}

func (h *convergerHarness) reconciler(t *testing.T) *Reconciler {
	t.Helper()
	r, err := NewReconciler(h.desired, h.pool, h.kernel, testRealm, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A re-drive of an unresolved Tenant makes it pending with its attempts reset; one the desired state
// does not hold is refused. The unconverged listing holds pending and unresolved Tenants only.
func TestARedriveMakesAnUnresolvedTenantPendingAgain(t *testing.T) {
	h := newConvergerHarness(t)
	sweep := h.reconciler(t)
	ctx := context.Background()
	tenant := newID(t)
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.tenant_convergence SET state = 'unresolved', attempts = 8,
		    last_error_class = 'forbidden' WHERE tenant_id = $1`, tenant.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	listed, err := sweep.Unconverged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if u := find(listed, tenant); u == nil || u.State != "unresolved" || u.LastErrorClass != "forbidden" || u.DeliveredAt == nil {
		t.Errorf("the unconverged listing holds %+v for the Tenant", u)
	}

	if err := sweep.Redrive(ctx, tenant, newID(t), " "); err == nil {
		t.Error("a re-drive without a reason was accepted")
	}
	if err := sweep.Redrive(ctx, newID(t), newID(t), "why"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("re-driving an unknown Tenant answered %v, want ErrUnknownTenant", err)
	}
	if err := sweep.Redrive(ctx, tenant, newID(t), "the credential's roles are back"); err != nil {
		t.Fatal(err)
	}
	if state, _, swept, attempts := h.convergence(tenant); state != "pending" || attempts != 0 || !swept {
		t.Errorf("the re-driven Tenant is %s, %d attempts, sweep %v", state, attempts, swept)
	}
	h.drain()
	listed, _ = sweep.Unconverged(ctx)
	if u := find(listed, tenant); u != nil {
		t.Errorf("a converged Tenant is listed: %+v", u)
	}
}

func find(listed []Unconverged, tenant id.UUID) *Unconverged {
	for i := range listed {
		if listed[i].TenantID == tenant {
			return &listed[i]
		}
	}
	return nil
}

// A sweep records its run: converged when nothing was unknown, drift when an unknown Organization was
// disabled, unresolved when the snapshot could not be read. The findings listing filters by class and
// carries no kernel user identifier.
func TestASweepRecordsItsRun(t *testing.T) {
	h := newConvergerHarness(t)
	ctx := context.Background()
	run := func(r *Reconciler) (SweepResult, string, int) {
		t.Helper()
		result, err := r.Sweep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var (
			outcome  string
			findings int
		)
		if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx, `SELECT outcome, findings FROM identity.reconcile_run
			    WHERE run_id = $1 AND sweep = 'tenant_context' AND finished_at IS NOT NULL`,
				result.RunID.String()).Scan(&outcome, &findings)
		}); err != nil {
			t.Fatalf("the run is not recorded finished: %v", err)
		}
		return result, outcome, findings
	}

	// An Organization no known Tenant names, with a member: drift.
	stray := newID(t)
	orgID, err := h.kernel.CreateOrganization(ctx, testRealm, stray.String(), true)
	if err != nil {
		t.Fatal(err)
	}
	_, user := h.person()
	if err := h.kernel.AddOrganizationMember(ctx, testRealm, orgID, user); err != nil {
		t.Fatal(err)
	}
	result, outcome, count := run(h.reconciler(t))
	if result.Outcome != OutcomeDrift || outcome != OutcomeDrift || count < 1 {
		t.Errorf("a sweep that disabled an unknown Organization recorded %s, %s, %d findings", result.Outcome, outcome, count)
	}
	if _, outcome, _ := run(h.reconciler(t)); outcome != OutcomeConverged {
		t.Errorf("the next sweep recorded %s, want converged", outcome)
	}

	failing, err := NewReconciler(h.desired, h.pool, h.kernel, testRealm, snapshotSource{err: errors.New("refused")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, outcome, _ := run(failing); outcome != OutcomeUnresolved {
		t.Errorf("a sweep without its snapshot recorded %s, want unresolved", outcome)
	}

	listed, err := h.reconciler(t).Findings(ctx, "unknown_organization", 500)
	if err != nil || len(listed) == 0 || listed[0].FindingClass != "unknown_organization" {
		t.Fatalf("the findings listing holds %+v (%v)", listed, err)
	}
	for _, f := range listed {
		if f.FindingClass != "unknown_organization" {
			t.Errorf("a filtered listing holds a %s finding", f.FindingClass)
		}
	}
	if _, err := h.reconciler(t).Findings(ctx, "nonsense", 0); !errors.Is(err, ErrUnknownClass) {
		t.Errorf("an unknown class answered %v", err)
	}
}

// A sweep's convergence records a finding naming the kernel user; the listing keeps the principal and
// drops the kernel identifier.
func TestTheFindingsListingCarriesNoKernelUser(t *testing.T) {
	h := newConvergerHarness(t)
	ctx := context.Background()
	tenant := newID(t)
	_, user := h.person()
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	h.drain()
	org, _ := h.organization(tenant)
	if err := h.kernel.AddOrganizationMember(ctx, testRealm, org.ID, user); err != nil {
		t.Fatal(err)
	}
	if err := h.reconciler(t).Redrive(ctx, tenant, newID(t), "a member was added by hand"); err != nil {
		t.Fatal(err)
	}
	h.drain()
	listed, err := h.reconciler(t).Findings(ctx, "extra_member", 500)
	if err != nil {
		t.Fatal(err)
	}
	var mine *Finding
	for i := range listed {
		if listed[i].TenantID != nil && *listed[i].TenantID == tenant {
			mine = &listed[i]
		}
	}
	if mine == nil || mine.PrincipalID == nil {
		t.Fatalf("no extra_member finding naming the person for the Tenant: %+v", listed)
	}
	if string(mine.Detail) == "" || containsKey(t, mine.Detail, "kernel_user_id") {
		t.Errorf("the listed detail carries a kernel user: %s", mine.Detail)
	}
}

func containsKey(t *testing.T, raw []byte, key string) bool {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	_, ok := fields[key]
	return ok
}

// The sweep-age gauge reads the newest finished run once there is one.
func TestTheSweepAgeIsObserved(t *testing.T) {
	h := newConvergerHarness(t)
	sweep := h.reconciler(t)
	reader := sdkmetric.NewManualReader()
	if err := sweep.Instrument(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")); err != nil {
		t.Fatal(err)
	}
	if err := sweep.Instrument(nil); err != nil {
		t.Errorf("a nil meter answered %v", err)
	}
	if _, err := sweep.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	age, ok := collect(t, reader)["identity.tenant_projection.sweep_age"].(metricdata.Gauge[float64])
	if !ok || len(age.DataPoints) != 1 || age.DataPoints[0].Value < 0 {
		t.Errorf("sweep_age observed %+v", age)
	}
}
