package tenantcontext

// A restore to an older point raises every tenant_security_version by 10^9 before Organization Control
// serves again, and republishes each withdrawn Tenant (ADR-ORG-003 §5.5). tenant_version is not
// bumped, and restarts from the backup, so it may be at or below the one held here. A Tenant is
// therefore ordered by (tenant_security_version, tenant_version), and these prove the withdrawal is
// applied, the events after it too, and a pre-restore event delivered late is not (TDD-identity-control-002
// 2.6.0).

import (
	"context"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// restoreBump is ADR-ORG-003 §5.5's margin, M = 10^9.
const restoreBump = 1_000_000_000

func readTenant(t *testing.T, p *db.Pool, tenant id.UUID) Tenant {
	t.Helper()
	held := Tenant{TenantID: tenant}
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_status, tenant_version, tenant_security_version
			FROM identity.tenant_desired WHERE tenant_id = $1`, tenant.String()).
			Scan(&held.TenantStatus, &held.TenantVersion, &held.TenantSecurityVersion)
	}); err != nil {
		t.Fatal(err)
	}
	return held
}

func TestATenantSecurityVersionBumpedByTheRestoreIsApplied(t *testing.T) {
	p := pool(t)
	desired, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := newID(t)

	// The consumer applied a restore made after the backup: active at version 7, security version 4.
	held := Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 7, TenantSecurityVersion: 4}
	if _, err := desired.Apply(ctx, envelope(t, TenantRestored, held, 10)); err != nil {
		t.Fatal(err)
	}
	// The backup held it suspended at version 5, security version 3. The restore bumps the security
	// version to 3 + 10^9 and republishes the suspension; tenant_version 5 is below the one held.
	withdrawal := Tenant{TenantID: tenant, TenantStatus: "suspended", TenantVersion: 5,
		TenantSecurityVersion: 3 + restoreBump}
	if outcome, err := desired.Apply(ctx, envelope(t, TenantSuspended, withdrawal, 20)); err != nil ||
		!outcome.Applied() || outcome.Superseded {
		t.Fatalf("the republished withdrawal: %+v, %v; want applied", outcome, err)
	}
	if got := readTenant(t, p, tenant); got != withdrawal {
		t.Errorf("after the withdrawal the Tenant is %+v, want %+v", got, withdrawal)
	}
	if c, _ := readConvergence(t, p, tenant); !c.priority || c.state != "pending" {
		t.Errorf("the withdrawal marks the Tenant priority: %+v", c)
	}

	// The next transition after the restore: tenant_version 6, security version one above the bump.
	next := Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 6, TenantSecurityVersion: 4 + restoreBump}
	if outcome, err := desired.Apply(ctx, envelope(t, TenantRestored, next, 30)); err != nil || outcome.Superseded {
		t.Fatalf("the transition after the restore: %+v, %v; want applied", outcome, err)
	}
	// A transition that does not raise the security version is still ordered by tenant_version.
	plain := Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 7, TenantSecurityVersion: 4 + restoreBump}
	if outcome, err := desired.Apply(ctx, envelope(t, TenantActivated, plain, 40)); err != nil || outcome.Superseded {
		t.Fatalf("a plain transition after the restore: %+v, %v; want applied", outcome, err)
	}
	// A pre-restore event delivered late: version 8 is above the held 7, and its security version is
	// below the bump, so it is discarded.
	late := Tenant{TenantID: tenant, TenantStatus: "suspended", TenantVersion: 8, TenantSecurityVersion: 5}
	if outcome, err := desired.Apply(ctx, envelope(t, TenantSuspended, late, 50)); err != nil || !outcome.Superseded {
		t.Errorf("a pre-restore event delivered late: %+v, %v; want superseded", outcome, err)
	}
	if got := readTenant(t, p, tenant); got != plain {
		t.Errorf("the Tenant is %+v, want %+v", got, plain)
	}
}

// The snapshot orders a Tenant by the same pair, so a snapshot read after the restore carries the
// withdrawal even where its tenant_version is below the one held.
func TestASnapshotRowAtTheBumpedSecurityVersionIsApplied(t *testing.T) {
	p := pool(t)
	desired, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant, principal, membership := newID(t), newID(t), newID(t)
	if _, err := desired.Apply(ctx, envelope(t, TenantRestored,
		Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 9, TenantSecurityVersion: 6}, 10)); err != nil {
		t.Fatal(err)
	}
	rows := []SnapshotRow{{MembershipID: membership, PrincipalID: principal, TenantID: tenant, MembershipStatus: "active",
		MembershipVersion: 1, TenantStatus: "suspended", TenantVersion: 8, TenantSecurityVersion: 5 + restoreBump}}
	if err := desired.ApplySnapshot(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if got := readTenant(t, p, tenant); got.TenantStatus != "suspended" || got.TenantSecurityVersion != 5+restoreBump {
		t.Errorf("after the snapshot the Tenant is %+v; want suspended at the bumped security version", got)
	}
}
