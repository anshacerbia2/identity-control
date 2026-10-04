package tenantcontext

// Reconciliation against the real engine and the fake kernel (TDD-identity-control-002 2.1.0
// §Reconciliation).

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

type snapshotSource struct {
	mark int64
	rows []SnapshotRow
	err  error
}

func (s snapshotSource) OrganizationSnapshot(context.Context) (int64, []SnapshotRow, error) {
	return s.mark, s.rows, s.err
}

func findings(t *testing.T, p *db.Pool, tenant id.UUID) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT finding_class FROM identity.projection_finding WHERE tenant_id = $1`,
			tenant.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var class string
			if err := rows.Scan(&class); err != nil {
				return err
			}
			out[class]++
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// A Membership whose event was lost is added from the snapshot, and the sweep records it as missing;
// a member added by hand is removed and recorded as extra; a convergence that follows an event
// records nothing.
func TestASweepRepairsAndRecords(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	alice, aliceUser := h.person()
	bob, bobUser := h.person()
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	h.deliver(string(MembershipGranted), Membership{MembershipID: newID(t), PrincipalID: alice, TenantID: tenant,
		MembershipStatus: "active", MembershipVersion: 1}, 2)
	h.drain()
	if got := findings(t, h.pool, tenant); len(got) != 0 {
		t.Fatalf("a convergence after an event recorded findings: %v", got)
	}
	org, _ := h.organization(tenant)
	h.kernel.SetOrganizationMember(org.ID, "kc-by-hand")

	// Bob's grant never arrived; the snapshot carries it.
	rows := []SnapshotRow{{MembershipID: newID(t), PrincipalID: bob, TenantID: tenant, MembershipStatus: "active",
		MembershipVersion: 1, TenantStatus: "active", TenantVersion: 1, TenantSecurityVersion: 1}}
	sweep, err := NewReconciler(h.desired, h.pool, h.kernel, testRealm, snapshotSource{mark: 9, rows: rows}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sweep.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.drain()
	_, members := h.organization(tenant)
	held := map[keycloak.UserID]bool{}
	for _, m := range members {
		held[m] = true
	}
	if len(members) != 2 || !held[aliceUser] || !held[bobUser] {
		t.Errorf("after the sweep: members %v, want alice %s and bob %s", members, aliceUser, bobUser)
	}
	got := findings(t, h.pool, tenant)
	if got["missing_member"] != 1 || got["extra_member"] != 1 {
		t.Errorf("findings %v; want one missing and one extra member", got)
	}
}

// A snapshot row older than the held state changes nothing, for a Membership or for its Tenant.
func TestAnOlderSnapshotRowChangesNothing(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	principal, _ := h.person()
	membership := newID(t)
	h.deliver(string(TenantSuspended), Tenant{TenantID: tenant, TenantStatus: "suspended", TenantVersion: 5,
		TenantSecurityVersion: 3}, 1)
	h.deliver(string(MembershipRevoked), Membership{MembershipID: membership, PrincipalID: principal, TenantID: tenant,
		MembershipStatus: "revoked", MembershipVersion: 4}, 2)
	rows := []SnapshotRow{{MembershipID: membership, PrincipalID: principal, TenantID: tenant, MembershipStatus: "active",
		MembershipVersion: 3, TenantStatus: "active", TenantVersion: 4, TenantSecurityVersion: 2}}
	if err := h.desired.ApplySnapshot(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	if status, version := readMembership(t, h.pool, membership); status != "revoked" || version != 4 {
		t.Errorf("the Membership is %s at %d; want revoked at 4", status, version)
	}
	var tenantStatus string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_status FROM identity.tenant_desired WHERE tenant_id = $1`,
			tenant.String()).Scan(&tenantStatus)
	}); err != nil {
		t.Fatal(err)
	}
	if tenantStatus != "suspended" {
		t.Errorf("the Tenant is %s; want suspended", tenantStatus)
	}
}

// An Organization the authority never created is disabled and emptied, once; a snapshot that cannot
// be read leaves the kernel half of the sweep to run.
func TestAnUnknownOrganizationIsWithdrawn(t *testing.T) {
	h := newConvergerHarness(t)
	ctx := context.Background()
	stray := newID(t)
	orgID, err := h.kernel.CreateOrganization(ctx, testRealm, stray.String(), true)
	if err != nil {
		t.Fatal(err)
	}
	h.kernel.SetOrganizationMember(orgID, "kc-stray")
	sweep, err := NewReconciler(h.desired, h.pool, h.kernel, testRealm,
		snapshotSource{err: errors.New("organization: answered 403")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := sweep.Sweep(ctx)
	if err != nil || result.SnapshotErr == nil || result.Unknown != 1 {
		t.Fatalf("the sweep: %+v, %v", result, err)
	}
	org, err := h.kernel.GetOrganization(ctx, testRealm, orgID)
	members, _ := h.kernel.OrganizationMembers(ctx, testRealm, orgID)
	if err != nil || org.Enabled || len(members) != 0 {
		t.Errorf("the stray Organization: %+v, members %v, %v", org, members, err)
	}
	if again, err := sweep.Sweep(ctx); err != nil || again.Unknown != 0 {
		t.Errorf("a second sweep: %+v, %v; want nothing more to withdraw", again, err)
	}
	var count int
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.projection_finding
			WHERE finding_class = 'unknown_organization' AND detail->>'name' = $1`, stray.String()).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d unknown_organization findings; want one", count)
	}
}
