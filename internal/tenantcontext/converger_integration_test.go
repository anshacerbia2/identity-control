package tenantcontext

// Converging Tenants against the real engine and the fake kernel (TDD-identity-control-002 2.0.0
// §Converging a Tenant).

import (
	"context"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

const testRealm keycloak.Realm = "scnehaux"

type convergerHarness struct {
	t       *testing.T
	pool    *db.Pool
	desired *Desired
	kernel  *keycloakfake.Client
	conv    *Converger
}

func newConvergerHarness(t *testing.T) *convergerHarness {
	t.Helper()
	p := pool(t)
	desired, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &keycloakfake.Client{}
	conv, err := NewConverger(p, kernel, ConvergerConfig{Realm: testRealm, Interval: time.Second,
		AttemptTimeout: time.Second, Lease: 5 * time.Second, MaxAttempts: 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &convergerHarness{t: t, pool: p, desired: desired, kernel: kernel, conv: conv}
}

// person maps a Principal to a kernel user, as identity-control's creation path does.
func (h *convergerHarness) person() (id.UUID, keycloak.UserID) {
	h.t.Helper()
	principal := newID(h.t)
	user := keycloak.UserID("kc-" + principal.String())
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
		    (principal_id, realm, username, subject_type, keycloak_user_id, state)
		    VALUES ($1, $2, $3, 'human', $4, 'active')`,
			principal.String(), string(testRealm), "user-"+principal.String(), string(user))
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return principal, user
}

func (h *convergerHarness) deliver(eventType string, data any, position int64) {
	h.t.Helper()
	if _, err := h.desired.Apply(context.Background(), envelope(h.t, event.Type(eventType), data, position)); err != nil {
		h.t.Fatalf("delivering %s: %v", eventType, err)
	}
}

// drain converges until no Tenant is due. The database is shared, across the tests here and across
// CI's two runs of them, so a sweep may have marked many Tenants: each test asserts only its own.
func (h *convergerHarness) drain() {
	h.t.Helper()
	for i := 0; i < 10000; i++ {
		found, err := h.conv.RunOnce(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		if !found {
			return
		}
	}
}

func (h *convergerHarness) organization(tenant id.UUID) (keycloak.Organization, []keycloak.UserID) {
	h.t.Helper()
	ctx := context.Background()
	org, found, err := h.kernel.FindOrganization(ctx, testRealm, tenant.String())
	if err != nil || !found {
		h.t.Fatalf("the Organization for %s: found %v, %v", tenant, found, err)
	}
	members, err := h.kernel.OrganizationMembers(ctx, testRealm, org.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	return org, members
}

// A granted Membership adds the member, a revoked one removes it; a suspended Tenant disables its
// Organization and a restore re-enables it with its members.
func TestTheKernelFollowsTheDesiredState(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	alice, aliceUser := h.person()
	bob, _ := h.person()
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	aliceMembership, bobMembership := newID(t), newID(t)
	h.deliver(string(MembershipGranted), Membership{MembershipID: aliceMembership, PrincipalID: alice, TenantID: tenant,
		MembershipStatus: "active", MembershipVersion: 1}, 2)
	h.deliver(string(MembershipGranted), Membership{MembershipID: bobMembership, PrincipalID: bob, TenantID: tenant,
		MembershipStatus: "active", MembershipVersion: 1}, 3)
	h.drain()
	org, members := h.organization(tenant)
	if !org.Enabled || org.Alias != tenant.String() || len(members) != 2 {
		t.Fatalf("after two grants: %+v, members %v", org, members)
	}

	h.deliver(string(MembershipRevoked), Membership{MembershipID: bobMembership, PrincipalID: bob, TenantID: tenant,
		MembershipStatus: "revoked", MembershipVersion: 2}, 4)
	h.drain()
	if _, members := h.organization(tenant); len(members) != 1 || members[0] != aliceUser {
		t.Errorf("after the revoke: members %v, want only %s", members, aliceUser)
	}

	h.deliver(string(TenantSuspended), Tenant{TenantID: tenant, TenantStatus: "suspended", TenantVersion: 2,
		TenantSecurityVersion: 2}, 5)
	h.drain()
	if org, members := h.organization(tenant); org.Enabled || len(members) != 1 {
		t.Errorf("after the suspension: %+v, members %v; want disabled, the member kept", org, members)
	}
	h.deliver(string(TenantRestored), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 3,
		TenantSecurityVersion: 3}, 6)
	h.drain()
	if org, members := h.organization(tenant); !org.Enabled || len(members) != 1 || members[0] != aliceUser {
		t.Errorf("after the restore: %+v, members %v", org, members)
	}
	var state string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM identity.tenant_convergence WHERE tenant_id = $1`, tenant.String()).
			Scan(&state)
	}); err != nil {
		t.Fatal(err)
	}
	if state != "converged" {
		t.Errorf("the Tenant is %s, want converged", state)
	}
}

// A create whose response was lost is found by its exact name on the next attempt, not made twice;
// a hand-added member is removed.
func TestALostCreateIsFoundNotRepeated(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	h.kernel.AmbiguousOrganizationCreate = true
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	h.drain() // the create lands, its response is lost, and the Tenant backs off
	// The failed attempt backs off; make it due now.
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.tenant_convergence SET next_attempt_at = now() WHERE tenant_id = $1`,
			tenant.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.drain()
	if h.kernel.Calls.CreateOrganization != 1 {
		t.Errorf("%d creates; want one", h.kernel.Calls.CreateOrganization)
	}
	org, _ := h.organization(tenant)
	h.kernel.SetOrganizationMember(org.ID, "kc-by-hand")
	h.deliver(string(TenantRestored), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 2,
		TenantSecurityVersion: 1}, 2)
	h.drain()
	if _, members := h.organization(tenant); len(members) != 0 {
		t.Errorf("a member the authority never granted stayed: %v", members)
	}
}

// A Tenant the kernel keeps failing for is parked as unresolved after the configured attempts.
func TestAFailingTenantIsParked(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	h.kernel.FailOrganizations = keycloak.ErrUnavailable
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	for attempt := 0; attempt < 2; attempt++ {
		if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE identity.tenant_convergence SET next_attempt_at = now() WHERE tenant_id = $1`,
				tenant.String())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		h.drain()
	}
	var state, class string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, coalesce(last_error_class, '') FROM identity.tenant_convergence
			WHERE tenant_id = $1`, tenant.String()).Scan(&state, &class)
	}); err != nil {
		t.Fatal(err)
	}
	if state != "unresolved" || class != "unavailable" {
		t.Errorf("after two failures: %s (%s), want unresolved (unavailable)", state, class)
	}
}

// A recorded Organization identifier that names another Tenant's Organization is not trusted: the
// converger finds this Tenant's by its name and leaves the other untouched.
func TestARecordedIdentifierNamingAnotherTenantIsNotTrusted(t *testing.T) {
	h := newConvergerHarness(t)
	ctx := context.Background()
	other, err := h.kernel.CreateOrganization(ctx, testRealm, newID(t).String(), true)
	if err != nil {
		t.Fatal(err)
	}
	h.kernel.SetOrganizationMember(other, "kc-other-tenant")
	tenant := newID(t)
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.tenant_convergence SET kernel_org_id = $2 WHERE tenant_id = $1`,
			tenant.String(), other)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.drain()
	if members, _ := h.kernel.OrganizationMembers(ctx, testRealm, other); len(members) != 1 {
		t.Errorf("the other Tenant's Organization was changed: members %v", members)
	}
	if org, _ := h.organization(tenant); org.ID == other {
		t.Error("this Tenant was converged onto another Tenant's Organization")
	}
}
