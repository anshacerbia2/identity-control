package tenantcontext

// Applying organization-control's repair, and the report an operator posts (TDD-identity-control-002
// 2.2.0).

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/delivery"
)

type finding struct {
	Classification string      `json:"classification"`
	MembershipID   id.UUID     `json:"membership_id"`
	State          *Membership `json:"state"`
}

func repair(consumer string, findings ...finding) map[string]any {
	return map[string]any{"consumer_id": consumer, "mark": 50, "findings": findings}
}

// A repair carrying a revoked state removes the member; an extra with no state makes the Membership
// absent and removes its member too; a repair for another consumer applies nothing.
func TestARepairIsAppliedByVersion(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	alice, _ := h.person()
	bob, _ := h.person()
	aliceMembership, bobMembership := newID(t), newID(t)
	h.deliver(string(TenantActivated), Tenant{TenantID: tenant, TenantStatus: "active", TenantVersion: 1,
		TenantSecurityVersion: 1}, 1)
	for _, m := range []Membership{
		{MembershipID: aliceMembership, PrincipalID: alice, TenantID: tenant, MembershipStatus: "active", MembershipVersion: 1},
		{MembershipID: bobMembership, PrincipalID: bob, TenantID: tenant, MembershipStatus: "active", MembershipVersion: 1},
	} {
		h.deliver(string(MembershipGranted), m, 2)
	}
	h.drain()

	other := repair("foundation-reference", finding{Classification: "extra", MembershipID: aliceMembership})
	if _, err := h.desired.Apply(context.Background(), envelope(t, RepairReconciled, other, 10)); err != nil {
		t.Fatal(err)
	}
	if status, _ := readMembership(t, h.pool, aliceMembership); status != "active" {
		t.Errorf("another consumer's sweep changed alice to %s", status)
	}

	revoked := Membership{MembershipID: aliceMembership, PrincipalID: alice, TenantID: tenant, MembershipStatus: "revoked",
		MembershipVersion: 3}
	ours := repair("identity-control",
		finding{Classification: "mismatch", MembershipID: aliceMembership, State: &revoked},
		finding{Classification: "extra", MembershipID: bobMembership})
	if outcome, err := h.desired.Apply(context.Background(), envelope(t, RepairReconciled, ours, 11)); err != nil ||
		!outcome.Applied() {
		t.Fatalf("our sweep: %+v, %v", outcome, err)
	}
	if status, version := readMembership(t, h.pool, aliceMembership); status != "revoked" || version != 3 {
		t.Errorf("alice is %s at %d; want revoked at 3", status, version)
	}
	if status, _ := readMembership(t, h.pool, bobMembership); status != "absent" {
		t.Errorf("bob is %s; want absent", status)
	}
	h.drain()
	if _, members := h.organization(tenant); len(members) != 0 {
		t.Errorf("after the repair: members %v", members)
	}
}

// A missing finding with no state comes from a producer that sent versions alone: the sweep is
// refused as a whole, and nothing is withdrawn.
func TestAStatelessMissingRefusesTheSweep(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	alice, _ := h.person()
	membership := newID(t)
	h.deliver(string(MembershipGranted), Membership{MembershipID: membership, PrincipalID: alice, TenantID: tenant,
		MembershipStatus: "active", MembershipVersion: 1}, 1)
	bad := repair("identity-control", finding{Classification: "missing", MembershipID: membership})
	if _, err := h.desired.Apply(context.Background(), envelope(t, RepairReconciled, bad, 2)); !errors.Is(err, delivery.ErrPoison) {
		t.Errorf("a stateless missing: %v, want poison", err)
	}
	if status, _ := readMembership(t, h.pool, membership); status != "active" {
		t.Errorf("the Membership is %s; want it untouched", status)
	}
}

// The report lists the active Memberships, at the position this consumer has applied.
func TestTheReportListsTheActiveMemberships(t *testing.T) {
	h := newConvergerHarness(t)
	tenant := newID(t)
	alice, _ := h.person()
	active, revoked := newID(t), newID(t)
	h.deliver(string(MembershipGranted), Membership{MembershipID: active, PrincipalID: alice, TenantID: tenant,
		MembershipStatus: "active", MembershipVersion: 2}, 1)
	h.deliver(string(MembershipRevoked), Membership{MembershipID: revoked, PrincipalID: alice, TenantID: tenant,
		MembershipStatus: "revoked", MembershipVersion: 4}, 2)
	report, err := h.desired.Report(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	listed := map[id.UUID]int64{}
	for _, row := range report.Rows {
		listed[row.MembershipID] = row.MembershipVersion
	}
	if report.ConsumerID != "identity-control" || listed[active] != 2 {
		t.Errorf("the report %+v does not list the active Membership at 2", report)
	}
	if _, found := listed[revoked]; found {
		t.Error("the report lists a revoked Membership")
	}
}
