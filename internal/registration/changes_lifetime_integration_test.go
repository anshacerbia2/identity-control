package registration

// Lifetime-class changes against the real database (ADR-IAM-003 §5.9, STD-IAM-002 §3.3,
// TDD-identity-control-003 §Registration Changes).

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func (h *harness) lifetimeProposal(registration Registration, by id.UUID, class string) Proposal {
	return Proposal{RegistrationID: registration.ID, LifetimeClass: &class, ExpectedVersion: registration.Version,
		ProposedBy: by, Reason: "the API now moves funds", Provider: true}
}

// callerOf registers a public client whose audience names the given resources, and returns its
// kernel client.
func (h *harness) callerOf(key string, resources ...string) keycloak.ClientUUID {
	h.t.Helper()
	req := h.request(key, ProfilePublic)
	req.Audience = resources
	registration, err := h.service.Register(context.Background(), req)
	if err != nil {
		h.t.Fatalf("register %s: %v", key, err)
	}
	_, client := h.state(registration.ID)
	return keycloak.ClientUUID(client)
}

// An applied lifetime-class change writes the class and the version, and moves the lifespan of every
// caller whose shortest class it changes, and of no other.
func TestALifetimeClassChangeMovesEveryCaller(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	orders := h.resource("lt-orders", "L1")
	h.resource("lt-admin", "L0")
	h.resource("lt-other", "L2")
	only := h.callerOf("lt-only", "lt-orders")
	shared := h.callerOf("lt-shared", "lt-orders", "lt-admin")
	unrelated := h.callerOf("lt-unrelated", "lt-other")
	if h.live(only).AccessTokenLifespan != 540 || h.live(shared).AccessTokenLifespan != 240 ||
		h.live(unrelated).AccessTokenLifespan != 900 {
		t.Fatalf("the callers start at %d, %d, %d", h.live(only).AccessTokenLifespan, h.live(shared).AccessTokenLifespan,
			h.live(unrelated).AccessTokenLifespan)
	}

	change, created, err := h.service.ProposeChange(ctx, h.lifetimeProposal(orders, h.caller, "L0"))
	if err != nil || !created || change.State != ChangeApplied || change.Kind != ChangeLifetimeClass {
		t.Fatalf("propose: %+v, %v, %v", change, created, err)
	}
	if stringOf(change.PreviousLifetimeClass) != "L1" || stringOf(change.LifetimeClass) != "L0" ||
		change.RedirectURIs != nil || change.Audience != nil {
		t.Errorf("the change records %+v", change)
	}
	got, _ := h.service.Get(ctx, orders.ID)
	if got.LifetimeClass != "L0" || got.Version != orders.Version+1 {
		t.Errorf("desired state is %s at version %d", got.LifetimeClass, got.Version)
	}
	if h.live(only).AccessTokenLifespan != 240 {
		t.Errorf("the only caller's lifespan is %d, want 240 from L0", h.live(only).AccessTokenLifespan)
	}
	if h.live(shared).AccessTokenLifespan != 240 || h.live(unrelated).AccessTokenLifespan != 900 {
		t.Errorf("callers it does not move hold %d and %d", h.live(shared).AccessTokenLifespan, h.live(unrelated).AccessTokenLifespan)
	}

	// Lengthening moves the caller that has no shorter class, and leaves the one that has.
	longer, _, err := h.service.ProposeChange(ctx, h.lifetimeProposal(got, h.caller, "L2"))
	if err != nil || longer.State != ChangeApplied {
		t.Fatalf("lengthen: %+v, %v", longer, err)
	}
	if h.live(only).AccessTokenLifespan != 900 || h.live(shared).AccessTokenLifespan != 240 {
		t.Errorf("after L2 the callers hold %d and %d, want 900 and 240", h.live(only).AccessTokenLifespan,
			h.live(shared).AccessTokenLifespan)
	}
}

func TestALifetimeClassChangeIsRefusedWhenItBreaksARule(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	resource := h.resource("lt-rules-api", "L1")
	client := h.publicClient("lt-rules-client")

	both := h.lifetimeProposal(resource, h.caller, "L0")
	both.Audience = &[]string{}
	for name, proposal := range map[string]Proposal{
		"a client's lifetime class":   h.lifetimeProposal(client, h.caller, "L0"),
		"a class that does not exist": h.lifetimeProposal(resource, h.caller, "L9"),
		"the registered class":        h.lifetimeProposal(resource, h.caller, "L1"),
		"two kinds at once":           both,
	} {
		if _, _, err := h.service.ProposeChange(ctx, proposal); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s answered %v, want ErrInvalid", name, err)
		}
	}
	stale := h.lifetimeProposal(resource, h.caller, "L0")
	stale.ExpectedVersion++
	if _, _, err := h.service.ProposeChange(ctx, stale); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("a stale version answered %v, want ErrVersionConflict", err)
	}
}

// In production a lifetime-class change waits for a provider other than its proposer, and moves
// nothing until it is approved.
func TestAProductionLifetimeClassChangeWaitsForAnotherProvider(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	resource := h.resource("lt-prod-api", "L1")
	caller := h.callerOf("lt-prod-caller", "lt-prod-api")

	change, created, err := h.service.ProposeChange(ctx, h.lifetimeProposal(resource, h.caller, "L0"))
	if err != nil || !created || change.State != ChangeProposed || !change.ApprovalRequired {
		t.Fatalf("propose: %+v, %v, %v", change, created, err)
	}
	if h.live(caller).AccessTokenLifespan != 540 {
		t.Errorf("a waiting change moved the caller to %d", h.live(caller).AccessTokenLifespan)
	}
	if again, created, err := h.service.ProposeChange(ctx, h.lifetimeProposal(resource, h.caller, "L0")); err != nil || created || again.ID != change.ID {
		t.Errorf("a retried proposal answered %v, %v, %v", again.ID, created, err)
	}
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, h.caller), true); !errors.Is(err, ErrSelfApproval) {
		t.Errorf("the proposer's approval answered %v, want ErrSelfApproval", err)
	}
	applied, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, h.person("human")), true)
	if err != nil || applied.State != ChangeApplied {
		t.Fatalf("approve: %+v, %v", applied, err)
	}
	if got, _ := h.service.Get(ctx, resource.ID); got.LifetimeClass != "L0" || h.live(caller).AccessTokenLifespan != 240 {
		t.Errorf("an approved change left %s and a caller at %d", got.LifetimeClass, h.live(caller).AccessTokenLifespan)
	}
}

// A kernel that refuses one caller rolls the change back and puts back the callers already written.
func TestALifetimeClassChangeTheKernelRefusesPutsTheCallersBack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	resource := h.resource("lt-fail-api", "L1")
	first := h.callerOf("lt-fail-first", "lt-fail-api")
	second := h.callerOf("lt-fail-second", "lt-fail-api")
	h.kernel.FailPatchOf = map[keycloak.ClientUUID]error{second: keycloak.ErrUnavailable}

	if _, _, err := h.service.ProposeChange(ctx, h.lifetimeProposal(resource, h.caller, "L0")); err == nil {
		t.Fatal("a change the kernel refused was applied")
	}
	h.kernel.FailPatchOf = nil
	if h.live(first).AccessTokenLifespan != 540 || h.live(second).AccessTokenLifespan != 540 {
		t.Errorf("after the refusal the callers hold %d and %d, want 540 put back", h.live(first).AccessTokenLifespan,
			h.live(second).AccessTokenLifespan)
	}
	got, _ := h.service.Get(ctx, resource.ID)
	changes, _ := h.service.Changes(ctx, resource.ID)
	if got.LifetimeClass != "L1" || got.Version != resource.Version || len(changes) != 0 {
		t.Errorf("a refused change left %s at version %d and recorded %+v", got.LifetimeClass, got.Version, changes)
	}
}
