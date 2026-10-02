package registration

// Audience changes against the real database (TDD-identity-control-003 §Registration Changes).

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func (h *harness) audienceProposal(registration Registration, by id.UUID, provider bool, audience ...string) Proposal {
	return Proposal{RegistrationID: registration.ID, Audience: &audience, ExpectedVersion: registration.Version,
		ProposedBy: by, Reason: "the caller moves to the API's own resource", Provider: provider}
}

func (h *harness) spec(client string) keycloak.ClientSpec {
	h.t.Helper()
	spec, _, ok := h.kernel.Spec(keycloak.ClientUUID(client))
	if !ok {
		h.t.Fatalf("the kernel holds no client %s", client)
	}
	return spec
}

// An applied audience change writes desired state sorted, makes the kernel's audience exactly the
// set, and re-derives the lifespan from the shortest lifetime class it names.
func TestAnAudienceChangeRewritesTheAudienceAndTheLifespan(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.resource("aud-orders", "L1")
	h.resource("aud-admin", "L0")
	registration := h.publicClient("aud-caller")
	_, client := h.state(registration.ID)

	change, created, err := h.service.ProposeChange(ctx, h.audienceProposal(registration, h.caller, true, "aud-orders", "aud-admin"))
	if err != nil || !created || change.State != ChangeApplied || change.Kind != ChangeAudience {
		t.Fatalf("propose: %+v, %v, %v", change, created, err)
	}
	want := []string{"aud-admin", "aud-orders"}
	if !slices.Equal(change.Audience, want) || len(change.PreviousAudience) != 0 || change.RedirectURIs != nil {
		t.Errorf("the change records %v from %v (redirects %v)", change.Audience, change.PreviousAudience, change.RedirectURIs)
	}
	got, _ := h.service.Get(ctx, registration.ID)
	if !slices.Equal(got.Audience, want) || got.Version != registration.Version+1 {
		t.Errorf("desired state is %v at version %d", got.Audience, got.Version)
	}
	if spec := h.spec(client); !slices.Equal(spec.Audience, want) {
		t.Errorf("the kernel client's audience is %v", spec.Audience)
	}
	if live := h.live(keycloak.ClientUUID(client)); live.AccessTokenLifespan != 240 {
		t.Errorf("the lifespan is %d; an L0 resource in the audience derives 240", live.AccessTokenLifespan)
	}

	narrowed, _, err := h.service.ProposeChange(ctx, h.audienceProposal(got, h.caller, true, "aud-orders"))
	if err != nil || narrowed.State != ChangeApplied || !slices.Equal(narrowed.PreviousAudience, want) {
		t.Fatalf("narrow: %+v, %v", narrowed, err)
	}
	if live := h.live(keycloak.ClientUUID(client)); live.AccessTokenLifespan != 540 {
		t.Errorf("the lifespan is %d after narrowing to an L1 resource, want 540", live.AccessTokenLifespan)
	}
	if spec := h.spec(client); !slices.Equal(spec.Audience, []string{"aud-orders"}) {
		t.Errorf("the kernel client's audience is %v after narrowing", spec.Audience)
	}
}

func TestAnAudienceChangeIsRefusedWhenItBreaksARule(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.resource("aud-rules-api", "L1")
	registration := h.publicClient("aud-rules")
	resource := h.resource("aud-rules-other", "L1")
	retired := h.resource("aud-rules-retired", "L1")
	if _, err := h.service.Retire(ctx, h.change(retired.ID, "no longer served")); err != nil {
		t.Fatalf("retire: %v", err)
	}

	both := h.audienceProposal(registration, h.caller, true, "aud-rules-api")
	both.RedirectURIs = movedCallback
	for name, proposal := range map[string]Proposal{
		"an unregistered resource": h.audienceProposal(registration, h.caller, true, "aud-nobody"),
		"a retired resource":       h.audienceProposal(registration, h.caller, true, "aud-rules-retired"),
		"the registration itself":  h.audienceProposal(registration, h.caller, true, "aud-rules"),
		"a repeated resource":      h.audienceProposal(registration, h.caller, true, "aud-rules-api", "aud-rules-api"),
		"not a client_key":         h.audienceProposal(registration, h.caller, true, "Not A Key"),
		"the registered audience":  h.audienceProposal(registration, h.caller, true),
		"a resource's audience":    h.audienceProposal(resource, h.caller, true, "aud-rules-api"),
		"both kinds at once":       both,
	} {
		if _, _, err := h.service.ProposeChange(ctx, proposal); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s answered %v, want ErrInvalid", name, err)
		}
	}

	// The order of an audience carries no meaning, so a reordered set is the registered one.
	applied, _, err := h.service.ProposeChange(ctx, h.audienceProposal(registration, h.caller, true, "aud-rules-api", "aud-rules-other"))
	if err != nil {
		t.Fatal(err)
	}
	moved, _ := h.service.Get(ctx, applied.Registration)
	if _, _, err := h.service.ProposeChange(ctx, h.audienceProposal(moved, h.caller, true, "aud-rules-other", "aud-rules-api")); !errors.Is(err, ErrInvalid) {
		t.Errorf("the registered audience reordered answered %v, want ErrInvalid", err)
	}
}

// An owner adds only resources it owns, because the resource's owners did not agree to a client they
// do not know; removing is never refused. A provider adds any registered resource.
func TestAnOwnerAddsToAnAudienceOnlyResourcesItOwns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owned := h.resource("aud-owned-api", "L1")
	h.resource("aud-foreign-api", "L1")
	registration := h.publicClient("aud-owner-client")
	alice := h.person("human")
	if _, err := h.service.GrantOwner(ctx, OwnershipChange{RegistrationID: owned.ID, Principal: alice, ChangedBy: h.caller,
		Reason: "the orders team"}); err != nil {
		t.Fatal(err)
	}

	if _, _, err := h.service.ProposeChange(ctx, h.audienceProposal(registration, alice, false, "aud-foreign-api")); !errors.Is(err, ErrNotResourceOwner) {
		t.Errorf("an owner adding a resource it does not own answered %v, want ErrNotResourceOwner", err)
	}
	added, _, err := h.service.ProposeChange(ctx, h.audienceProposal(registration, alice, false, "aud-owned-api"))
	if err != nil || added.State != ChangeApplied {
		t.Fatalf("an owner adding its own resource: %+v, %v", added, err)
	}

	// A provider adds the foreign resource; the owner then removes the one it owns from a set that
	// still names the foreign one, which narrows and is not refused.
	current, _ := h.service.Get(ctx, registration.ID)
	if _, _, err := h.service.ProposeChange(ctx, h.audienceProposal(current, h.caller, true, "aud-owned-api", "aud-foreign-api")); err != nil {
		t.Fatalf("a provider adding a resource: %v", err)
	}
	current, _ = h.service.Get(ctx, registration.ID)
	if _, _, err := h.service.ProposeChange(ctx, h.audienceProposal(current, alice, false, "aud-foreign-api")); err != nil {
		t.Errorf("an owner narrowing an audience was refused: %v", err)
	}
}

// A kernel that refuses the audience leaves desired state and the version where they were.
func TestAnAudienceChangeTheKernelRefusesIsNotRecorded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.resource("aud-fail-api", "L1")
	registration := h.publicClient("aud-fail")
	h.kernel.FailPatch = keycloak.ErrUnavailable
	if _, _, err := h.service.ProposeChange(ctx, h.audienceProposal(registration, h.caller, true, "aud-fail-api")); err == nil {
		t.Fatal("a change the kernel refused was applied")
	}
	h.kernel.FailPatch = nil
	got, _ := h.service.Get(ctx, registration.ID)
	if len(got.Audience) != 0 || got.Version != registration.Version {
		t.Errorf("a refused change left %v at version %d", got.Audience, got.Version)
	}
	changes, _ := h.service.Changes(ctx, registration.ID)
	if len(changes) != 0 {
		t.Errorf("a refused change was recorded: %+v", changes)
	}
}
