package registration

// Registration changes against the real database (ADR-IAM-003 §5.2, TDD-identity-control-003
// §Registration Changes).

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

var movedCallback = []string{"https://app.example.com/callback", "https://new.example.com/callback"}

func (h *harness) publicClient(key string) Registration {
	h.t.Helper()
	registration, err := h.service.Register(context.Background(), h.request(key, ProfilePublic))
	if err != nil {
		h.t.Fatalf("register %s: %v", key, err)
	}
	return registration
}

func (h *harness) proposal(registration Registration, by id.UUID, uris []string) Proposal {
	return Proposal{RegistrationID: registration.ID, RedirectURIs: uris, ExpectedVersion: registration.Version,
		ProposedBy: by, Reason: "the callback moves to the new host"}
}

func (h *harness) decision(change Change, decision string, by id.UUID) Decision {
	return Decision{RegistrationID: change.Registration, ChangeID: change.ID, Decision: decision, DecidedBy: by,
		Reason: "reviewed the new host"}
}

func TestANonProductionChangeIsAppliedAtOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	registration := h.publicClient("change-now")
	_, client := h.state(registration.ID)

	change, created, err := h.service.ProposeChange(ctx, h.proposal(registration, h.caller, movedCallback))
	if err != nil || !created {
		t.Fatalf("propose: %+v, %v, %v", change, created, err)
	}
	if change.State != ChangeApplied || change.ApprovalRequired || change.DecidedBy == nil || *change.DecidedBy != h.caller {
		t.Errorf("a non-production change is %+v, want applied by its proposer", change)
	}
	if !slices.Equal(change.PreviousRedirectURIs, registration.RedirectURIs) || change.BaseVersion != registration.Version {
		t.Errorf("the change's preview is %v at version %d", change.PreviousRedirectURIs, change.BaseVersion)
	}
	got, _ := h.service.Get(ctx, registration.ID)
	if !slices.Equal(got.RedirectURIs, movedCallback) || got.Version != registration.Version+1 {
		t.Errorf("desired state is %v at version %d", got.RedirectURIs, got.Version)
	}
	if live := h.live(keycloak.ClientUUID(client)); !slices.Equal(live.RedirectURIs, movedCallback) {
		t.Errorf("the kernel client holds %v", live.RedirectURIs)
	}

	// The version read before is stale now.
	if _, _, err := h.service.ProposeChange(ctx, h.proposal(registration, h.caller, []string{"https://other.example.com/cb"})); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("a stale version answered %v, want ErrVersionConflict", err)
	}
}

func TestAProposalIsRefusedWhenItBreaksARule(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	registration := h.publicClient("change-rules")
	resource := h.resource("change-api", "L1")
	for name, c := range map[string]struct {
		proposal Proposal
		want     error
	}{
		"wildcard":   {h.proposal(registration, h.caller, []string{"https://*.example.com/cb"}), ErrInvalid},
		"plain http": {h.proposal(registration, h.caller, []string{"http://app.example.com/cb"}), ErrInvalid},
		"repeated":   {h.proposal(registration, h.caller, []string{"https://a.example.com/cb", "https://a.example.com/cb"}), ErrInvalid},
		"empty":      {h.proposal(registration, h.caller, nil), ErrInvalid},
		"unchanged":  {h.proposal(registration, h.caller, registration.RedirectURIs), ErrInvalid},
		"no version": {Proposal{RegistrationID: registration.ID, RedirectURIs: movedCallback, ProposedBy: h.caller, Reason: "r"}, ErrInvalid},
		"no reason":  {Proposal{RegistrationID: registration.ID, RedirectURIs: movedCallback, ExpectedVersion: 1, ProposedBy: h.caller}, ErrInvalid},
		"a resource": {h.proposal(resource, h.caller, movedCallback), ErrInvalid},
		"unknown":    {Proposal{RegistrationID: h.caller, RedirectURIs: movedCallback, ExpectedVersion: 1, ProposedBy: h.caller, Reason: "r"}, ErrNotFound},
	} {
		if _, _, err := h.service.ProposeChange(ctx, c.proposal); !errors.Is(err, c.want) {
			t.Errorf("%s answered %v, want %v", name, err, c.want)
		}
	}

	suspended, err := h.service.Suspend(ctx, h.change(registration.ID, "contain it"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.service.ProposeChange(ctx, h.proposal(suspended, h.caller, movedCallback)); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("a change to a suspended registration answered %v, want ErrInvalidTransition", err)
	}
}

func TestAProductionChangeWaitsForAnotherProvider(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	registration := h.publicClient("change-approved")
	_, client := h.state(registration.ID)
	proposer, approver := h.caller, h.person("human")

	change, created, err := h.service.ProposeChange(ctx, h.proposal(registration, proposer, movedCallback))
	if err != nil || !created || change.State != ChangeProposed || !change.ApprovalRequired {
		t.Fatalf("propose: %+v, %v, %v", change, created, err)
	}
	if got, _ := h.service.Get(ctx, registration.ID); !slices.Equal(got.RedirectURIs, registration.RedirectURIs) {
		t.Errorf("a waiting change moved desired state to %v", got.RedirectURIs)
	}

	// The same proposal retried is the same change; another is refused while it waits.
	again, created, err := h.service.ProposeChange(ctx, h.proposal(registration, proposer, movedCallback))
	if err != nil || created || again.ID != change.ID {
		t.Errorf("a retried proposal answered %+v, %v, %v", again.ID, created, err)
	}
	if _, _, err := h.service.ProposeChange(ctx, h.proposal(registration, proposer, []string{"https://x.example.com/cb"})); !errors.Is(err, ErrChangeOpen) {
		t.Errorf("a second open proposal answered %v, want ErrChangeOpen", err)
	}

	// The queue lists it, with its client_key.
	queue, err := h.service.OpenChanges(ctx)
	if err != nil || !slices.ContainsFunc(queue, func(c Change) bool { return c.ID == change.ID && c.ClientKey == "change-approved" }) {
		t.Errorf("the queue is %+v, %v", queue, err)
	}

	// Its proposer approves nothing, and neither does an owner.
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, proposer), true); !errors.Is(err, ErrSelfApproval) {
		t.Errorf("the proposer's approval answered %v, want ErrSelfApproval", err)
	}
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, approver), false); !errors.Is(err, ErrNotProvider) {
		t.Errorf("an owner's approval answered %v, want ErrNotProvider", err)
	}

	applied, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, approver), true)
	if err != nil || applied.State != ChangeApplied || applied.DecidedBy == nil || *applied.DecidedBy != approver {
		t.Fatalf("approve: %+v, %v", applied, err)
	}
	if got, _ := h.service.Get(ctx, registration.ID); !slices.Equal(got.RedirectURIs, movedCallback) {
		t.Errorf("an approved change left desired state at %v", got.RedirectURIs)
	}
	if live := h.live(keycloak.ClientUUID(client)); !slices.Equal(live.RedirectURIs, movedCallback) {
		t.Errorf("an approved change left the kernel client at %v", live.RedirectURIs)
	}
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionReject, approver), true); !errors.Is(err, ErrChangeDecided) {
		t.Errorf("deciding an applied change answered %v, want ErrChangeDecided", err)
	}
}

func TestTheDatabaseRefusesASelfApprovedProductionChange(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	registration := h.publicClient("change-separated")
	change, _, err := h.service.ProposeChange(ctx, h.proposal(registration, h.caller, movedCallback))
	if err != nil {
		t.Fatal(err)
	}
	// Past the service, straight at the table: the check holds AC-5 on its own.
	err = h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, decideChangeStatement, change.ID.String(), ChangeApplied, h.caller.String(), "mine", h.service.now())
		return err
	})
	if err == nil {
		t.Fatal("the database recorded a production change applied by its proposer")
	}
}

func TestAProposalWhoseRegistrationMovedIsSuperseded(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	registration := h.publicClient("change-stale")
	change, _, err := h.service.ProposeChange(ctx, h.proposal(registration, h.caller, movedCallback))
	if err != nil {
		t.Fatal(err)
	}
	// A suspension and a restore move the version; the proposal was made against the one before.
	if _, err := h.service.Suspend(ctx, h.change(registration.ID, "contain it")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Restore(ctx, h.change(registration.ID, "contained")); err != nil {
		t.Fatal(err)
	}
	approver := h.person("human")
	superseded, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, approver), true)
	if !errors.Is(err, ErrSuperseded) || superseded.State != ChangeSuperseded {
		t.Fatalf("approving a stale proposal answered %+v, %v", superseded, err)
	}
	if got, _ := h.service.Get(ctx, registration.ID); !slices.Equal(got.RedirectURIs, registration.RedirectURIs) {
		t.Errorf("a superseded change moved desired state to %v", got.RedirectURIs)
	}
}

func TestAKernelFailureLeavesTheProposalOpen(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	registration := h.publicClient("change-kernel")
	change, _, err := h.service.ProposeChange(ctx, h.proposal(registration, h.caller, movedCallback))
	if err != nil {
		t.Fatal(err)
	}
	h.kernel.FailPatch = errors.New("kernel unavailable")
	approver := h.person("human")
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, approver), true); err == nil {
		t.Fatal("an approval the kernel did not confirm succeeded")
	}
	got, _ := h.service.Get(ctx, registration.ID)
	if !slices.Equal(got.RedirectURIs, registration.RedirectURIs) || got.Version != registration.Version {
		t.Errorf("a failed approval left desired state at %v, version %d", got.RedirectURIs, got.Version)
	}
	changes, _ := h.service.Changes(ctx, registration.ID)
	if len(changes) != 1 || changes[0].State != ChangeProposed {
		t.Errorf("a failed approval left the change %+v", changes)
	}

	// Retried once the kernel answers, it applies.
	h.kernel.FailPatch = nil
	if applied, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, approver), true); err != nil || applied.State != ChangeApplied {
		t.Errorf("the retried approval answered %+v, %v", applied, err)
	}
}

func TestOnlyTheProposerWithdrawsAndAProviderRejects(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	registration := h.publicClient("change-withdrawn")
	someone := h.person("human")

	change, _, err := h.service.ProposeChange(ctx, h.proposal(registration, h.caller, movedCallback))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionWithdraw, someone), true); !errors.Is(err, ErrNotProposer) {
		t.Errorf("a withdrawal by someone else answered %v, want ErrNotProposer", err)
	}
	withdrawn, err := h.service.DecideChange(ctx, h.decision(change, DecisionWithdraw, h.caller), false)
	if err != nil || withdrawn.State != ChangeWithdrawn {
		t.Fatalf("withdraw: %+v, %v", withdrawn, err)
	}

	// With the first decided, another may be proposed, and a provider rejects it.
	next, _, err := h.service.ProposeChange(ctx, h.proposal(registration, h.caller, []string{"https://other.example.com/cb"}))
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := h.service.DecideChange(ctx, h.decision(next, DecisionReject, someone), true)
	if err != nil || rejected.State != ChangeRejected || rejected.DecisionReason != "reviewed the new host" {
		t.Fatalf("reject: %+v, %v", rejected, err)
	}
	changes, err := h.service.Changes(ctx, registration.ID)
	if err != nil || len(changes) != 2 || changes[0].ID != next.ID {
		t.Errorf("the changes, newest first, are %+v, %v", changes, err)
	}
	if _, err := h.service.DecideChange(ctx, Decision{RegistrationID: registration.ID, ChangeID: someone, Decision: DecisionReject,
		DecidedBy: someone, Reason: "r"}, true); !errors.Is(err, ErrChangeNotFound) {
		t.Errorf("deciding an unknown change answered %v, want ErrChangeNotFound", err)
	}
	if _, err := h.service.DecideChange(ctx, Decision{RegistrationID: registration.ID, ChangeID: next.ID, Decision: "merge",
		DecidedBy: someone, Reason: "r"}, true); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unknown decision answered %v, want ErrInvalid", err)
	}
}
