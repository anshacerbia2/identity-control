package registration

// Registration requests against the real database (ADR-IAM-003 §5.3, TDD-identity-control-003
// §Registration Requests).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

func (h *harness) proposalBy(developer id.UUID, req Request, owners ...id.UUID) RegistrationProposal {
	req.RegisteredBy, req.Developer = developer, true
	return RegistrationProposal{Request: req, Owners: owners, Reason: "orders goes live"}
}

func (h *harness) requestDecision(request RegistrationRequest, decision string, by id.UUID) RequestDecision {
	return RequestDecision{RequestID: request.ID, Decision: decision, DecidedBy: by, Reason: "reviewed the redirect URIs"}
}

func TestARequestIsOnlyForProduction(t *testing.T) {
	h := newHarness(t)
	developer, colleague := h.developer(), h.person("human")
	_, _, err := h.service.ProposeRegistration(context.Background(),
		h.proposalBy(developer, h.request("req-dev", ProfilePublic), developer, colleague))
	if !errors.Is(err, ErrRequestNotNeeded) {
		t.Errorf("a request outside production answered %v, want ErrRequestNotNeeded", err)
	}
	// And in production a developer no longer registers directly.
	h.service.cfg.Production = true
	if _, err := h.service.Register(context.Background(), h.asDeveloper(developer, "req-direct", ProfilePublic)); !errors.Is(err, ErrDeveloperScope) ||
		!strings.Contains(err.Error(), "registration-requests") {
		t.Errorf("a developer's direct production registration answered %v", err)
	}
}

func TestARequestIsRefusedWhenItBreaksARule(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	developer, colleague, workload := h.developer(), h.person("human"), h.person("workload")
	h.publicClient("req-taken")

	privileged := h.request("req-admin", ProfilePublic)
	privileged.AudienceClass = "privileged"
	for name, c := range map[string]struct {
		proposal RegistrationProposal
		want     error
	}{
		"one owner":        {h.proposalBy(developer, h.request("req-one", ProfilePublic), developer, developer), ErrInvalid},
		"workload owner":   {h.proposalBy(developer, h.request("req-wl", ProfilePublic), developer, workload), ErrOwnerNotEligible},
		"no reason":        {RegistrationProposal{Request: h.request("req-r", ProfilePublic), Owners: []id.UUID{developer, colleague}}, ErrInvalid},
		"invalid document": {h.proposalBy(developer, h.request("Req Bad", ProfilePublic), developer, colleague), ErrInvalid},
		"privileged class": {h.proposalBy(developer, privileged, developer, colleague), ErrDeveloperScope},
		"key taken":        {h.proposalBy(developer, h.request("req-taken", ProfilePublic), developer, colleague), ErrKeyTaken},
	} {
		if _, _, err := h.service.ProposeRegistration(ctx, c.proposal); !errors.Is(err, c.want) {
			t.Errorf("%s answered %v, want %v", name, err, c.want)
		}
	}
	if queue, _ := h.service.RequestQueue(ctx); len(queue) != 0 {
		t.Errorf("refused requests left %d in the queue", len(queue))
	}
}

func TestAnotherProviderApprovesARequestAndItsOwnersAreGranted(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	developer, colleague, approver := h.developer(), h.person("human"), h.person("human")
	key := testKey(t)
	req := h.confidential("req-orders", key)

	request, created, err := h.service.ProposeRegistration(ctx, h.proposalBy(developer, req, developer, colleague))
	if err != nil || !created || request.State != RequestProposed || len(request.Owners) != 2 {
		t.Fatalf("propose: %+v, %v, %v", request, created, err)
	}
	// The stored key is its public members only.
	var stored struct {
		PublicKey map[string]string `json:"public_key"`
	}
	if err := json.Unmarshal(request.Request, &stored); err != nil || stored.PublicKey["kty"] != "RSA" || stored.PublicKey["d"] != "" {
		t.Errorf("the stored key is %v, %v", stored.PublicKey, err)
	}
	again, created, err := h.service.ProposeRegistration(ctx, h.proposalBy(developer, req, developer, colleague))
	if err != nil || created || again.ID != request.ID {
		t.Errorf("a retried request answered %v, %v, %v", again.ID, created, err)
	}
	if _, _, err := h.service.ProposeRegistration(ctx, h.proposalBy(colleague, h.confidential("req-orders", testKey(t)), developer, colleague)); !errors.Is(err, ErrRequestOpen) {
		t.Errorf("a second open request answered %v, want ErrRequestOpen", err)
	}
	if mine, _ := h.service.MyRequests(ctx, developer); len(mine) != 1 || mine[0].ID != request.ID {
		t.Errorf("the developer's own requests are %+v", mine)
	}

	if _, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionApprove, developer), true); !errors.Is(err, ErrSelfApproval) {
		t.Errorf("the proposer's approval answered %v, want ErrSelfApproval", err)
	}
	if _, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionApprove, colleague), false); !errors.Is(err, ErrNotProvider) {
		t.Errorf("an owner's approval answered %v, want ErrNotProvider", err)
	}
	approved, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionApprove, approver), true)
	if err != nil || approved.State != RequestApproved || approved.RegistrationID == nil {
		t.Fatalf("approve: %+v, %v", approved, err)
	}
	registration, err := h.service.Get(ctx, *approved.RegistrationID)
	if err != nil || registration.State != StateActive || registration.RegisteredBy != developer {
		t.Fatalf("the approved registration is %+v, %v", registration, err)
	}
	owners, _ := h.service.Owners(ctx, registration.ID)
	if len(owners) != 2 || owners[0].GrantedBy != approver {
		t.Errorf("the approved registration's owners are %+v", owners)
	}
	// Retried by the same provider, the approval is the same; anyone else is told it is decided.
	if retried, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionApprove, approver), true); err != nil || retried.ID != request.ID {
		t.Errorf("the retried approval answered %v, %v", retried.ID, err)
	}
	other := h.person("human")
	if _, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionReject, other), true); !errors.Is(err, ErrChangeDecided) {
		t.Errorf("rejecting an approved request answered %v, want ErrChangeDecided", err)
	}
}

func TestTheDatabaseRefusesASelfApprovedRequest(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	developer, colleague := h.developer(), h.person("human")
	request, _, err := h.service.ProposeRegistration(ctx, h.proposalBy(developer, h.request("req-self", ProfilePublic), developer, colleague))
	if err != nil {
		t.Fatal(err)
	}
	registration := h.publicClient("req-self-elsewhere")
	err = h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return decideRequest(ctx, tx, request.ID, RequestApproved, developer, "mine", h.service.now(), &registration.ID)
	})
	if err == nil {
		t.Fatal("the database recorded a request approved by its proposer")
	}
}

func TestAnOwnerWhoLeftRefusesTheApprovalAndNothingIsCreated(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	developer, colleague, approver := h.developer(), h.person("human"), h.person("human")
	request, _, err := h.service.ProposeRegistration(ctx, h.proposalBy(developer, h.request("req-left", ProfilePublic), developer, colleague))
	if err != nil {
		t.Fatal(err)
	}
	h.setMapping(colleague, "retired")
	if _, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionApprove, approver), true); !errors.Is(err, ErrOwnerNotEligible) {
		t.Errorf("an approval naming an owner who left answered %v, want ErrOwnerNotEligible", err)
	}
	if n := h.registrationsNamed("req-left"); n != 0 {
		t.Errorf("a refused approval left %d registrations", n)
	}
	if queue, _ := h.service.RequestQueue(ctx); len(queue) != 1 || queue[0].State != RequestProposed {
		t.Errorf("a refused approval left the queue %+v", queue)
	}
}

func TestOnlyTheProposerWithdrawsARequestAndAProviderRejectsOne(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	developer, colleague, provider := h.developer(), h.person("human"), h.person("human")
	request, _, err := h.service.ProposeRegistration(ctx, h.proposalBy(developer, h.request("req-gone", ProfilePublic), developer, colleague))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionWithdraw, colleague), false); !errors.Is(err, ErrNotProposer) {
		t.Errorf("a withdrawal by someone else answered %v, want ErrNotProposer", err)
	}
	withdrawn, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionWithdraw, developer), false)
	if err != nil || withdrawn.State != RequestWithdrawn || withdrawn.RegistrationID != nil {
		t.Fatalf("withdraw: %+v, %v", withdrawn, err)
	}

	next, _, err := h.service.ProposeRegistration(ctx, h.proposalBy(developer, h.request("req-gone", ProfilePublic), developer, colleague))
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := h.service.DecideRegistration(ctx, h.requestDecision(next, DecisionReject, provider), true)
	if err != nil || rejected.State != RequestRejected || rejected.DecisionReason != "reviewed the redirect URIs" {
		t.Fatalf("reject: %+v, %v", rejected, err)
	}
	if n := h.registrationsNamed("req-gone"); n != 0 {
		t.Errorf("a rejected request left %d registrations", n)
	}
	if _, err := h.service.DecideRegistration(ctx, RequestDecision{RequestID: provider, Decision: DecisionReject, DecidedBy: provider,
		Reason: "r"}, true); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("deciding an unknown request answered %v, want ErrRequestNotFound", err)
	}
	if _, err := h.service.DecideRegistration(ctx, RequestDecision{RequestID: next.ID, Decision: "merge", DecidedBy: provider,
		Reason: "r"}, true); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unknown decision answered %v, want ErrInvalid", err)
	}
}
