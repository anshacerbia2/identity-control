package registration

// The back-channel logout URI of a confidential client, against the real database (ADR-IAM-009,
// TDD-identity-control-003 1.37.0).

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

const logoutURI = "https://bff.example.com/auth/back-channel-logout"

// A registration records the URI as desired state, and creates the kernel client with it, front
// channel off and the session named.
func TestARegistrationWritesItsBackChannelLogoutURI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	req := h.confidential("logout-bff", testKey(t))
	req.BackChannelLogoutURI = logoutURI
	registration, err := h.service.Register(ctx, req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if registration.BackChannelLogoutURI != logoutURI {
		t.Errorf("the registration reads %q", registration.BackChannelLogoutURI)
	}
	_, client := h.state(registration.ID)
	if live := h.live(keycloak.ClientUUID(client)); live.Logout != keycloak.DesiredLogout(logoutURI) {
		t.Errorf("the kernel client's logout is %+v", live.Logout)
	}

	// A client registered without one holds no URL, and front channel off all the same.
	plain, _ := h.registerConfidential("logout-plain", testKey(t))
	_, plainClient := h.state(plain.ID)
	if live := h.live(keycloak.ClientUUID(plainClient)); live.Logout != keycloak.DesiredLogout("") || plain.BackChannelLogoutURI != "" {
		t.Errorf("a client registered without a URI holds %+v and reads %q", live.Logout, plain.BackChannelLogoutURI)
	}
}

// In production a logout token travels over TLS only, so an http URI is refused there, and accepted
// outside it.
func TestAnHTTPBackChannelLogoutURIIsRefusedInProduction(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.service.cfg.Production = true
	req := h.confidential("logout-http-prod", testKey(t))
	req.BackChannelLogoutURI = "http://bff.internal:8090/auth/back-channel-logout"
	if _, err := h.service.Register(ctx, req); !errors.Is(err, ErrInvalid) {
		t.Errorf("an http URI in production answered %v, want ErrInvalid", err)
	}
	h.service.cfg.Production = false
	req = h.confidential("logout-http-dev", testKey(t))
	req.BackChannelLogoutURI = "http://bff.internal:8090/auth/back-channel-logout"
	if _, err := h.service.Register(ctx, req); err != nil {
		t.Errorf("an http URI outside production was refused: %v", err)
	}
}

// An adoption converges the logout class only when it is named, and records the declared URI.
func TestAnAdoptionConvergesTheLogoutConfiguration(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := testKey(t)
	client := h.bootstrapped("logout-adopted", key)
	h.kernel.ConsoleChange("", client, func(c *keycloak.Client) { c.Logout.FrontChannel = true })

	declared := h.adoption("logout-adopted", key)
	declared.BackChannelLogoutURI = logoutURI
	if _, err := h.service.Adopt(ctx, declared); !errors.Is(err, ErrNotAdoptable) {
		t.Fatalf("an adoption not naming logout answered %v, want ErrNotAdoptable", err)
	}
	declared.Converge = []string{ClassLogout}
	declared.IdempotencyKey = "logout-adopted-2"
	result, err := h.service.Adopt(ctx, declared)
	if err != nil || result.Registration == nil || result.Registration.BackChannelLogoutURI != logoutURI {
		t.Fatalf("adopt: %+v, %v", result, err)
	}
	if live := h.live(client); live.Logout != keycloak.DesiredLogout(logoutURI) {
		t.Errorf("the adopted client's logout is %+v", live.Logout)
	}
}

// logoutProposal is a back-channel logout URI change; "" removes the URI (TDD-identity-control-003 1.38.0).
func (h *harness) logoutProposal(registration Registration, uri string) Proposal {
	return Proposal{RegistrationID: registration.ID, BackChannelLogoutURI: &uri, ExpectedVersion: registration.Version,
		ProposedBy: h.caller, Reason: "the BFF's logout endpoint moves", Provider: true}
}

// Outside production a back-channel logout URI change applies at once: desired state, the version and
// the kernel client move together, and a removal leaves front-channel logout off and no URL.
func TestABackChannelLogoutURIChangeIsAppliedAtOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	registration, client := h.registerConfidential("logout-change", testKey(t))

	set, created, err := h.service.ProposeChange(ctx, h.logoutProposal(registration, logoutURI))
	if err != nil || !created || set.State != ChangeApplied || set.Kind != ChangeBackChannelLogout {
		t.Fatalf("set: %+v, %v, %v", set, created, err)
	}
	if set.PreviousBackChannelLogoutURI != nil || stringOf(set.BackChannelLogoutURI) != logoutURI ||
		set.RedirectURIs != nil || set.Audience != nil || set.LifetimeClass != nil {
		t.Errorf("the change records %+v", set)
	}
	got, _ := h.service.Get(ctx, registration.ID)
	if got.BackChannelLogoutURI != logoutURI || got.Version != registration.Version+1 {
		t.Errorf("desired state is %q at version %d", got.BackChannelLogoutURI, got.Version)
	}
	if live := h.live(client); live.Logout != keycloak.DesiredLogout(logoutURI) {
		t.Errorf("the kernel client's logout is %+v", live.Logout)
	}

	moved := "https://bff.example.com/auth/back-channel-logout-v2"
	change, _, err := h.service.ProposeChange(ctx, h.logoutProposal(got, moved))
	if err != nil || stringOf(change.PreviousBackChannelLogoutURI) != logoutURI || stringOf(change.BackChannelLogoutURI) != moved {
		t.Fatalf("move: %+v, %v", change, err)
	}
	got, _ = h.service.Get(ctx, registration.ID)
	if live := h.live(client); live.Logout != keycloak.DesiredLogout(moved) || got.BackChannelLogoutURI != moved {
		t.Errorf("a moved URI left %+v and %q", live.Logout, got.BackChannelLogoutURI)
	}

	removed, _, err := h.service.ProposeChange(ctx, h.logoutProposal(got, ""))
	if err != nil || removed.State != ChangeApplied || removed.BackChannelLogoutURI != nil ||
		stringOf(removed.PreviousBackChannelLogoutURI) != moved {
		t.Fatalf("remove: %+v, %v", removed, err)
	}
	got, _ = h.service.Get(ctx, registration.ID)
	if live := h.live(client); live.Logout != keycloak.DesiredLogout("") || got.BackChannelLogoutURI != "" {
		t.Errorf("a removed URI left %+v and %q", live.Logout, got.BackChannelLogoutURI)
	}
}

func TestABackChannelLogoutURIChangeIsRefusedWhenItBreaksARule(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	confidential, _ := h.registerConfidential("logout-rules", testKey(t))
	public := h.publicClient("logout-rules-public")

	both := h.logoutProposal(confidential, logoutURI)
	both.RedirectURIs = movedCallback
	for name, proposal := range map[string]Proposal{
		"a public client":               h.logoutProposal(public, logoutURI),
		"a relative URI":                h.logoutProposal(confidential, "/auth/back-channel-logout"),
		"a fragment":                    h.logoutProposal(confidential, logoutURI+"#x"),
		"credentials":                   h.logoutProposal(confidential, "https://user:pw@bff.example.com/logout"),
		"a wildcard":                    h.logoutProposal(confidential, "https://*.example.com/logout"),
		"another scheme":                h.logoutProposal(confidential, "ftp://bff.example.com/logout"),
		"removing a URI not registered": h.logoutProposal(confidential, ""),
		"two kinds at once":             both,
	} {
		if _, _, err := h.service.ProposeChange(ctx, proposal); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s answered %v, want ErrInvalid", name, err)
		}
	}
	if _, _, err := h.service.ProposeChange(ctx, h.logoutProposal(confidential, logoutURI)); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, _ := h.service.Get(ctx, confidential.ID)
	if _, _, err := h.service.ProposeChange(ctx, h.logoutProposal(got, logoutURI)); !errors.Is(err, ErrInvalid) {
		t.Errorf("the registered URI answered %v, want ErrInvalid", err)
	}
	stale := h.logoutProposal(got, "https://bff.example.com/other")
	stale.ExpectedVersion--
	if _, _, err := h.service.ProposeChange(ctx, stale); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("a stale version answered %v, want ErrVersionConflict", err)
	}

	h.service.cfg.Production = true
	if _, _, err := h.service.ProposeChange(ctx, h.logoutProposal(got, "http://bff.internal/logout")); !errors.Is(err, ErrInvalid) {
		t.Errorf("an http URI in production answered %v, want ErrInvalid", err)
	}
}

// In production a back-channel logout URI change waits for a provider other than its proposer, and
// the kernel is written only when it is approved.
func TestAProductionBackChannelLogoutURIChangeWaitsForAnotherProvider(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	registration, client := h.registerConfidential("logout-prod", testKey(t))

	change, created, err := h.service.ProposeChange(ctx, h.logoutProposal(registration, logoutURI))
	if err != nil || !created || change.State != ChangeProposed || !change.ApprovalRequired {
		t.Fatalf("propose: %+v, %v, %v", change, created, err)
	}
	if live := h.live(client); live.Logout != keycloak.DesiredLogout("") {
		t.Errorf("a waiting change wrote the kernel: %+v", live.Logout)
	}
	if again, created, err := h.service.ProposeChange(ctx, h.logoutProposal(registration, logoutURI)); err != nil || created || again.ID != change.ID {
		t.Errorf("a retried proposal answered %v, %v, %v", again.ID, created, err)
	}
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, h.caller), true); !errors.Is(err, ErrSelfApproval) {
		t.Errorf("the proposer's approval answered %v, want ErrSelfApproval", err)
	}

	// A kernel that does not answer leaves the proposal open; retried, it applies.
	approver := h.person("human")
	h.kernel.FailPatch = errors.New("kernel unavailable")
	if _, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, approver), true); err == nil {
		t.Fatal("an approval the kernel did not confirm succeeded")
	}
	if got, _ := h.service.Get(ctx, registration.ID); got.BackChannelLogoutURI != "" || got.Version != registration.Version {
		t.Errorf("a failed approval left %q at version %d", got.BackChannelLogoutURI, got.Version)
	}
	h.kernel.FailPatch = nil
	applied, err := h.service.DecideChange(ctx, h.decision(change, DecisionApprove, approver), true)
	if err != nil || applied.State != ChangeApplied {
		t.Fatalf("approve: %+v, %v", applied, err)
	}
	if live := h.live(client); live.Logout != keycloak.DesiredLogout(logoutURI) {
		t.Errorf("an approved change left the kernel client's logout %+v", live.Logout)
	}
}
