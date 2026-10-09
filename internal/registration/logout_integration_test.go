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
