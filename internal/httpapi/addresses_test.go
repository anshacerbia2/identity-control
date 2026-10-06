package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/securitynotify"
)

type stubAddresses struct {
	err       error
	principal id.UUID
	address   string
	code      string
	verb      string
}

func (s *stubAddresses) List(_ context.Context, principal id.UUID) ([]securitynotify.Address, error) {
	s.principal = principal
	return []securitynotify.Address{{Channel: "email", Address: "me@example.com", Origin: "creation", State: "active"}}, s.err
}

func (s *stubAddresses) Add(_ context.Context, principal id.UUID, address string) (securitynotify.Address, error) {
	s.principal, s.address, s.verb = principal, address, "add"
	return securitynotify.Address{Address: address, State: "pending"}, s.err
}

func (s *stubAddresses) Verify(_ context.Context, principal, _ id.UUID, code string) error {
	s.principal, s.code, s.verb = principal, code, "verify"
	return s.err
}

func (s *stubAddresses) Remove(_ context.Context, principal, _ id.UUID) error {
	s.principal, s.verb = principal, "remove"
	return s.err
}

func addressHandler(t *testing.T, stub *stubAddresses) http.Handler {
	t.Helper()
	me, err := httpapi.NewMe(&stubSelf{}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	me.UseAddresses(stub)
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Me: me, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// A person's own addresses (TDD-identity-control-008 1.2.0): adding and removing need a recent aal2,
// proving needs only the code, and each acts on the caller.
func TestAPersonManagesTheirOwnAddresses(t *testing.T) {
	stub := &stubAddresses{}
	handler := addressHandler(t, stub)
	addressID := mustUUID(t).String()

	r, person := asPerson(t, httptest.NewRequest(http.MethodGet, "/v1/me/notification-addresses", nil), time.Minute)
	if w := serve(handler, r); w.Code != http.StatusOK || stub.principal != person || !strings.Contains(w.Body.String(), "me@example.com") {
		t.Errorf("list: %d %s", w.Code, w.Body)
	}

	r, person = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/notification-addresses",
		strings.NewReader(`{"address":"new@example.com"}`)), time.Minute)
	if w := serve(handler, r); w.Code != http.StatusCreated || stub.address != "new@example.com" || stub.principal != person {
		t.Errorf("add: %d %s", w.Code, w.Body)
	}

	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/notification-addresses",
		strings.NewReader(`{"address":"new@example.com"}`)), time.Hour)
	if w := serve(handler, r); w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "acr_values") {
		t.Errorf("an add an hour after sign-in answered %d; want a step-up challenge", w.Code)
	}

	// Proving needs no step-up: the code is the proof, and the person may read it on another device.
	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/notification-addresses/"+addressID+":verify",
		strings.NewReader(`{"code":"12345678"}`)), time.Hour)
	if w := serve(handler, r); w.Code != http.StatusNoContent || stub.verb != "verify" || stub.code != "12345678" {
		t.Errorf("verify: %d %s", w.Code, w.Body)
	}

	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/notification-addresses/"+addressID+":remove", nil), time.Hour)
	if w := serve(handler, r); w.Code != http.StatusUnauthorized {
		t.Errorf("a removal an hour after sign-in answered %d; want a step-up challenge", w.Code)
	}
	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/notification-addresses/"+addressID+":remove", nil), time.Minute)
	if w := serve(handler, r); w.Code != http.StatusNoContent || stub.verb != "remove" {
		t.Errorf("remove: %d %s", w.Code, w.Body)
	}

	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/notification-addresses/not-an-id:remove", nil), time.Minute)
	if w := serve(handler, r); w.Code != http.StatusNotFound {
		t.Errorf("a malformed address id answered %d; want 404", w.Code)
	}
}

func TestAddressRefusalsAreTold(t *testing.T) {
	for err, want := range map[error]int{
		securitynotify.ErrInvalidAddress: http.StatusBadRequest,
		securitynotify.ErrAddressHeld:    http.StatusConflict,
		securitynotify.ErrTooMany:        http.StatusConflict,
		securitynotify.ErrLastAddress:    http.StatusConflict,
		securitynotify.ErrNoSuchAddress:  http.StatusNotFound,
		securitynotify.ErrWrongCode:      http.StatusBadRequest,
	} {
		handler := addressHandler(t, &stubAddresses{err: err})
		r, _ := asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/notification-addresses",
			strings.NewReader(`{"address":"x@example.com"}`)), time.Minute)
		if w := serve(handler, r); w.Code != want {
			t.Errorf("%v answered %d; want %d", err, w.Code, want)
		}
	}
}
