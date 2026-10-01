package httpapi_test

// Application developer standing (ADR-IAM-003 §5.3, TDD-identity-control-003 §Application
// Developers): a provider grants and revokes it, and a caller holding it may create a registration,
// refused before the body is read without it.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

func registerRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/registrations", strings.NewReader(`{"client_key":"orders-web","profile":"public"}`))
	r.Header.Set("Idempotency-Key", "k-1")
	return r
}

func TestAnApplicationDeveloperRegistersOnItsStanding(t *testing.T) {
	developer, stranger := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{developers: map[id.UUID]bool{developer: true}}
	handler := registrarHandler(t, registrar)

	if w := serve(handler, asOwner(registerRequest(), stranger)); w.Code != http.StatusForbidden || registrar.req != nil {
		t.Fatalf("a caller without the standing answered %d and reached the service: %v", w.Code, registrar.req != nil)
	}
	if w := serve(handler, asOwner(registerRequest(), developer)); w.Code != http.StatusCreated {
		t.Fatalf("an application developer's registration answered %d: %s", w.Code, w.Body)
	}
	if registrar.req == nil || !registrar.req.Developer || registrar.req.RegisteredBy != developer {
		t.Errorf("the developer's registration reached the service as %+v", registrar.req)
	}

	r, _ := asPrincipal(t, registerRequest())
	if w := serve(handler, r); w.Code != http.StatusCreated || registrar.req.Developer {
		t.Errorf("a provider's registration answered %d, registered as a developer: %v", w.Code, registrar.req.Developer)
	}
}

func TestADevelopersRefusalIsForbidden(t *testing.T) {
	developer := mustUUID(t)
	for _, err := range []error{
		fmt.Errorf("%w: rule", registration.ErrDeveloperScope),
		registration.ErrNotDeveloper,
	} {
		registrar := &stubRegistrar{developers: map[id.UUID]bool{developer: true}, err: err}
		if w := serve(registrarHandler(t, registrar), asOwner(registerRequest(), developer)); w.Code != http.StatusForbidden {
			t.Errorf("a registration refused with %v answered %d, want 403", err, w.Code)
		}
	}
	failing := &stubRegistrar{readErr: errors.New("database down")}
	if w := serve(registrarHandler(t, failing), asOwner(registerRequest(), developer)); w.Code != http.StatusInternalServerError {
		t.Errorf("a failed standing read answered %d, want 500", w.Code)
	}
}

func TestAProviderGrantsAndRevokesTheStanding(t *testing.T) {
	owner, developer := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{}
	handler := registrarHandler(t, registrar)
	grant := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/application-developers",
			strings.NewReader(`{"principal_id":"`+developer.String()+`"}`))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "builds the orders service")
		return r
	}
	revoke := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/application-developers/"+developer.String()+":revoke", nil)
		r.Header.Set(httpapi.AdministrativeReasonHeader, "moved teams")
		return r
	}

	for name, r := range map[string]*http.Request{
		"list":   httptest.NewRequest(http.MethodGet, "/v1/application-developers", nil),
		"grant":  grant(),
		"revoke": revoke(),
	} {
		if w := serve(handler, asOwner(r, owner)); w.Code != http.StatusForbidden {
			t.Errorf("an owner's %s answered %d, want 403", name, w.Code)
		}
	}

	r, provider := asPrincipal(t, grant())
	if w := serve(handler, r); w.Code != http.StatusCreated {
		t.Fatalf("a provider's grant answered %d: %s", w.Code, w.Body)
	}
	if got := registrar.devChange; got == nil || got.Principal != developer || got.ChangedBy != provider || got.Reason != "builds the orders service" {
		t.Errorf("the grant reached the service as %+v", got)
	}
	r, _ = asPrincipal(t, revoke())
	if w := serve(handler, r); w.Code != http.StatusOK || !registrar.devRevoked {
		t.Errorf("a provider's revocation answered %d, revoked %v", w.Code, registrar.devRevoked)
	}
	l, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/application-developers", nil))
	if w := serve(handler, l); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"developers"`) {
		t.Errorf("a provider's list answered %d: %s", w.Code, w.Body)
	}
}

func TestStandingRoutesRefuseMalformedRequestsAndMapRefusals(t *testing.T) {
	developer := mustUUID(t)
	handler := registrarHandler(t, &stubRegistrar{})
	for name, c := range map[string]struct {
		method, path, body string
		reason             bool
		want               int
	}{
		"grant without a reason": {http.MethodPost, "/v1/application-developers", `{"principal_id":"` + developer.String() + `"}`, false, http.StatusBadRequest},
		"grant, not json":        {http.MethodPost, "/v1/application-developers", `nope`, true, http.StatusBadRequest},
		"grant, bad principal":   {http.MethodPost, "/v1/application-developers", `{"principal_id":"x"}`, true, http.StatusBadRequest},
		"unknown action":         {http.MethodPost, "/v1/application-developers/" + developer.String() + ":promote", "", true, http.StatusNotFound},
		"revoke, bad principal":  {http.MethodPost, "/v1/application-developers/x:revoke", "", true, http.StatusBadRequest},
		"revoke without reason":  {http.MethodPost, "/v1/application-developers/" + developer.String() + ":revoke", "", false, http.StatusBadRequest},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(c.method, c.path, strings.NewReader(c.body)))
		if c.reason {
			r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		}
		if w := serve(handler, r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}

	for err, want := range map[error]int{
		registration.ErrOwnerNotEligible:  http.StatusBadRequest,
		registration.ErrAlreadyDeveloper:  http.StatusConflict,
		registration.ErrDeveloperNotFound: http.StatusNotFound,
		errors.New("database down"):       http.StatusInternalServerError,
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/application-developers/"+developer.String()+":revoke", nil))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		if w := serve(registrarHandler(t, &stubRegistrar{err: err}), r); w.Code != want {
			t.Errorf("a revocation refused with %v answered %d, want %d", err, w.Code, want)
		}
	}
	failing := &stubRegistrar{readErr: errors.New("database down")}
	l, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/application-developers", nil))
	if w := serve(registrarHandler(t, failing), l); w.Code != http.StatusInternalServerError {
		t.Errorf("a failed list answered %d, want 500", w.Code)
	}
}
