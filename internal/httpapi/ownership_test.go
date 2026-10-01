package httpapi_test

// The owner routes (ADR-IAM-003, TDD-identity-control-003 §Registration Ownership): an owner reaches
// a registration it owns and nothing else, and every other route refuses it before reading anything.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

func TestAnOwnerReachesOnlyTheRegistrationsItOwns(t *testing.T) {
	owner, owned, other := mustUUID(t), mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{owners: map[id.UUID]id.UUID{owned: owner}}
	handler := registrarHandler(t, registrar)

	for _, path := range []string{
		"/v1/registrations/" + owned.String(),
		"/v1/registrations/" + owned.String() + "/keys",
		"/v1/registrations/" + owned.String() + "/owners",
	} {
		if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, path, nil), owner)); w.Code != http.StatusOK {
			t.Errorf("an owner reading %s answered %d, want 200: %s", path, w.Code, w.Body)
		}
	}
	// Another registration is not found, so an owner cannot learn which exist.
	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, "/v1/registrations/"+other.String(), nil), owner)); w.Code != http.StatusNotFound {
		t.Errorf("an owner reading a registration it does not own answered %d, want 404", w.Code)
	}

	// An owner suspends and restores its own client; retirement is a provider's.
	for action, want := range map[string]int{"suspend": http.StatusOK, "restore": http.StatusOK, "retire": http.StatusForbidden} {
		r := asOwner(httptest.NewRequest(http.MethodPost, "/v1/registrations/"+owned.String()+":"+action, nil), owner)
		r.Header.Set(httpapi.AdministrativeReasonHeader, "the key leaked")
		if w := serve(handler, r); w.Code != want {
			t.Errorf("an owner's :%s answered %d, want %d: %s", action, w.Code, want, w.Body)
		}
	}

	// GET /v1/registrations:mine lists what the caller owns.
	w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, "/v1/registrations:mine", nil), owner))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), owned.String()) || strings.Contains(w.Body.String(), other.String()) {
		t.Errorf("mine answered %d: %s", w.Code, w.Body)
	}
}

func TestEveryProviderRouteRefusesAnOwner(t *testing.T) {
	owner, owned := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{owners: map[id.UUID]id.UUID{owned: owner}}
	handler := registrarHandler(t, registrar)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/v1/registrations"},
		{http.MethodPost, "/v1/registrations"},
		{http.MethodPost, "/v1/registrations:adopt"},
		{http.MethodPost, "/v1/registrations:reconcile"},
		{http.MethodGet, "/v1/registrations:drift"},
		{http.MethodGet, "/v1/registrations:expiring-keys"},
		{http.MethodPost, "/v1/registrations/" + owned.String() + "/owners"},
		{http.MethodPost, "/v1/registrations/" + owned.String() + "/owners/" + owner.String() + ":revoke"},
		{http.MethodPost, "/v1/registrations/" + owned.String() + "/drift-exceptions"},
		{http.MethodPost, "/v1/principals"},
		{http.MethodGet, "/v1/principals:dangling"},
		{http.MethodPost, "/v1/workloads"},
		{http.MethodGet, "/v1/workloads/" + owner.String()},
	} {
		r := asOwner(httptest.NewRequest(c.method, c.path, strings.NewReader(`{}`)), owner)
		r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		if w := serve(handler, r); w.Code != http.StatusForbidden {
			t.Errorf("an owner's %s %s answered %d, want 403", c.method, c.path, w.Code)
		}
	}
	if registrar.granted != nil {
		t.Error("an owner's request reached the ownership service")
	}
}

// Every route in routes.go is wrapped, so a route added later is a provider's unless someone decides
// it is an owner's: an unwrapped HandleFunc fails this test.
func TestEveryAPIRouteIsWrapped(t *testing.T) {
	source, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`api\.HandleFunc\("([^"]+)",\s*(.*)\)`)
	matches := line.FindAllStringSubmatch(string(source), -1)
	if len(matches) < 20 {
		t.Fatalf("found %d routes; the pattern no longer reads routes.go", len(matches))
	}
	for _, m := range matches {
		pattern, handler := m[1], strings.TrimSpace(m[2])
		if pattern == "GET /v1/registrations:mine" {
			continue // the caller's own ownerships, for any caller
		}
		if !strings.HasPrefix(handler, "p(") && !strings.HasPrefix(handler, "owned(") {
			t.Errorf("%s is served by %s, neither providerOnly nor owned", pattern, handler)
		}
	}
}

func TestAProviderGrantsOwnershipWithAReason(t *testing.T) {
	registrationID, owner := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{}
	handler := registrarHandler(t, registrar)
	path := "/v1/registrations/" + registrationID.String() + "/owners"

	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"principal_id":"`+owner.String()+`"}`)))
	if w := serve(handler, r); w.Code != http.StatusBadRequest || registrar.granted != nil {
		t.Errorf("a grant without a reason answered %d", w.Code)
	}
	r, caller := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"principal_id":"`+owner.String()+`"}`)))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "the orders team owns this BFF")
	if w := serve(handler, r); w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := registrar.granted; got == nil || got.RegistrationID != registrationID || got.Principal != owner ||
		got.ChangedBy != caller || got.Reason != "the orders team owns this BFF" {
		t.Errorf("granted %+v", got)
	}
}

func TestAProviderRevokesOwnershipWithAReason(t *testing.T) {
	registrationID, owner := mustUUID(t), mustUUID(t)
	base := "/v1/registrations/" + registrationID.String() + "/owners/"
	for name, c := range map[string]struct {
		path, reason string
		want         int
	}{
		"no reason":          {base + owner.String() + ":revoke", "", http.StatusBadRequest},
		"an unknown action":  {base + owner.String() + ":delete", "r", http.StatusNotFound},
		"a malformed owner":  {base + "nope:revoke", "r", http.StatusBadRequest},
		"a malformed client": {"/v1/registrations/nope/owners/" + owner.String() + ":revoke", "r", http.StatusBadRequest},
	} {
		registrar := &stubRegistrar{}
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, c.path, nil))
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(registrarHandler(t, registrar), r); w.Code != c.want || registrar.granted != nil {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}

	registrar := &stubRegistrar{}
	r, caller := asPrincipal(t, httptest.NewRequest(http.MethodPost, base+owner.String()+":revoke", nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "moved team")
	if w := serve(registrarHandler(t, registrar), r); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := registrar.granted; got == nil || got.Principal != owner || got.ChangedBy != caller || got.Reason != "moved team" {
		t.Errorf("revoked %+v", got)
	}
}

func TestOwnershipRefusalsAreMappedToTheirStatus(t *testing.T) {
	registrationID, owner := mustUUID(t), mustUUID(t)
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"an ineligible owner":   {registration.ErrOwnerNotEligible, http.StatusBadRequest},
		"an incomplete request": {registration.ErrInvalid, http.StatusBadRequest},
		"already an owner":      {registration.ErrAlreadyOwner, http.StatusConflict},
		"too few owners":        {registration.ErrTooFewOwners, http.StatusConflict},
		"a retired client":      {registration.ErrInvalidTransition, http.StatusConflict},
		"not an owner":          {registration.ErrOwnerNotFound, http.StatusNotFound},
		"an unknown client":     {registration.ErrNotFound, http.StatusNotFound},
		"a database failure":    {errors.New("connection refused"), http.StatusInternalServerError},
	} {
		handler := registrarHandler(t, &stubRegistrar{err: c.err})
		grant, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations/"+registrationID.String()+"/owners",
			strings.NewReader(`{"principal_id":"`+owner.String()+`"}`)))
		grant.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		if w := serve(handler, grant); w.Code != c.want {
			t.Errorf("a grant meeting %s answered %d, want %d", name, w.Code, c.want)
		}
		list, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations/"+registrationID.String()+"/owners", nil))
		if w := serve(handler, list); w.Code != c.want {
			t.Errorf("a listing meeting %s answered %d, want %d", name, w.Code, c.want)
		}
	}
	if strings.Contains(serve(registrarHandler(t, &stubRegistrar{err: errors.New("connection refused")}),
		func() *http.Request {
			r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations/"+registrationID.String()+"/owners", nil))
			return r
		}()).Body.String(), "connection refused") {
		t.Error("a database error reached the response")
	}
}

func TestOwnerRoutesRefuseWhatTheyCannotRead(t *testing.T) {
	owner := mustUUID(t)
	handler := registrarHandler(t, &stubRegistrar{})
	if w := serve(handler, httptest.NewRequest(http.MethodGet, "/v1/registrations:mine", nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("mine without a caller answered %d, want 401", w.Code)
	}
	if w := serve(handler, httptest.NewRequest(http.MethodGet, "/v1/registrations/"+owner.String()+"/keys", nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("an owner route without a caller answered %d, want 401", w.Code)
	}
	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, "/v1/registrations/nope/keys", nil), owner)); w.Code != http.StatusBadRequest {
		t.Errorf("an owner naming a malformed registration answered %d, want 400", w.Code)
	}
	if w := serve(handler, httptest.NewRequest(http.MethodGet, "/v1/registrations", nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("a provider route without a caller answered %d, want 401", w.Code)
	}
}

func TestOwnershipRoutesRefuseMalformedRequests(t *testing.T) {
	registrationID := mustUUID(t)
	handler := registrarHandler(t, &stubRegistrar{})
	for name, c := range map[string]struct{ method, path, body string }{
		"a body that is not an ownership": {http.MethodPost, "/v1/registrations/" + registrationID.String() + "/owners", `{"owner":1}`},
		"a malformed principal":           {http.MethodPost, "/v1/registrations/" + registrationID.String() + "/owners", `{"principal_id":"nope"}`},
		"a malformed registration":        {http.MethodPost, "/v1/registrations/nope/owners", `{"principal_id":"` + mustUUID(t).String() + `"}`},
		"a listing of a malformed client": {http.MethodGet, "/v1/registrations/nope/owners", ""},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(c.method, c.path, strings.NewReader(c.body)))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		if w := serve(handler, r); w.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", name, w.Code)
		}
	}
}

// A failed ownership read admits nobody and discloses nothing.
func TestAFailedOwnershipReadAdmitsNobody(t *testing.T) {
	owner, registrationID := mustUUID(t), mustUUID(t)
	handler := registrarHandler(t, &stubRegistrar{readErr: errors.New("connection refused"),
		owners: map[id.UUID]id.UUID{registrationID: owner}})
	for _, path := range []string{"/v1/registrations/" + registrationID.String() + "/keys", "/v1/registrations:mine"} {
		w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, path, nil), owner))
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "connection refused") {
			t.Errorf("%s answered %d: %s", path, w.Code, w.Body)
		}
	}
}
