package httpapi_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func principalRoutes(t *testing.T, stub *stubProvisioner) http.Handler {
	t.Helper()
	principals, err := httpapi.NewPrincipals(stub, realm)
	if err != nil {
		t.Fatal(err)
	}
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// A relink is an operator's decision, so it names who and why: the caller, never the body.
func TestARelinkIsRecordedUnderTheCallerWithItsReason(t *testing.T) {
	stub := &stubProvisioner{}
	target := mustUUID(t)
	r, operator := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/principals/"+target.String()+":relink", nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "user deleted by mistake")
	w := serve(principalRoutes(t, stub), r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"active"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if stub.relinked == nil || stub.relinked.PrincipalID != target || stub.relinked.RelinkedBy != operator ||
		stub.relinked.Reason != "user deleted by mistake" {
		t.Errorf("relinked %+v", stub.relinked)
	}
}

func TestARelinkRefusesWhatItCannotDo(t *testing.T) {
	target := mustUUID(t).String()
	for name, c := range map[string]struct {
		path   string
		reason string
		err    error
		auth   bool
		want   int
	}{
		"no caller":             {"/v1/principals/" + target + ":relink", "why", nil, false, http.StatusUnauthorized},
		"no reason":             {"/v1/principals/" + target + ":relink", "", nil, true, http.StatusBadRequest},
		"an unknown action":     {"/v1/principals/" + target + ":resurrect", "why", nil, true, http.StatusNotFound},
		"a malformed id":        {"/v1/principals/nope:relink", "why", nil, true, http.StatusBadRequest},
		"the user still exists": {"/v1/principals/" + target + ":relink", "why", provisioning.ErrUserStillExists, true, http.StatusConflict},
		"not active":            {"/v1/principals/" + target + ":relink", "why", provisioning.ErrInvalidTransition, true, http.StatusConflict},
		"no such Principal":     {"/v1/principals/" + target + ":relink", "why", provisioning.ErrNotFound, true, http.StatusNotFound},
		"kernel unreachable":    {"/v1/principals/" + target + ":relink", "why", keycloak.ErrUnavailable, true, http.StatusServiceUnavailable},
	} {
		r := httptest.NewRequest(http.MethodPost, c.path, nil)
		if c.auth {
			r, _ = asPrincipal(t, r)
		}
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(principalRoutes(t, &stubProvisioner{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestDanglingAndReconcileReportTheSweep(t *testing.T) {
	stub := &stubProvisioner{dangling: []provisioning.DanglingFinding{{PrincipalID: mustUUID(t)}}}
	handler := principalRoutes(t, stub)

	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/principals:dangling", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), stub.dangling[0].PrincipalID.String()) {
		t.Errorf("dangling answered %d: %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/principals:reconcile", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"dangling":1`) {
		t.Errorf("reconcile answered %d: %s", w.Code, w.Body)
	}

	failing := principalRoutes(t, &stubProvisioner{err: errors.New("kernel down")})
	for path, want := range map[string]int{"/v1/principals:dangling": http.StatusInternalServerError} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
		if w := serve(failing, r); w.Code != want {
			t.Errorf("%s answered %d, want %d", path, w.Code, want)
		}
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/principals:reconcile", nil))
	if w := serve(failing, r); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a failed reconcile answered %d", w.Code)
	}
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/principals:dangling", nil),
		httptest.NewRequest(http.MethodPost, "/v1/principals:reconcile", nil),
	} {
		if w := serve(handler, r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a caller answered %d", r.Method, r.URL.Path, w.Code)
		}
	}
}
