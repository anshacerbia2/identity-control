package httpapi_test

import (
	"errors"
	"fmt"
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
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations, Workloads: stubWorkloads(t), Database: &stubProber{}})
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
	stub := &stubProvisioner{dangling: []provisioning.DanglingFinding{{PrincipalID: mustUUID(t)}},
		unmapped: []provisioning.UserFinding{{FindingID: mustUUID(t), Class: provisioning.FindingUnmapped, Username: "console.made"}}}
	handler := principalRoutes(t, stub)

	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/principals:unmapped", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"username":"console.made"`) ||
		!strings.Contains(w.Body.String(), `"finding_class":"unmapped"`) {
		t.Errorf("unmapped answered %d: %s", w.Code, w.Body)
	}

	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/principals:dangling", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), stub.dangling[0].PrincipalID.String()) {
		t.Errorf("dangling answered %d: %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/principals:reconcile", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"dangling":1`) ||
		!strings.Contains(w.Body.String(), `"unmapped":1`) {
		t.Errorf("reconcile answered %d: %s", w.Code, w.Body)
	}

	failing := principalRoutes(t, &stubProvisioner{err: errors.New("kernel down")})
	for path, want := range map[string]int{"/v1/principals:dangling": http.StatusInternalServerError,
		"/v1/principals:unmapped": http.StatusInternalServerError} {
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
		httptest.NewRequest(http.MethodGet, "/v1/principals:unmapped", nil),
		httptest.NewRequest(http.MethodPost, "/v1/principals:reconcile", nil),
	} {
		if w := serve(handler, r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a caller answered %d", r.Method, r.URL.Path, w.Code)
		}
	}
}

// A release names who, why and which user the triage kept, and answers with the Principal suspended
// (TDD-identity-control-001 1.18.0 §Leaving Quarantine).
func TestAReleaseIsRecordedUnderTheCallerWithItsReasonAndUser(t *testing.T) {
	stub := &stubProvisioner{}
	target := mustUUID(t)
	r, operator := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/principals/"+target.String()+":release",
		strings.NewReader(`{"username":"ana.santos"}`)))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "the console copy was deleted; ticket 41")
	w := serve(principalRoutes(t, stub), r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"suspended"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if stub.released == nil || stub.released.PrincipalID != target || stub.released.ReleasedBy != operator ||
		stub.released.Reason != "the console copy was deleted; ticket 41" || stub.released.Username != "ana.santos" {
		t.Errorf("released %+v", stub.released)
	}
}

func TestAReleaseRefusesWhatItCannotDo(t *testing.T) {
	target := mustUUID(t).String()
	path := "/v1/principals/" + target + ":release"
	for name, c := range map[string]struct {
		body   string
		reason string
		err    error
		want   int
	}{
		"no reason":              {`{"username":"a"}`, "", nil, http.StatusBadRequest},
		"no username":            {`{}`, "why", nil, http.StatusBadRequest},
		"no body":                {``, "why", nil, http.StatusBadRequest},
		"two users left":         {`{"username":"a"}`, "why", fmt.Errorf("%w: 2 kernel users carry this principal_id", provisioning.ErrReleaseRefused), http.StatusConflict},
		"not quarantined":        {`{"username":"a"}`, "why", provisioning.ErrInvalidTransition, http.StatusConflict},
		"a workload":             {`{"username":"a"}`, "why", provisioning.ErrWorkloadRelease, http.StatusConflict},
		"no such Principal":      {`{"username":"a"}`, "why", provisioning.ErrNotFound, http.StatusNotFound},
		"the kernel unreachable": {`{"username":"a"}`, "why", keycloak.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, strings.NewReader(c.body)))
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(principalRoutes(t, &stubProvisioner{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

// The pending and quarantined listings are a provider's reads, and carry no kernel identifier.
func TestThePendingAndQuarantinedListings(t *testing.T) {
	stub := &stubProvisioner{
		pending:     []provisioning.PendingMapping{{PrincipalID: mustUUID(t), Username: "late.create", Overdue: true}},
		quarantined: []provisioning.QuarantinedMapping{{PrincipalID: mustUUID(t), Username: "twice", QuarantineReason: "2 kernel users carry this principal_id"}},
	}
	handler := principalRoutes(t, stub)
	for path, want := range map[string]string{
		"/v1/principals:pending":     `"overdue":true`,
		"/v1/principals:quarantined": `"quarantine_reason":"2 kernel users carry this principal_id"`,
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
		w := serve(handler, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) || strings.Contains(w.Body.String(), "keycloak_user_id") {
			t.Errorf("%s answered %d: %s", path, w.Code, w.Body)
		}
		if w := serve(handler, httptest.NewRequest(http.MethodGet, path, nil)); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without a caller answered %d", path, w.Code)
		}
		failing, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
		if w := serve(principalRoutes(t, &stubProvisioner{err: errors.New("database down")}), failing); w.Code != http.StatusInternalServerError {
			t.Errorf("%s failing answered %d", path, w.Code)
		}
	}
}
