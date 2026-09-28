package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/reconcile"
)

type stubReconciler struct {
	status     reconcile.Status
	statusErr  error
	run        reconcile.Run
	sweepErr   error
	sweeps     int
	resolveErr error
	resolved   *reconcile.Resolution
	grantErr   error
	granted    *reconcile.Exception
	lasting    time.Duration
}

func (s *stubReconciler) Status(context.Context) (reconcile.Status, error) {
	return s.status, s.statusErr
}

func (s *stubReconciler) Sweep(context.Context) (reconcile.Run, error) {
	s.sweeps++
	return s.run, s.sweepErr
}

func (s *stubReconciler) Resolve(_ context.Context, resolution reconcile.Resolution) error {
	s.resolved = &resolution
	return s.resolveErr
}

func (s *stubReconciler) GrantException(_ context.Context, exception reconcile.Exception, lasting time.Duration) (reconcile.Exception, error) {
	s.granted, s.lasting = &exception, lasting
	return exception, s.grantErr
}

func registrationsHandler(t *testing.T, stub *stubReconciler) http.Handler {
	t.Helper()
	registrations, err := httpapi.NewRegistrations(stub)
	if err != nil {
		t.Fatal(err)
	}
	principals, err := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	if err != nil {
		t.Fatal(err)
	}
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

func asPrincipal(t *testing.T, r *http.Request) (*http.Request, id.UUID) {
	principal := mustUUID(t)
	return r.WithContext(httpapi.WithCallerScope(r.Context(), "principal:"+principal.String())), principal
}

func serve(handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestEveryDriftRouteRequiresAnAuthenticatedPrincipal(t *testing.T) {
	stub := &stubReconciler{}
	handler := registrationsHandler(t, stub)
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/registrations:drift", nil),
		httptest.NewRequest(http.MethodPost, "/v1/registrations:reconcile", nil),
		httptest.NewRequest(http.MethodPost, "/v1/registrations/"+mustUUID(t).String()+"/drift-exceptions", strings.NewReader(`{}`)),
	} {
		if w := serve(handler, r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a caller, want 401", r.Method, r.URL.Path, w.Code)
		}
	}
	if stub.sweeps != 0 || stub.resolved != nil || stub.granted != nil {
		t.Error("an unauthenticated request reached the reconciler")
	}
}

func TestDriftReportsTheLastRunAndOpenFindings(t *testing.T) {
	finished := time.Now().UTC()
	stub := &stubReconciler{status: reconcile.Status{
		LastRun:  &reconcile.Run{Outcome: reconcile.Unresolved, FinishedAt: &finished},
		Findings: []reconcile.Finding{{ClientKey: "identity-control-caller", Class: reconcile.Blocked}},
	}}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations:drift", nil))
	w := serve(registrationsHandler(t, stub), r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var body struct {
		LastRun  struct{ Outcome string } `json:"last_run"`
		Findings []struct {
			ClientKey string `json:"client_key"`
			Class     string `json:"finding_class"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.LastRun.Outcome != "unresolved" || len(body.Findings) != 1 || body.Findings[0].Class != "blocked" {
		t.Errorf("body = %s", w.Body)
	}

	stub.statusErr = errors.New("database down")
	if w := serve(registrationsHandler(t, stub), r); w.Code != http.StatusInternalServerError {
		t.Errorf("a failed status read answered %d", w.Code)
	}
}

func TestReconcileRunsASweepNow(t *testing.T) {
	stub := &stubReconciler{run: reconcile.Run{Outcome: reconcile.Converged}}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations:reconcile", nil))
	w := serve(registrationsHandler(t, stub), r)
	if w.Code != http.StatusOK || stub.sweeps != 1 || stub.resolved != nil {
		t.Errorf("status %d, %d sweep(s), resolved %v", w.Code, stub.sweeps, stub.resolved)
	}
	if !strings.Contains(w.Body.String(), `"outcome":"converged"`) {
		t.Errorf("body = %s", w.Body)
	}
}

// Applying desired state to findings the sweep left alone is an override of its decision, so it
// names a reason, and the reason and the caller are what the finding records.
func TestResolvingFindingsRequiresAReason(t *testing.T) {
	finding := mustUUID(t)
	body := `{"findings":["` + finding.String() + `"]}`
	stub := &stubReconciler{}
	handler := registrationsHandler(t, stub)

	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations:reconcile", strings.NewReader(body)))
	if w := serve(handler, r); w.Code != http.StatusBadRequest || stub.resolved != nil {
		t.Errorf("a resolution without a reason answered %d and resolved %v", w.Code, stub.resolved)
	}

	r, principal := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations:reconcile", strings.NewReader(body)))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "investigated")
	if w := serve(handler, r); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if stub.resolved == nil || stub.resolved.ResolvedBy != principal || stub.resolved.Reason != "investigated" ||
		len(stub.resolved.Findings) != 1 || stub.resolved.Findings[0] != finding || stub.sweeps != 1 {
		t.Errorf("resolved %+v with %d sweep(s)", stub.resolved, stub.sweeps)
	}
}

func TestReconcileRefusesWhatItCannotRead(t *testing.T) {
	handler := registrationsHandler(t, &stubReconciler{})
	for name, body := range map[string]string{
		"an unknown field": `{"everything":true}`,
		"a malformed id":   `{"findings":["nope"]}`,
		"a document":       `[`,
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations:reconcile", strings.NewReader(body)))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "why")
		if w := serve(handler, r); w.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", name, w.Code)
		}
	}
}

func TestReconcileMapsTheReconcilersErrors(t *testing.T) {
	finding := `{"findings":["` + mustUUID(t).String() + `"]}`
	for name, c := range map[string]struct {
		stub *stubReconciler
		body string
		want int
	}{
		"not resolvable":     {&stubReconciler{resolveErr: reconcile.ErrNotResolvable}, finding, http.StatusBadRequest},
		"kernel unavailable": {&stubReconciler{resolveErr: keycloak.ErrUnavailable}, finding, http.StatusServiceUnavailable},
		"sweep failed":       {&stubReconciler{sweepErr: errors.New("database down")}, "", http.StatusServiceUnavailable},
		"status failed":      {&stubReconciler{statusErr: errors.New("database down")}, "", http.StatusInternalServerError},
		"another replica":    {&stubReconciler{sweepErr: reconcile.ErrSweepInProgress}, "", http.StatusOK},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations:reconcile", strings.NewReader(c.body)))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "why")
		w := serve(registrationsHandler(t, c.stub), r)
		if w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
		if name == "another replica" && !strings.Contains(w.Body.String(), `"deferred":true`) {
			t.Errorf("a sweep deferred to another replica is not reported as deferred: %s", w.Body)
		}
	}
}

func TestADriftExceptionIsGrantedByTheCaller(t *testing.T) {
	stub := &stubReconciler{}
	registration := mustUUID(t)
	r, principal := asPrincipal(t, httptest.NewRequest(http.MethodPost,
		"/v1/registrations/"+registration.String()+"/drift-exceptions",
		strings.NewReader(`{"field_class":"token_lifespan","actor":"admin-user","reason":"load test","duration_seconds":3600}`)))
	w := serve(registrationsHandler(t, stub), r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if stub.granted.Registration != registration || stub.granted.GrantedBy != principal ||
		stub.granted.FieldClass != reconcile.TokenLifespan || stub.lasting != time.Hour {
		t.Errorf("granted %+v lasting %s", stub.granted, stub.lasting)
	}
}

func TestADriftExceptionRefusesWhatItCannotGrant(t *testing.T) {
	path := "/v1/registrations/" + mustUUID(t).String() + "/drift-exceptions"
	valid := `{"field_class":"token_lifespan","actor":"a","reason":"r","duration_seconds":60}`
	for name, c := range map[string]struct {
		path, body string
		stub       *stubReconciler
		want       int
	}{
		"a malformed registration": {"/v1/registrations/nope/drift-exceptions", valid, &stubReconciler{}, http.StatusBadRequest},
		"an unknown field":         {path, `{"forever":true}`, &stubReconciler{}, http.StatusBadRequest},
		"an invalid exception":     {path, valid, &stubReconciler{grantErr: reconcile.ErrInvalid}, http.StatusBadRequest},
		"no such registration":     {path, valid, &stubReconciler{grantErr: reconcile.ErrNoSuchRegistration}, http.StatusNotFound},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body)))
		if w := serve(registrationsHandler(t, c.stub), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestTheDriftHandlerNeedsAReconciler(t *testing.T) {
	if _, err := httpapi.NewRegistrations(nil); err == nil {
		t.Error("a drift handler without a reconciler was built")
	}
}
