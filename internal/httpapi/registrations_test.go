package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/reconcile"
	"github.com/anshacerbia2/identity-control/internal/registration"
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

func (s *stubReconciler) FindingsFor(_ context.Context, registration id.UUID) ([]reconcile.Finding, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return []reconcile.Finding{{Registration: registration, Class: reconcile.Repaired}}, nil
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

func (s *stubReconciler) ExceptionsFor(_ context.Context, registration id.UUID) ([]reconcile.Exception, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return []reconcile.Exception{{Registration: registration, FieldClass: reconcile.RedirectURIs, Actor: "admin-user"}}, nil
}

func registrationsHandler(t *testing.T, stub *stubReconciler) http.Handler {
	t.Helper()
	registrations, err := httpapi.NewRegistrations(&stubRegistrar{}, stub)
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
		httptest.NewRequest(http.MethodGet, "/v1/registrations/"+mustUUID(t).String()+"/drift-exceptions", nil),
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

func TestARegistrationsDriftExceptionsAreReported(t *testing.T) {
	registrationID := mustUUID(t)
	path := "/v1/registrations/" + registrationID.String() + "/drift-exceptions"
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
	w := serve(registrationsHandler(t, &stubReconciler{}), r)
	var body struct {
		Exceptions []struct {
			Registration string `json:"registration_id"`
			FieldClass   string `json:"field_class"`
			Actor        string `json:"actor"`
		} `json:"exceptions"`
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Exceptions) != 1 || body.Exceptions[0].Registration != registrationID.String() ||
		body.Exceptions[0].FieldClass != "redirect_uris" || body.Exceptions[0].Actor != "admin-user" {
		t.Errorf("exceptions: %s", w.Body)
	}
	for name, c := range map[string]struct {
		path string
		stub *stubReconciler
		want int
	}{
		"a malformed id": {"/v1/registrations/nope/drift-exceptions", &stubReconciler{}, http.StatusBadRequest},
		"a failed read":  {path, &stubReconciler{statusErr: errors.New("database down")}, http.StatusInternalServerError},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, c.path, nil))
		if w := serve(registrationsHandler(t, c.stub), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestTheDriftHandlerNeedsAReconciler(t *testing.T) {
	if _, err := httpapi.NewRegistrations(nil, &stubReconciler{}); err == nil {
		t.Error("a drift handler without a reconciler was built")
	}
}

type stubRegistrar struct {
	req     *registration.Request
	created registration.Registration
	err     error
	listed  *registration.ListQuery
	page    registration.Page

	// The key surface's record of what it was asked.
	addedKey   json.RawMessage
	addedBy    id.UUID
	notAdded   bool
	revokedKey id.UUID
	revokedBy  id.UUID
	reason     string
}

func (s *stubRegistrar) Keys(_ context.Context, registrationID id.UUID) ([]registration.Key, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []registration.Key{{Registration: registrationID, KID: "k1", State: registration.KeyActive}}, nil
}

func (s *stubRegistrar) AddKey(_ context.Context, registrationID id.UUID, publicKey json.RawMessage, by id.UUID) ([]registration.Key, bool, error) {
	s.addedKey, s.addedBy = publicKey, by
	if s.err != nil {
		return nil, false, s.err
	}
	return []registration.Key{{Registration: registrationID, KID: "k2", State: registration.KeyActive}}, !s.notAdded, nil
}

func (s *stubRegistrar) RevokeKey(_ context.Context, registrationID, keyID, by id.UUID, reason string) ([]registration.Key, error) {
	s.revokedKey, s.revokedBy, s.reason = keyID, by, reason
	if s.err != nil {
		return nil, s.err
	}
	return []registration.Key{{Registration: registrationID, ID: keyID, State: registration.KeyRevoked}}, nil
}

func (s *stubRegistrar) List(_ context.Context, query registration.ListQuery) (registration.Page, error) {
	s.listed = &query
	return s.page, s.err
}

func (s *stubRegistrar) Register(_ context.Context, req registration.Request) (registration.Registration, error) {
	s.req = &req
	return s.created, s.err
}

func (s *stubRegistrar) Get(_ context.Context, registrationID id.UUID) (registration.Registration, error) {
	if s.err != nil {
		return registration.Registration{}, s.err
	}
	return registration.Registration{ID: registrationID, ClientKey: "web"}, nil
}

func registrarHandler(t *testing.T, registrar *stubRegistrar) http.Handler {
	t.Helper()
	registrations, err := httpapi.NewRegistrations(registrar, &stubReconciler{})
	if err != nil {
		t.Fatal(err)
	}
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// The list passes its cursor, size and state through, and answers with the page and its next cursor.
func TestTheRegistrationListPassesItsCursorThrough(t *testing.T) {
	after, _ := id.NewV7()
	next := "0192f0e0-0000-7000-8000-000000000001"
	registrar := &stubRegistrar{page: registration.Page{
		Registrations: []registration.Registration{{ClientKey: "web", State: "active"}}, Next: &next}}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet,
		"/v1/registrations?after="+after.String()+"&limit=10&state=active", nil))
	w := serve(registrarHandler(t, registrar), r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := registrar.listed; got == nil || got.After != after || got.Limit != 10 || got.State != "active" {
		t.Errorf("query = %+v", got)
	}
	var body struct {
		Registrations []map[string]any `json:"registrations"`
		Next          *string          `json:"next"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Registrations) != 1 || body.Next == nil || *body.Next != next {
		t.Errorf("body = %+v", body)
	}
}

func TestTheRegistrationListRefusesWhatItCannotRead(t *testing.T) {
	for name, target := range map[string]string{
		"a cursor that is not an identifier": "/v1/registrations?after=page-2",
		"a limit that is not a number":       "/v1/registrations?limit=ten",
		"a limit of zero":                    "/v1/registrations?limit=0",
	} {
		t.Run(name, func(t *testing.T) {
			registrar := &stubRegistrar{}
			r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, target, nil))
			w := serve(registrarHandler(t, registrar), r)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status %d: %s", w.Code, w.Body)
			}
		})
	}
	// The service's own refusal (a limit over the maximum, an unknown state) is a 400 as well.
	registrar := &stubRegistrar{err: fmt.Errorf("%w: limit must be between 1 and 100", registration.ErrInvalid)}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations?limit=500", nil))
	if w := serve(registrarHandler(t, registrar), r); w.Code != http.StatusBadRequest {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
}

func TestTheRegistrationListRequiresACaller(t *testing.T) {
	w := serve(registrarHandler(t, &stubRegistrar{}), httptest.NewRequest(http.MethodGet, "/v1/registrations", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d", w.Code)
	}
}

const registerBody = `{"client_key":"web","profile":"public","audience_class":"internal","application_ref":"app",
  "audience":["orders"],"redirect_uris":["https://app.example.com/cb"]}`

// The caller, not the body, is the accountable Principal, and the key is claimed under the caller.
func TestARegistrationIsRecordedUnderTheCaller(t *testing.T) {
	registrar := &stubRegistrar{created: registration.Registration{ClientKey: "web", State: "active"}}
	r, principal := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations", strings.NewReader(registerBody)))
	r.Header.Set(httpapi.IdempotencyHeader, "register-1")
	w := serve(registrarHandler(t, registrar), r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	got := registrar.req
	if got.RegisteredBy != principal || got.CallerScope != "principal:"+principal.String() || got.IdempotencyKey != "register-1" ||
		got.ClientKey != "web" || len(got.Audience) != 1 || len(got.RedirectURIs) != 1 {
		t.Errorf("request = %+v", got)
	}
}

func TestARegistrationRefusesWhatItCannotRead(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		key  string
	}{
		"no Idempotency-Key":   {registerBody, ""},
		"an unknown field":     {`{"client_key":"web","secret":"x"}`, "k"},
		"a malformed document": {`{`, "k"},
	} {
		registrar := &stubRegistrar{}
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations", strings.NewReader(c.body)))
		if c.key != "" {
			r.Header.Set(httpapi.IdempotencyHeader, c.key)
		}
		if w := serve(registrarHandler(t, registrar), r); w.Code != http.StatusBadRequest || registrar.req != nil {
			t.Errorf("%s answered %d", name, w.Code)
		}
	}
	w := serve(registrarHandler(t, &stubRegistrar{}), httptest.NewRequest(http.MethodPost, "/v1/registrations", strings.NewReader(registerBody)))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated registration answered %d", w.Code)
	}
}

func TestARegistrationMapsTheRegistrarsErrors(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"invalid":           {registration.ErrInvalid, http.StatusBadRequest},
		"a private key":     {registration.ErrPrivateKey, http.StatusBadRequest},
		"public key reused": {registration.ErrKeyInUse, http.StatusConflict},
		"scope undeclared":  {registration.ErrScopeUndeclared, http.StatusBadRequest},
		"key taken":         {registration.ErrKeyTaken, http.StatusConflict},
		"key reused":        {idempotency.ErrConflict, http.StatusConflict},
		"in progress":       {idempotency.ErrInProgress, http.StatusConflict},
		"kernel down":       {keycloak.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations", strings.NewReader(registerBody)))
		r.Header.Set(httpapi.IdempotencyHeader, "k")
		if w := serve(registrarHandler(t, &stubRegistrar{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestARegistrationIsReadByIdentifier(t *testing.T) {
	registrationID := mustUUID(t)
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations/"+registrationID.String(), nil))
	w := serve(registrarHandler(t, &stubRegistrar{}), r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), registrationID.String()) {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
	for path, want := range map[string]int{
		"/v1/registrations/nope": http.StatusBadRequest,
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
		if w := serve(registrarHandler(t, &stubRegistrar{}), r); w.Code != want {
			t.Errorf("%s answered %d", path, w.Code)
		}
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations/"+registrationID.String(), nil))
	if w := serve(registrarHandler(t, &stubRegistrar{err: registration.ErrNotFound}), r); w.Code != http.StatusNotFound {
		t.Errorf("an unknown registration answered %d", w.Code)
	}
	if w := serve(registrarHandler(t, &stubRegistrar{}), httptest.NewRequest(http.MethodGet, "/v1/registrations/"+registrationID.String(), nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated read answered %d", w.Code)
	}
}

func TestTheRegistrationHandlerNeedsARegistrar(t *testing.T) {
	if _, err := httpapi.NewRegistrations(&stubRegistrar{}, nil); err == nil {
		t.Error("a handler without a reconciler was built")
	}
}

func TestARegistrationsFindingsAreReported(t *testing.T) {
	registrationID := mustUUID(t)
	path := "/v1/registrations/" + registrationID.String() + "/findings"
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
	w := serve(registrationsHandler(t, &stubReconciler{}), r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"finding_class":"repaired"`) {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
	for name, c := range map[string]struct {
		path string
		stub *stubReconciler
		auth bool
		want int
	}{
		"no caller":      {path, &stubReconciler{}, false, http.StatusUnauthorized},
		"a malformed id": {"/v1/registrations/nope/findings", &stubReconciler{}, true, http.StatusBadRequest},
		"a failed read":  {path, &stubReconciler{statusErr: errors.New("database down")}, true, http.StatusInternalServerError},
	} {
		r := httptest.NewRequest(http.MethodGet, c.path, nil)
		if c.auth {
			r, _ = asPrincipal(t, r)
		}
		if w := serve(registrationsHandler(t, c.stub), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

const keyBody = `{"public_key":{"kty":"RSA","kid":"k2","n":"AQAB","e":"AQAB"}}`

// A registration carries the confidential client's first public key through to the registrar.
func TestARegistrationCarriesItsPublicKey(t *testing.T) {
	registrar := &stubRegistrar{created: registration.Registration{ClientKey: "bff", State: "active"}}
	body := `{"client_key":"bff","profile":"confidential","audience_class":"internal","application_ref":"app",
	  "redirect_uris":["https://app.example.com/cb"],"public_key":{"kty":"RSA","n":"AQAB","e":"AQAB"}}`
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/registrations", strings.NewReader(body)))
	r.Header.Set(httpapi.IdempotencyHeader, "register-bff")
	if w := serve(registrarHandler(t, registrar), r); w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := registrar.req; got == nil || !strings.Contains(string(got.PublicKey), `"kty":"RSA"`) {
		t.Errorf("request = %+v", got)
	}
}

// The next key is added under the caller. A key that was added answers 201, and one that already
// was the client's active key answers 200: a retry after a lost response.
func TestTheNextKeyIsAddedUnderTheCaller(t *testing.T) {
	registrationID := mustUUID(t)
	path := "/v1/registrations/" + registrationID.String() + "/keys"
	for _, c := range []struct {
		notAdded bool
		want     int
	}{{false, http.StatusCreated}, {true, http.StatusOK}} {
		registrar := &stubRegistrar{notAdded: c.notAdded}
		r, principal := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, strings.NewReader(keyBody)))
		w := serve(registrarHandler(t, registrar), r)
		if w.Code != c.want || !strings.Contains(w.Body.String(), `"kid":"k2"`) {
			t.Errorf("status %d, want %d: %s", w.Code, c.want, w.Body)
		}
		if registrar.addedBy != principal || !strings.Contains(string(registrar.addedKey), `"kid":"k2"`) {
			t.Errorf("added %s by %s", registrar.addedKey, registrar.addedBy)
		}
	}
}

func TestTheKeysAreListed(t *testing.T) {
	registrationID := mustUUID(t)
	path := "/v1/registrations/" + registrationID.String() + "/keys"
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
	if w := serve(registrarHandler(t, &stubRegistrar{}), r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"kid":"k1"`) {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
	if w := serve(registrarHandler(t, &stubRegistrar{err: registration.ErrNotFound}), r); w.Code != http.StatusNotFound {
		t.Errorf("an unknown registration's keys answered %d", w.Code)
	}
}

// Revocation names the key and carries the caller's reason, which it cannot do without.
func TestAKeyIsRevokedWithAReason(t *testing.T) {
	registrationID, keyID := mustUUID(t), mustUUID(t)
	path := "/v1/registrations/" + registrationID.String() + "/keys/" + keyID.String() + ":revoke"
	registrar := &stubRegistrar{}
	r, principal := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "the laptop holding it was lost")
	if w := serve(registrarHandler(t, registrar), r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"revoked"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if registrar.revokedKey != keyID || registrar.revokedBy != principal || registrar.reason != "the laptop holding it was lost" {
		t.Errorf("revoked %s by %s for %q", registrar.revokedKey, registrar.revokedBy, registrar.reason)
	}

	for name, c := range map[string]struct {
		path   string
		reason string
		want   int
	}{
		"no reason":          {path, "", http.StatusBadRequest},
		"an unknown action":  {"/v1/registrations/" + registrationID.String() + "/keys/" + keyID.String() + ":rotate", "r", http.StatusNotFound},
		"no action":          {"/v1/registrations/" + registrationID.String() + "/keys/" + keyID.String(), "r", http.StatusNotFound},
		"a malformed key id": {"/v1/registrations/" + registrationID.String() + "/keys/nope:revoke", "r", http.StatusBadRequest},
		"a malformed registration": {"/v1/registrations/nope/keys/" + keyID.String() + ":revoke", "r",
			http.StatusBadRequest},
	} {
		registrar := &stubRegistrar{}
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, c.path, nil))
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(registrarHandler(t, registrar), r); w.Code != c.want || !registrar.revokedKey.IsNil() {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestTheKeyRoutesMapTheRegistrarsErrors(t *testing.T) {
	registrationID, keyID := mustUUID(t), mustUUID(t)
	add := "/v1/registrations/" + registrationID.String() + "/keys"
	revoke := add + "/" + keyID.String() + ":revoke"
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"a private key":         {registration.ErrPrivateKey, http.StatusBadRequest},
		"an invalid key":        {registration.ErrInvalid, http.StatusBadRequest},
		"a key in use":          {registration.ErrKeyInUse, http.StatusConflict},
		"a rotation underway":   {registration.ErrRotationInProgress, http.StatusConflict},
		"a keyless profile":     {registration.ErrNotKeyed, http.StatusConflict},
		"an inactive client":    {registration.ErrNotActive, http.StatusConflict},
		"a key already revoked": {registration.ErrKeyNotLive, http.StatusConflict},
		"an unknown client":     {registration.ErrNotFound, http.StatusNotFound},
		"kernel down":           {keycloak.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, add, strings.NewReader(keyBody)))
		if w := serve(registrarHandler(t, &stubRegistrar{err: c.err}), r); w.Code != c.want {
			t.Errorf("adding: %s answered %d, want %d", name, w.Code, c.want)
		}
		r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, revoke, nil))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "leaked")
		if w := serve(registrarHandler(t, &stubRegistrar{err: c.err}), r); w.Code != c.want {
			t.Errorf("revoking: %s answered %d, want %d", name, w.Code, c.want)
		}
	}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, add, strings.NewReader(`{"public_key":{},"secret":"x"}`)))
	if w := serve(registrarHandler(t, &stubRegistrar{}), r); w.Code != http.StatusBadRequest {
		t.Errorf("a key document with an unknown field answered %d", w.Code)
	}
}

func TestEveryKeyRouteRequiresAnAuthenticatedPrincipal(t *testing.T) {
	registrationID, keyID := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{}
	handler := registrarHandler(t, registrar)
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/registrations/"+registrationID.String()+"/keys", nil),
		httptest.NewRequest(http.MethodPost, "/v1/registrations/"+registrationID.String()+"/keys", strings.NewReader(keyBody)),
		httptest.NewRequest(http.MethodPost, "/v1/registrations/"+registrationID.String()+"/keys/"+keyID.String()+":revoke", nil),
	} {
		if w := serve(handler, r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a caller, want 401", r.Method, r.URL.Path, w.Code)
		}
	}
	if registrar.addedKey != nil || !registrar.revokedKey.IsNil() {
		t.Error("an unauthenticated request reached the registrar")
	}
}
