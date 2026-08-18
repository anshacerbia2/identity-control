package httpapi_test

// The assertion this file exists for is the last line of TDD-identity-control-001's Week 2
// checklist: `keycloak_user_id` is absent from every response body, asserted by test.
//
// The provisioning package proves it at the type level — Response has no field to populate.
// Proving it here as well is not duplication: a later route could marshal a different type, and
// the property that matters is about the bytes on the wire rather than about one struct.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

const realm = keycloak.Realm("scnehaux")

// stubProvisioner returns a configured outcome and records what it was asked for.
type stubProvisioner struct {
	response provisioning.Response
	err      error
	calls    int
	last     provisioning.CreateRequest
}

func (s *stubProvisioner) Create(_ context.Context, req provisioning.CreateRequest) (provisioning.Response, error) {
	s.calls++
	s.last = req
	return s.response, s.err
}

func mustUUID(t *testing.T) id.UUID {
	t.Helper()
	value, err := id.NewV7()
	if err != nil {
		t.Fatalf("NewV7: %v", err)
	}
	return value
}

func handler(t *testing.T, stub *stubProvisioner) *httpapi.Principals {
	t.Helper()
	h, err := httpapi.NewPrincipals(stub, realm)
	if err != nil {
		t.Fatalf("NewPrincipals: %v", err)
	}
	return h
}

// request builds an authenticated POST. Authentication is a context value because that is where
// the middleware supplied by the composition root puts it, and deriving the caller from the
// request would let one caller claim another's idempotency key.
func request(t *testing.T, body string, opts ...func(*http.Request)) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/principals", strings.NewReader(body))
	r.Header.Set(httpapi.IdempotencyHeader, "key-0001")
	r = r.WithContext(httpapi.WithCallerScope(r.Context(), "svc:admin-api"))
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func TestCreatePrincipalReturns201WithTheIdentifier(t *testing.T) {
	principalID := mustUUID(t)
	stub := &stubProvisioner{response: provisioning.Response{
		PrincipalID: principalID, SubjectType: keycloak.SubjectHuman, Realm: realm,
	}}

	w := httptest.NewRecorder()
	handler(t, stub).CreatePrincipal(w, request(t, `{"username":"operator","subject_type":"human"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["principal_id"] != principalID.String() {
		t.Errorf("principal_id = %v, want %s", body["principal_id"], principalID)
	}
	if stub.last.CallerScope != "svc:admin-api" {
		t.Errorf("caller scope = %q, want the authenticated value", stub.last.CallerScope)
	}
	if stub.last.Realm != realm {
		t.Errorf("realm = %q; it is configuration, not caller input", stub.last.Realm)
	}
}

// TestNoResponseBodyCarriesAKernelIdentifier is the checklist item. Every route and every
// failure branch is exercised, and each body is searched for the kernel's identifier shape and
// for any field name that would carry one.
func TestNoResponseBodyCarriesAKernelIdentifier(t *testing.T) {
	principalID := mustUUID(t)

	outcomes := map[string]*stubProvisioner{
		"created": {response: provisioning.Response{
			PrincipalID: principalID, SubjectType: keycloak.SubjectHuman, Realm: realm,
		}},
		"idempotency conflict": {err: idempotency.ErrConflict},
		"in progress":          {err: idempotency.ErrInProgress},
		"username taken":       {err: fmt.Errorf("create: %w", keycloak.ErrConflict)},
		"kernel unavailable":   {err: fmt.Errorf("create: %w", keycloak.ErrUnavailable)},
		"kernel ambiguous":     {err: fmt.Errorf("create: %w", keycloak.ErrAmbiguous)},
		"mapping not found":    {err: provisioning.ErrNotFound},
		"identifier taken":     {err: provisioning.ErrIdentifierTaken},
		"duplicate in kernel":  {err: provisioning.ErrDuplicateInKernel},
		"credential forbidden": {err: fmt.Errorf("create: %w", keycloak.ErrForbidden)},
		"validation":           {err: errors.New("provisioning: username is required")},
	}

	for name, stub := range outcomes {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler(t, stub).CreatePrincipal(w, request(t, `{"username":"operator","subject_type":"human"}`))

			body := w.Body.String()
			if strings.Contains(body, "kc-user-") {
				t.Errorf("body carries a kernel identifier: %s", body)
			}
			for _, forbidden := range []string{"keycloak_user_id", "keycloak", "user_id"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("body mentions %q: %s", forbidden, body)
				}
			}
		})
	}
}

// TestErrorMappingProducesTheStatusACallerActsOn asserts the distinctions that change client
// behaviour. Collapsing these into 500 would tell a caller to give up when it should retry, and
// to retry when it should stop.
func TestErrorMappingProducesTheStatusACallerActsOn(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"key reused with a different request": {idempotency.ErrConflict, http.StatusConflict},
		"identical request in flight":         {idempotency.ErrInProgress, http.StatusConflict},
		"username already exists":             {fmt.Errorf("x: %w", keycloak.ErrConflict), http.StatusConflict},
		"kernel unavailable":                  {fmt.Errorf("x: %w", keycloak.ErrUnavailable), http.StatusServiceUnavailable},
		"kernel outcome unknown":              {fmt.Errorf("x: %w", keycloak.ErrAmbiguous), http.StatusServiceUnavailable},
		"mapping absent":                      {provisioning.ErrNotFound, http.StatusNotFound},
		"our own defect":                      {provisioning.ErrDuplicateInKernel, http.StatusInternalServerError},
		"credential lacks a role":             {fmt.Errorf("x: %w", keycloak.ErrForbidden), http.StatusInternalServerError},
		"invalid request":                     {errors.New("provisioning: realm is required"), http.StatusBadRequest},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler(t, &stubProvisioner{err: tc.err}).CreatePrincipal(w,
				request(t, `{"username":"operator","subject_type":"human"}`))
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}

// TestAmbiguousOutcomeIsReportedAsUnavailable states the reasoning behind the one mapping that
// looks wrong. Telling a caller the outcome is unknown invites it to retry with a fresh key,
// and a fresh key mints a second Principal for one request.
func TestAmbiguousOutcomeIsReportedAsUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	handler(t, &stubProvisioner{err: fmt.Errorf("x: %w", keycloak.ErrAmbiguous)}).
		CreatePrincipal(w, request(t, `{"username":"operator","subject_type":"human"}`))

	if !strings.Contains(w.Body.String(), "same Idempotency-Key") {
		t.Errorf("the response does not tell the caller to retry with the same key: %s", w.Body.String())
	}
}

func TestUnauthenticatedRequestIsRefusedBeforeTheProvisioner(t *testing.T) {
	stub := &stubProvisioner{}
	r := httptest.NewRequest(http.MethodPost, "/v1/principals",
		strings.NewReader(`{"username":"operator","subject_type":"human"}`))
	r.Header.Set(httpapi.IdempotencyHeader, "key-0001")

	w := httptest.NewRecorder()
	handler(t, stub).CreatePrincipal(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if stub.calls != 0 {
		t.Errorf("the provisioner was called %d times for an unauthenticated request", stub.calls)
	}
}

// TestCallerScopeIsNotTakenFromTheRequest is the assertion that keeps one caller from claiming
// another's idempotency key. A header or body field naming the caller must have no effect.
func TestCallerScopeIsNotTakenFromTheRequest(t *testing.T) {
	stub := &stubProvisioner{response: provisioning.Response{PrincipalID: mustUUID(t)}}

	w := httptest.NewRecorder()
	handler(t, stub).CreatePrincipal(w, request(t,
		`{"username":"operator","subject_type":"human"}`,
		func(r *http.Request) {
			r.Header.Set("X-Caller-Scope", "svc:someone-else")
			r.Header.Set("Authorization", "Bearer svc:someone-else")
		}))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if stub.last.CallerScope != "svc:admin-api" {
		t.Errorf("caller scope = %q; a request header changed the authenticated caller", stub.last.CallerScope)
	}
}

func TestMissingOrOversizedIdempotencyKeyIsRefused(t *testing.T) {
	cases := map[string]func(*http.Request){
		"absent":     func(r *http.Request) { r.Header.Del(httpapi.IdempotencyHeader) },
		"empty":      func(r *http.Request) { r.Header.Set(httpapi.IdempotencyHeader, "") },
		"whitespace": func(r *http.Request) { r.Header.Set(httpapi.IdempotencyHeader, "   ") },
		"too long": func(r *http.Request) {
			r.Header.Set(httpapi.IdempotencyHeader, strings.Repeat("k", 256))
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			stub := &stubProvisioner{}
			w := httptest.NewRecorder()
			handler(t, stub).CreatePrincipal(w,
				request(t, `{"username":"operator","subject_type":"human"}`, mutate))

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
			if stub.calls != 0 {
				t.Errorf("the provisioner was called %d times without a usable key", stub.calls)
			}
		})
	}
}

// TestMalformedBodyIsNotEchoed asserts the redaction property at the boundary where it is
// easiest to lose. A decoder error quotes the offending input, and a body must never be
// reflected: an error path is where a credential escapes into a log aggregator.
func TestMalformedBodyIsNotEchoed(t *testing.T) {
	stub := &stubProvisioner{}
	secret := "hunter2-should-never-appear"

	w := httptest.NewRecorder()
	handler(t, stub).CreatePrincipal(w, request(t,
		fmt.Sprintf(`{"username":"operator","password":%q}`, secret)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Errorf("the response echoed a request body value: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "password") {
		t.Errorf("the response names an unexpected field from the body: %s", w.Body.String())
	}
	if stub.calls != 0 {
		t.Error("a malformed body reached the provisioner")
	}
}

// TestUnknownFieldIsRefused matters because an ignored field is a silently dropped intent. A
// caller sending `realm` expects it to apply; refusing tells them it does not.
func TestUnknownFieldIsRefused(t *testing.T) {
	stub := &stubProvisioner{}
	w := httptest.NewRecorder()
	handler(t, stub).CreatePrincipal(w, request(t,
		`{"username":"operator","subject_type":"human","realm":"other"}`))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if stub.calls != 0 {
		t.Error("a request naming an unknown field reached the provisioner")
	}
}

func TestWorkloadOwnerMustParse(t *testing.T) {
	stub := &stubProvisioner{}
	w := httptest.NewRecorder()
	handler(t, stub).CreatePrincipal(w, request(t,
		`{"username":"job","subject_type":"workload","workload_owner":"not-a-uuid"}`))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if stub.calls != 0 {
		t.Error("an unparseable workload_owner reached the provisioner")
	}
}

func TestWorkloadOwnerIsPassedThrough(t *testing.T) {
	owner := mustUUID(t)
	stub := &stubProvisioner{response: provisioning.Response{PrincipalID: mustUUID(t)}}

	w := httptest.NewRecorder()
	handler(t, stub).CreatePrincipal(w, request(t, fmt.Sprintf(
		`{"username":"job","subject_type":"workload","workload_owner":%q}`, owner)))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if stub.last.WorkloadOwner != owner {
		t.Errorf("workload_owner = %s, want %s", stub.last.WorkloadOwner, owner)
	}
}

func TestNewPrincipalsRejectsMissingDependencies(t *testing.T) {
	if _, err := httpapi.NewPrincipals(nil, realm); err == nil {
		t.Error("NewPrincipals accepted a nil provisioner")
	}
	if _, err := httpapi.NewPrincipals(&stubProvisioner{}, ""); err == nil {
		t.Error("NewPrincipals accepted an empty realm")
	}
}

func TestCallerScopeRejectsBlankValues(t *testing.T) {
	ctx := httpapi.WithCallerScope(context.Background(), "   ")
	if _, ok := httpapi.CallerScope(ctx); ok {
		t.Error("a whitespace-only scope was accepted as an authenticated caller")
	}
	if _, ok := httpapi.CallerScope(context.Background()); ok {
		t.Error("an absent scope was reported as present")
	}
}
