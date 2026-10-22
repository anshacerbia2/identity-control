package httpapi_test

// The enrolment routes at the transport (ADR-IAM-011 §5.1 to §5.9, TDD-identity-control-001 1.27.0):
// a BFF workload the record admits, the client address from Forwarded alone, one answer per outcome,
// 429 with Retry-After, and the password shown once with no-store.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/enrolment"
	"github.com/anshacerbia2/identity-control/internal/httpapi"
)

type stubAdmission struct {
	admitted map[id.UUID]bool
	err      error
}

func (s stubAdmission) Admitted(_ context.Context, principal id.UUID) (bool, error) {
	return s.admitted[principal], s.err
}

type stubEnrolments struct {
	requested []enrolment.RequestInput
	verified  []enrolment.VerifyInput
	answer    id.UUID
	completed enrolment.Completed
	err       error
}

func (s *stubEnrolments) Request(_ context.Context, in enrolment.RequestInput) (id.UUID, error) {
	s.requested = append(s.requested, in)
	return s.answer, s.err
}

func (s *stubEnrolments) Verify(_ context.Context, in enrolment.VerifyInput) (enrolment.Completed, error) {
	s.verified = append(s.verified, in)
	return s.completed, s.err
}

var bff = id.MustParse("01a0fc67-3cc0-7011-95cb-e160cc46b5b0")

func enrolmentHandler(t *testing.T, stub *stubEnrolments, admission httpapi.EnrolmentAdmission) http.Handler {
	t.Helper()
	verifier, err := verify.New(verify.Config{
		Issuer: authIssuer, Audience: authAudience,
		Keys:        verify.StaticKeys{authKeyID: &signingKeyForAuth(t).PublicKey},
		Requirement: httpapi.EnrolmentCallerRequirement(),
		Now:         func() time.Time { return authNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Database: &stubProber{},
		Enrolments: stub, EnrolmentVerifier: verifier, EnrolmentAdmission: admission})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

func bffToken(t *testing.T, principal id.UUID) string {
	return token(t, map[string]any{"principal_id": principal.String(), "subject_type": "workload"})
}

func enrol(t *testing.T, handler http.Handler, path, body, bearer string, forwarded ...string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for _, value := range forwarded {
		request.Header.Add("Forwarded", value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestTheEnrolmentRoutesAdmitTheRegisteredBFFWorkloadAlone(t *testing.T) {
	stub := &stubEnrolments{answer: id.MustParse("01a0fc67-3cc0-7011-95cb-e160cc46b5b1")}
	admitted := stubAdmission{admitted: map[id.UUID]bool{bff: true}}
	handler := enrolmentHandler(t, stub, admitted)
	body := `{"token":"t"}`

	w := enrol(t, handler, "/v1/enrolments", body, bffToken(t, bff), "for=203.0.113.9;proto=https")
	if w.Code != http.StatusAccepted || strings.TrimSpace(w.Body.String()) != `{"enrolment_id":"`+stub.answer.String()+`"}` ||
		w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the admitted BFF answered %d %s", w.Code, w.Body)
	}
	if len(stub.requested) != 1 || stub.requested[0].ClientAddress != "203.0.113.9" || stub.requested[0].Caller != bff ||
		stub.requested[0].Token != "t" {
		t.Fatalf("the service was asked %+v", stub.requested)
	}

	other := id.MustParse("01a0fc67-3cc0-7011-95cb-e160cc46b5b2")
	for name, c := range map[string]struct {
		bearer string
		want   int
	}{
		"no token":                  {"", http.StatusUnauthorized},
		"a person's token":          {token(t, map[string]any{"principal_id": bff.String(), "subject_type": "human"}), http.StatusUnauthorized},
		"a workload not registered": {bffToken(t, other), http.StatusForbidden},
		"a workload with a Tenant": {token(t, map[string]any{"principal_id": bff.String(), "subject_type": "workload",
			"tenant_id": "01a0fc67-3cc0-7011-95cb-e160cc46b5b3"}), http.StatusUnauthorized},
	} {
		if w := enrol(t, handler, "/v1/enrolments", body, c.bearer, "for=203.0.113.9"); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
	if w := enrol(t, enrolmentHandler(t, stub, stubAdmission{err: errors.New("down")}), "/v1/enrolments", body,
		bffToken(t, bff), "for=203.0.113.9"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("an unreadable record answered %d", w.Code)
	}
	if len(stub.requested) != 1 {
		t.Errorf("a refused caller reached the service: %d requests", len(stub.requested))
	}
}

// Without the client address from the trusted workload there is no key to count under: 400, before
// the service runs (ADR-IAM-011 §5.8).
func TestAMissingOrMalformedForwardedIs400(t *testing.T) {
	stub := &stubEnrolments{}
	handler := enrolmentHandler(t, stub, stubAdmission{admitted: map[id.UUID]bool{bff: true}})
	for name, forwarded := range map[string][]string{
		"none":           nil,
		"no for":         {"proto=https;by=203.0.113.1"},
		"unknown":        {"for=unknown"},
		"obfuscated":     {"for=_hidden"},
		"not an address": {"for=example.com"},
		"bare IPv6":      {"for=2001:db8::1"},
	} {
		if w := enrol(t, handler, "/v1/enrolments", `{"token":"t"}`, bffToken(t, bff), forwarded...); w.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", name, w.Code)
		}
	}
	if len(stub.requested) != 0 {
		t.Errorf("the service ran %d times without an address", len(stub.requested))
	}
}

func TestTheClientAddressIsTheFirstForCountedAsTheLimitsCountIt(t *testing.T) {
	for _, c := range []struct {
		values []string
		want   string
		ok     bool
	}{
		{[]string{"for=192.0.2.60;proto=http;by=203.0.113.43"}, "192.0.2.60", true},
		{[]string{`for="192.0.2.60:4711"`}, "192.0.2.60", true},
		{[]string{`for="[2001:db8:cafe::17]"`}, "2001:db8:cafe::/64", true},
		{[]string{`for="[2001:db8:cafe:1:2:3:4:5]:4711"`}, "2001:db8:cafe:1::/64", true},
		{[]string{`for="[::ffff:192.0.2.1]"`}, "192.0.2.1", true},
		{[]string{"for=192.0.2.43, for=198.51.100.17"}, "192.0.2.43", true},
		{[]string{"for=192.0.2.43", "for=198.51.100.17"}, "192.0.2.43", true},
		{[]string{"For=192.0.2.43"}, "192.0.2.43", true},
		{[]string{`for="192.0.2.43:0"`}, "", false},
		{[]string{`for="[2001:db8::1%eth0]"`}, "", false},
		{[]string{"for=unknown, for=192.0.2.1"}, "", false},
		{[]string{""}, "", false},
	} {
		got, ok := httpapi.ClientAddress(c.values)
		if got != c.want || ok != c.ok {
			t.Errorf("%q answered %q %t, want %q %t", c.values, got, ok, c.want, c.ok)
		}
	}
}

func TestEachEnrolmentOutcomeHasOneAnswer(t *testing.T) {
	path := "/v1/enrolments/01a0fc67-3cc0-7011-95cb-e160cc46b5b4:verify"
	cases := []struct {
		name   string
		err    error
		status int
		detail string
	}{
		{"a refusal", enrolment.ErrRefused, http.StatusBadRequest, "The code is wrong, has expired, or has been tried too often; start again from the invitation link"},
		{"a limit", &enrolment.Limited{RetryAfter: 42}, http.StatusTooManyRequests, ""},
		{"a dependency", enrolment.ErrUnavailable, http.StatusServiceUnavailable, ""},
	}
	for _, c := range cases {
		stub := &stubEnrolments{err: c.err}
		handler := enrolmentHandler(t, stub, stubAdmission{admitted: map[id.UUID]bool{bff: true}})
		w := enrol(t, handler, path, `{"code":"12345678"}`, bffToken(t, bff), "for=198.51.100.7")
		if w.Code != c.status || (c.detail != "" && !strings.Contains(w.Body.String(), c.detail)) {
			t.Errorf("%s answered %d %s", c.name, w.Code, w.Body)
		}
		if c.status == http.StatusTooManyRequests && w.Header().Get("Retry-After") != "42" {
			t.Errorf("a limit answered Retry-After %q", w.Header().Get("Retry-After"))
		}
	}

	completed := enrolment.Completed{PrincipalID: bff, Username: "p@example.test", TemporaryPassword: "ABCDEFGHJKMNPQRSTVWXYZ01",
		LapsesAt: authNow}
	stub := &stubEnrolments{completed: completed}
	handler := enrolmentHandler(t, stub, stubAdmission{admitted: map[id.UUID]bool{bff: true}})
	w := enrol(t, handler, path, `{"code":"12345678"}`, bffToken(t, bff), `for="[2001:db8::5]"`)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"temporary_password":"ABCDEFGHJKMNPQRSTVWXYZ01"`) ||
		w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the right code answered %d %s", w.Code, w.Body)
	}
	if len(stub.verified) != 1 || stub.verified[0].Code != "12345678" || stub.verified[0].ClientAddress != "2001:db8::/64" ||
		stub.verified[0].EnrolmentID.String() != "01a0fc67-3cc0-7011-95cb-e160cc46b5b4" {
		t.Fatalf("the service was asked %+v", stub.verified)
	}

	// A malformed identifier is a code for no enrolment: counted, then the one refusal.
	stub = &stubEnrolments{err: enrolment.ErrRefused}
	handler = enrolmentHandler(t, stub, stubAdmission{admitted: map[id.UUID]bool{bff: true}})
	if w := enrol(t, handler, "/v1/enrolments/not-an-id:verify", `{"code":"1"}`, bffToken(t, bff), "for=198.51.100.7"); w.Code != http.StatusBadRequest ||
		len(stub.verified) != 1 || stub.verified[0].EnrolmentID.IsNil() {
		t.Errorf("a malformed identifier answered %d after %d calls", w.Code, len(stub.verified))
	}
	if w := enrol(t, handler, "/v1/enrolments/x:cancel", `{}`, bffToken(t, bff), "for=198.51.100.7"); w.Code != http.StatusNotFound {
		t.Errorf("an unknown action answered %d", w.Code)
	}
	if w := enrol(t, handler, "/v1/enrolments", `{"token":""}`, bffToken(t, bff), "for=198.51.100.7"); w.Code != http.StatusBadRequest {
		t.Errorf("an empty token answered %d", w.Code)
	}
}

type stubCallerRegistry struct {
	changes []enrolment.Change
	err     error
}

func (s *stubCallerRegistry) List(context.Context) ([]enrolment.Caller, error) {
	return []enrolment.Caller{{PrincipalID: bff, Purpose: "BFF"}}, s.err
}

func (s *stubCallerRegistry) Register(_ context.Context, change enrolment.Change) (enrolment.Caller, error) {
	s.changes = append(s.changes, change)
	return enrolment.Caller{PrincipalID: change.Principal, Purpose: change.Purpose, RegisteredBy: change.By}, s.err
}

func (s *stubCallerRegistry) Retire(_ context.Context, change enrolment.Change) (enrolment.Caller, error) {
	s.changes = append(s.changes, change)
	return enrolment.Caller{PrincipalID: change.Principal}, s.err
}

func callerRoutes(t *testing.T, registry *stubCallerRegistry) http.Handler {
	t.Helper()
	callers, err := httpapi.NewEnrolmentCallers(registry)
	if err != nil {
		t.Fatal(err)
	}
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Database: &stubProber{}, EnrolmentCallers: callers})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// A provider registers, lists and retires the BFF workloads, each change with its reason
// (ADR-IAM-011 §5.8).
func TestAProviderKeepsTheEnrolmentCallerRecord(t *testing.T) {
	registry := &stubCallerRegistry{}
	handler := callerRoutes(t, registry)
	r, provider := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/enrolment-callers",
		strings.NewReader(`{"principal_id":"`+bff.String()+`","purpose":"Identity Experience's BFF"}`)))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "the enrolment page")
	if w := serve(handler, r); w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	if len(registry.changes) != 1 || registry.changes[0].By != provider || registry.changes[0].Reason != "the enrolment page" ||
		registry.changes[0].Principal != bff {
		t.Fatalf("registered %+v", registry.changes)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/enrolment-callers", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), bff.String()) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/enrolment-callers/"+bff.String()+":retire", nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "replaced")
	if w := serve(handler, r); w.Code != http.StatusOK || len(registry.changes) != 2 {
		t.Fatalf("retire: %d %s", w.Code, w.Body)
	}
	for name, c := range map[string]struct {
		path, body, reason string
		err                error
		want               int
	}{
		"no reason":       {"/v1/enrolment-callers", `{"principal_id":"` + bff.String() + `","purpose":"p"}`, "", nil, http.StatusBadRequest},
		"not a workload":  {"/v1/enrolment-callers", `{"principal_id":"` + bff.String() + `","purpose":"p"}`, "r", enrolment.ErrNotWorkload, http.StatusBadRequest},
		"registered":      {"/v1/enrolment-callers", `{"principal_id":"` + bff.String() + `","purpose":"p"}`, "r", enrolment.ErrRegistered, http.StatusConflict},
		"a bad id":        {"/v1/enrolment-callers", `{"principal_id":"x","purpose":"p"}`, "r", nil, http.StatusBadRequest},
		"not registered":  {"/v1/enrolment-callers/" + bff.String() + ":retire", ``, "r", enrolment.ErrNoCaller, http.StatusNotFound},
		"another action":  {"/v1/enrolment-callers/" + bff.String() + ":suspend", ``, "r", nil, http.StatusNotFound},
		"a retire reason": {"/v1/enrolment-callers/" + bff.String() + ":retire", ``, "", nil, http.StatusBadRequest},
	} {
		registry := &stubCallerRegistry{err: c.err}
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body)))
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(callerRoutes(t, registry), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d: %s", name, w.Code, c.want, w.Body)
		}
	}
	// A person who is not a provider is refused before anything is read.
	r = httptest.NewRequest(http.MethodGet, "/v1/enrolment-callers", nil)
	r = asOwner(r, bff)
	if w := serve(callerRoutes(t, &stubCallerRegistry{}), r); w.Code != http.StatusForbidden {
		t.Errorf("a non-provider answered %d", w.Code)
	}
}
