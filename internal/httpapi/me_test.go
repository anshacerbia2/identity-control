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
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/securitystate"
)

type stubSelf struct {
	err       error
	state     string
	caller    id.UUID
	sid       string
	submitted *securitystate.Command
	// level is the level the account's enrollment requires; enrolled is the type authorized.
	level    string
	enrolled string
}

func (s *stubSelf) Enroll(_ context.Context, actor securitystate.Actor, authenticatorType string, meets func(level string) bool) (string, error) {
	s.caller = actor.Principal
	if s.err != nil {
		return "", s.err
	}
	level := s.level
	if level == "" {
		level = "aal1"
	}
	if !meets(level) {
		return "", securitystate.ErrStepUp{Level: level}
	}
	s.enrolled = authenticatorType
	return "CONFIGURE_TOTP", nil
}

func (s *stubSelf) MySessions(_ context.Context, principal id.UUID, sid string) ([]securitystate.MySession, error) {
	s.caller, s.sid = principal, sid
	return []securitystate.MySession{{SecurityRef: "k1.s", Current: true}}, s.err
}

func (s *stubSelf) MyAuthenticators(_ context.Context, principal id.UUID) ([]securitystate.MyAuthenticator, error) {
	s.caller = principal
	return []securitystate.MyAuthenticator{{SecurityRef: "k1.a", Type: "password"}}, s.err
}

func (s *stubSelf) MyOperation(_ context.Context, principal, operationID id.UUID) (securitystate.Operation, error) {
	s.caller = principal
	return securitystate.Operation{OperationID: operationID, State: securitystate.StateApplied}, s.err
}

func (s *stubSelf) Submit(_ context.Context, cmd securitystate.Command) (securitystate.Operation, error) {
	s.submitted = &cmd
	if s.err != nil {
		return securitystate.Operation{}, s.err
	}
	state := s.state
	if state == "" {
		state = securitystate.StateApplied
	}
	operationID, _ := id.NewV7()
	return securitystate.Operation{OperationID: operationID, PrincipalID: cmd.Subject, Type: cmd.Type, State: state}, nil
}

func meHandler(t *testing.T, stub *stubSelf) http.Handler {
	t.Helper()
	me, err := httpapi.NewMe(stub, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
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

// asPerson is any person's request: no provider authority, a sid, and an authentication authAge ago.
func asPerson(t *testing.T, r *http.Request, authAge time.Duration) (*http.Request, id.UUID) {
	t.Helper()
	person := mustUUID(t)
	ctx := httpapi.WithSessionID(httpapi.WithCallerScope(r.Context(), "principal:"+person.String()), "sid-1")
	ctx = httpapi.WithAssurance(ctx, httpapi.AcrAAL2, time.Now().Add(-authAge))
	r = r.WithContext(ctx)
	if r.Method == http.MethodPost {
		r.Header.Set("Idempotency-Key", "k-1")
	}
	return r, person
}

func TestAPersonReadsTheirOwnState(t *testing.T) {
	for path, key := range map[string]string{"/v1/me/sessions": `"sessions"`, "/v1/me/authenticators": `"authenticators"`} {
		stub := &stubSelf{}
		r, person := asPerson(t, httptest.NewRequest(http.MethodGet, path, nil), time.Minute)
		w := serve(meHandler(t, stub), r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), key) || stub.caller != person {
			t.Errorf("%s: %d %s, read as %s", path, w.Code, w.Body, stub.caller)
		}
	}
	stub := &stubSelf{}
	r, _ := asPerson(t, httptest.NewRequest(http.MethodGet, "/v1/me/sessions", nil), time.Minute)
	serve(meHandler(t, stub), r)
	if stub.sid != "sid-1" {
		t.Errorf("the session list was asked for sid %q, not the token's", stub.sid)
	}
}

func TestEachSelfCommandActsOnTheCaller(t *testing.T) {
	for path, opType := range map[string]string{
		"/v1/me/sessions/k1.s:terminate":    securitystate.TypeSessionTerminate,
		"/v1/me/sessions:terminate-all":     securitystate.TypeTerminateAll,
		"/v1/me/authenticators/k1.a:remove": securitystate.TypeAuthenticatorRemove,
	} {
		stub := &stubSelf{}
		r, person := asPerson(t, httptest.NewRequest(http.MethodPost, path, nil), time.Minute)
		w := serve(meHandler(t, stub), r)
		c := stub.submitted
		if w.Code != http.StatusOK || c == nil {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if !c.Self || c.Type != opType || c.Subject != person || c.Actor.Principal != person || c.Reason != "" ||
			c.ExpectedVersion != 0 || c.IdempotencyKey != "k-1" {
			t.Errorf("%s: submitted %+v", path, c)
		}
	}
}

// Removing an authenticator needs two factors, recently; ending a session needs neither.
func TestARemovalNeedsTwoFactors(t *testing.T) {
	stub := &stubSelf{}
	r, _ := asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/authenticators/k1.a:remove", nil), time.Minute)
	r = r.WithContext(httpapi.WithAssurance(r.Context(), "aal1", time.Now()))
	w := serve(meHandler(t, stub), r)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `acr_values="aal2"`) ||
		stub.submitted != nil {
		t.Errorf("a removal at aal1: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	r, _ = asPerson(t, httptest.NewRequest(http.MethodGet, "/v1/me/sessions", nil), time.Minute)
	r = r.WithContext(httpapi.WithAssurance(r.Context(), "aal1", time.Now()))
	if w := serve(meHandler(t, stub), r); w.Code != http.StatusOK {
		t.Errorf("reading one's sessions at aal1: %d", w.Code)
	}
}

// Removing an authenticator needs a recent sign-in; ending a session never does.
func TestOnlyARemovalNeedsAStepUp(t *testing.T) {
	stub := &stubSelf{}
	r, _ := asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/authenticators/k1.a:remove", nil), time.Hour)
	w := serve(meHandler(t, stub), r)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_user_authentication") ||
		stub.submitted != nil {
		t.Errorf("a stale removal: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/sessions:terminate-all", nil), time.Hour)
	if w := serve(meHandler(t, stub), r); w.Code != http.StatusOK {
		t.Errorf("ending sessions after an hour: %d", w.Code)
	}
}

func TestASelfCommandStillRunningPointsAtTheCallersOwnOperation(t *testing.T) {
	stub := &stubSelf{state: securitystate.StatePending}
	r, _ := asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/sessions:terminate-all", nil), time.Minute)
	w := serve(meHandler(t, stub), r)
	if w.Code != http.StatusAccepted || !strings.HasPrefix(w.Header().Get("Location"), "/v1/me/security-operations/") {
		t.Errorf("%d, Location %q", w.Code, w.Header().Get("Location"))
	}
	r, person := asPerson(t, httptest.NewRequest(http.MethodGet, "/v1/me/security-operations/"+mustUUID(t).String(), nil), time.Minute)
	if w := serve(meHandler(t, stub), r); w.Code != http.StatusOK || stub.caller != person {
		t.Errorf("reading the operation: %d as %s", w.Code, stub.caller)
	}
}

func TestSelfRoutesRefuseWhatTheyMust(t *testing.T) {
	handler := meHandler(t, &stubSelf{})
	if w := serve(handler, httptest.NewRequest(http.MethodGet, "/v1/me/sessions", nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("no caller: %d", w.Code)
	}
	r, _ := asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/sessions:terminate-all", nil), time.Minute)
	r.Header.Del("Idempotency-Key")
	if w := serve(handler, r); w.Code != http.StatusBadRequest {
		t.Errorf("no Idempotency-Key: %d", w.Code)
	}
	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/sessions/k1.s:delete", nil), time.Minute)
	if w := serve(handler, r); w.Code != http.StatusNotFound {
		t.Errorf("an unknown action: %d", w.Code)
	}
	r, _ = asPerson(t, httptest.NewRequest(http.MethodGet, "/v1/me/sessions", nil), time.Minute)
	if w := serve(meHandler(t, &stubSelf{err: keycloak.ErrUnavailable}), r); w.Code != http.StatusServiceUnavailable {
		t.Errorf("the kernel failing: %d", w.Code)
	}
	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/sessions:terminate-all", nil), time.Minute)
	if w := serve(meHandler(t, &stubSelf{err: securitystate.ErrState}), r); w.Code != http.StatusConflict {
		t.Errorf("a suspended caller: %d", w.Code)
	}
}

func TestTheSelfHandlerNeedsItsDependencies(t *testing.T) {
	if _, err := httpapi.NewMe(nil, time.Minute); err == nil {
		t.Error("a handler without a service was built")
	}
	if _, err := httpapi.NewMe(&stubSelf{}, 0); err == nil {
		t.Error("a handler without a step-up age was built")
	}
}

// Enrolling needs the level binding requires, recently: aal1 for a first second factor, aal2 once
// the person holds one (NIST SP 800-63B-4 4.1.2.1).
func TestEnrollingNeedsTheLevelBindingRequires(t *testing.T) {
	for name, c := range map[string]struct {
		level, acr string
		age        time.Duration
		status     int
	}{
		"a first factor at aal1":         {"aal1", "aal1", time.Minute, http.StatusOK},
		"a second at aal1":               {"aal2", "aal1", time.Minute, http.StatusUnauthorized},
		"a second at aal2":               {"aal2", httpapi.AcrAAL2, time.Minute, http.StatusOK},
		"a second at aal2, but long ago": {"aal2", httpapi.AcrAAL2, time.Hour, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &stubSelf{level: c.level}
			r, person := asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/authenticators:enroll",
				strings.NewReader(`{"type":"totp"}`)), c.age)
			r = r.WithContext(httpapi.WithAssurance(r.Context(), c.acr, time.Now().Add(-c.age)))
			w := serve(meHandler(t, stub), r)
			if w.Code != c.status {
				t.Fatalf("%d, want %d: %s", w.Code, c.status, w.Body)
			}
			if c.status == http.StatusOK && (!strings.Contains(w.Body.String(), `"action":"CONFIGURE_TOTP"`) || stub.caller != person) {
				t.Errorf("body %s, caller %s", w.Body, stub.caller)
			}
			if c.status == http.StatusUnauthorized &&
				!strings.Contains(w.Header().Get("WWW-Authenticate"), `acr_values="`+c.level+`"`) {
				t.Errorf("challenge %q; want the level %s", w.Header().Get("WWW-Authenticate"), c.level)
			}
		})
	}
	r, _ := asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/authenticators:enroll", strings.NewReader(`{}`)), time.Minute)
	if w := serve(meHandler(t, &stubSelf{}), r); w.Code != http.StatusBadRequest {
		t.Errorf("no type: %d", w.Code)
	}
}
