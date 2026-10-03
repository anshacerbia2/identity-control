package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/securitystate"
)

type stubCommander struct {
	err       error
	state     string
	submitted *securitystate.Command
}

func (s *stubCommander) Submit(_ context.Context, cmd securitystate.Command) (securitystate.Operation, error) {
	s.submitted = &cmd
	if s.err != nil {
		return securitystate.Operation{}, s.err
	}
	operationID, _ := id.NewV7()
	state := s.state
	if state == "" {
		state = securitystate.StateApplied
	}
	return securitystate.Operation{OperationID: operationID, PrincipalID: cmd.Subject, Type: cmd.Type, State: state}, nil
}

func (s *stubCommander) Get(_ context.Context, operationID id.UUID) (securitystate.Operation, error) {
	if s.err != nil {
		return securitystate.Operation{}, s.err
	}
	return securitystate.Operation{OperationID: operationID, State: securitystate.StateApplied}, nil
}

func securityHandler(t *testing.T, stub *stubCommander) http.Handler {
	t.Helper()
	security, err := httpapi.NewSecurity(stub, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Security: security, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// command builds a provider's command request, authenticated authAge ago.
func command(t *testing.T, path string, authAge time.Duration) (*http.Request, id.UUID) {
	t.Helper()
	r, caller := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"expected_version":3}`)))
	r.Header.Set("Idempotency-Key", "k-1")
	r.Header.Set(httpapi.AdministrativeReasonHeader, "incident 42: credential stuffing")
	return r.WithContext(httpapi.WithAssurance(r.Context(), "1", time.Now().Add(-authAge))), caller
}

func TestEachSecurityCommandReachesTheServiceAsItsType(t *testing.T) {
	subject := mustUUID(t).String()
	for path, opType := range map[string]string{
		"/v1/principals/" + subject + ":suspend":                         securitystate.TypeSuspend,
		"/v1/principals/" + subject + ":restore":                         securitystate.TypeRestore,
		"/v1/principals/" + subject + "/sessions:terminate-all":          securitystate.TypeTerminateAll,
		"/v1/principals/" + subject + "/authenticators/k1.sealed:revoke": securitystate.TypeRevoke,
	} {
		stub := &stubCommander{}
		r, caller := command(t, path, time.Minute)
		w := serve(securityHandler(t, stub), r)
		if w.Code != http.StatusOK || stub.submitted == nil {
			t.Fatalf("%s: status %d: %s", path, w.Code, w.Body)
		}
		c := stub.submitted
		if c.Type != opType || c.Subject.String() != subject || c.Actor.Principal != caller || c.ExpectedVersion != 3 ||
			c.Reason != "incident 42: credential stuffing" || c.IdempotencyKey != "k-1" ||
			!strings.HasPrefix(c.Actor.Assurance, "acr=1;auth_time=") || c.Actor.Correlation == "" {
			t.Errorf("%s: submitted %+v", path, c)
		}
		if (opType == securitystate.TypeRevoke) != (c.Ref == "k1.sealed") {
			t.Errorf("%s: reference %q", path, c.Ref)
		}
	}
}

func TestARelinkIsStillThePrincipalPaths(t *testing.T) {
	stub := &stubCommander{}
	r, _ := command(t, "/v1/principals/"+mustUUID(t).String()+":relink", time.Minute)
	serve(securityHandler(t, stub), r)
	if stub.submitted != nil {
		t.Error("a relink reached the security commands")
	}
}

// Each refusal the design orders before anything is written, and none reaches the service.
func TestASecurityCommandIsRefusedBeforeTheService(t *testing.T) {
	subject := mustUUID(t).String()
	path := "/v1/principals/" + subject + ":suspend"
	for name, c := range map[string]struct {
		edit   func(r *http.Request, caller id.UUID) *http.Request
		status int
	}{
		"its own Principal": {func(r *http.Request, caller id.UUID) *http.Request {
			r2, _ := command(t, "/v1/principals/"+caller.String()+":suspend", time.Minute)
			return r2.WithContext(httpapi.WithCallerScope(r2.Context(), "principal:"+caller.String()))
		}, http.StatusForbidden},
		"no Idempotency-Key": {func(r *http.Request, _ id.UUID) *http.Request { r.Header.Del("Idempotency-Key"); return r },
			http.StatusBadRequest},
		"no reason": {func(r *http.Request, _ id.UUID) *http.Request {
			r.Header.Del(httpapi.AdministrativeReasonHeader)
			return r
		}, http.StatusBadRequest},
		"no expected_version": {func(r *http.Request, _ id.UUID) *http.Request {
			r2 := r.Clone(r.Context())
			r2.Body = http.NoBody
			return r2
		}, http.StatusBadRequest},
		"a malformed subject": {func(r *http.Request, _ id.UUID) *http.Request {
			r2, _ := command(t, "/v1/principals/nope:suspend", time.Minute)
			return r2
		}, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &stubCommander{}
			r, caller := command(t, path, time.Minute)
			w := serve(securityHandler(t, stub), c.edit(r, caller))
			if w.Code != c.status || stub.submitted != nil {
				t.Errorf("status %d, submitted %t; want %d and nothing submitted: %s", w.Code, stub.submitted != nil, c.status, w.Body)
			}
		})
	}
}

// RFC 9470 §3: an authentication older than the step-up age is a 401 naming the allowed age.
func TestAStaleAuthenticationIsAskedToStepUp(t *testing.T) {
	stub := &stubCommander{}
	r, _ := command(t, "/v1/principals/"+mustUUID(t).String()+":suspend", 6*time.Minute)
	w := serve(securityHandler(t, stub), r)
	challenge := w.Header().Get("WWW-Authenticate")
	if w.Code != http.StatusUnauthorized || !strings.Contains(challenge, `error="insufficient_user_authentication"`) ||
		!strings.Contains(challenge, "max_age=300") {
		t.Errorf("status %d, challenge %q", w.Code, challenge)
	}
	if stub.submitted != nil {
		t.Error("a stale authentication reached the service")
	}
}

func TestACommandStillRunningAnswers202WithItsOperation(t *testing.T) {
	stub := &stubCommander{state: securitystate.StateRetrying}
	r, _ := command(t, "/v1/principals/"+mustUUID(t).String()+":suspend", time.Minute)
	w := serve(securityHandler(t, stub), r)
	if w.Code != http.StatusAccepted || !strings.HasPrefix(w.Header().Get("Location"), "/v1/security-operations/") {
		t.Errorf("status %d, Location %q", w.Code, w.Header().Get("Location"))
	}
}

func TestSecurityErrorsMapToTheirStatus(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
	}{
		"incomplete":       {securitystate.ErrInvalid, http.StatusBadRequest},
		"itself":           {securitystate.ErrSelfAction, http.StatusForbidden},
		"absent":           {securitystate.ErrNotFound, http.StatusNotFound},
		"a workload":       {securitystate.ErrWorkload, http.StatusConflict},
		"a state":          {securitystate.ErrState, http.StatusConflict},
		"a version":        {securitystate.ErrVersion, http.StatusConflict},
		"a reused key":     {securitystate.ErrKeyReuse, http.StatusConflict},
		"a concurrent key": {securitystate.ErrInProgress, http.StatusConflict},
		"anything else":    {errors.New("database gone"), http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := command(t, "/v1/principals/"+mustUUID(t).String()+":suspend", time.Minute)
			if w := serve(securityHandler(t, &stubCommander{err: c.err}), r); w.Code != c.status {
				t.Errorf("status %d; want %d: %s", w.Code, c.status, w.Body)
			}
		})
	}
}

func TestAnOperationIsReadByAProvider(t *testing.T) {
	handler := securityHandler(t, &stubCommander{})
	path := "/v1/security-operations/" + mustUUID(t).String()
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"applied"`) {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, path, nil), mustUUID(t))); w.Code != http.StatusForbidden {
		t.Errorf("an owner read an operation: %d", w.Code)
	}
}

// Only a provider commands: an owner's token and no token are refused before the service.
func TestOnlyAProviderCommands(t *testing.T) {
	subject := mustUUID(t).String()
	for _, path := range []string{"/v1/principals/" + subject + ":suspend", "/v1/principals/" + subject + ":restore",
		"/v1/principals/" + subject + "/sessions:terminate-all", "/v1/principals/" + subject + "/authenticators/k1.x:revoke"} {
		stub := &stubCommander{}
		handler := securityHandler(t, stub)
		anonymous := serve(handler, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"expected_version":1}`)))
		owner := serve(handler, asOwner(httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"expected_version":1}`)), mustUUID(t)))
		if anonymous.Code != http.StatusUnauthorized || owner.Code != http.StatusForbidden || stub.submitted != nil {
			t.Errorf("%s: anonymous %d, owner %d, submitted %t", path, anonymous.Code, owner.Code, stub.submitted != nil)
		}
	}
}

func TestTheSecurityHandlerNeedsItsDependencies(t *testing.T) {
	if _, err := httpapi.NewSecurity(nil, time.Minute); err == nil {
		t.Error("a handler without a commander was built")
	}
	if _, err := httpapi.NewSecurity(&stubCommander{}, 0); err == nil {
		t.Error("a handler without a step-up age was built")
	}
}
