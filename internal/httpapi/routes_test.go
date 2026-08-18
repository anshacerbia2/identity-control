package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
)

// stubProber reports a configured reachability outcome and counts calls.
type stubProber struct {
	err   error
	calls int
}

func (s *stubProber) Ping(context.Context) error {
	s.calls++
	return s.err
}

func surface(t *testing.T, prober httpapi.Prober) httpapi.Surface {
	t.Helper()
	handler, err := httpapi.NewPrincipals(&stubProvisioner{
		response: provisioning.Response{PrincipalID: mustUUID(t)},
	}, realm)
	if err != nil {
		t.Fatalf("NewPrincipals: %v", err)
	}
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: handler, Database: prober})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	return built
}

// routes mounts the surface the way the composition root does, so these tests exercise the
// pattern precedence between the two halves and not just each half in isolation.
func routes(t *testing.T, prober httpapi.Prober) http.Handler {
	t.Helper()
	identity := func(next http.Handler) http.Handler { return next }
	return surface(t, prober).Mount(identity, identity)
}

// TestLivenessTouchesNoDependency is the property that keeps a database outage from becoming a
// restart storm. An orchestrator that restarts every replica during an outage a restart cannot
// fix has converted a degradation into an outage.
func TestLivenessTouchesNoDependency(t *testing.T) {
	prober := &stubProber{err: errors.New("database is down")}

	w := httptest.NewRecorder()
	routes(t, prober).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 even while the database is unreachable", w.Code)
	}
	if prober.calls != 0 {
		t.Errorf("liveness probed the database %d times, want 0", prober.calls)
	}
}

// TestReadinessFailsWhenTheDatabaseIsUnreachable is the other half. A replica that cannot reach
// the Control Database can serve nothing and belongs out of the load balancer rather than
// returning errors to callers.
func TestReadinessFailsWhenTheDatabaseIsUnreachable(t *testing.T) {
	prober := &stubProber{err: errors.New("database is down")}

	w := httptest.NewRecorder()
	routes(t, prober).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	if prober.calls != 1 {
		t.Errorf("readiness probed the database %d times, want 1", prober.calls)
	}
}

func TestReadinessSucceedsWhenTheDatabaseIsReachable(t *testing.T) {
	prober := &stubProber{}

	w := httptest.NewRecorder()
	routes(t, prober).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestMutationFailsClosedWithoutAuthentication states the deployed behaviour of this increment.
// No authentication middleware exists yet, so the route is reachable and refuses. That is the
// correct posture under EAD-006 §8, and a permissive development mode is deliberately not
// offered: a permissive path that exists in one environment reaches production.
func TestMutationFailsClosedWithoutAuthentication(t *testing.T) {
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/principals",
		strings.NewReader(`{"username":"operator","subject_type":"human"}`))
	request.Header.Set(httpapi.IdempotencyHeader, "key-0001")

	routes(t, &stubProber{}).ServeHTTP(w, request)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestMutationSucceedsOnceACallerIsAuthenticated proves the route is wired rather than merely
// present, by supplying the context value an authentication middleware will set.
func TestMutationSucceedsOnceACallerIsAuthenticated(t *testing.T) {
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/principals",
		strings.NewReader(`{"username":"operator","subject_type":"human"}`))
	request.Header.Set(httpapi.IdempotencyHeader, "key-0001")
	request = request.WithContext(httpapi.WithCallerScope(request.Context(), "svc:admin-api"))

	routes(t, &stubProber{}).ServeHTTP(w, request)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: %s", w.Code, w.Body.String())
	}
}

// TestMethodAndPathAreExact guards against a route matching more than it should. A mux pattern
// that accepted GET on the creation path would expose creation to a link.
func TestMethodAndPathAreExact(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/principals"},
		{http.MethodPost, "/healthz"},
		{http.MethodPost, "/readyz"},
		{http.MethodPost, "/v1/principals/extra"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			routes(t, &stubProber{}).ServeHTTP(w,
				httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
			if w.Code == http.StatusOK || w.Code == http.StatusCreated {
				t.Errorf("status = %d; the route matched a request it should not", w.Code)
			}
		})
	}
}

// TestProbesAreNotBehindAuthentication is a regression test for an outage this repository
// actually produced: `chain(routes)` wrapped one mux, so the authentication middleware answered
// 401 on /readyz and the replica never entered service. The property is stated in terms of a
// probe chain that authenticates nothing and an api chain that rejects everything, because that
// is the difference the split exists to make.
func TestProbesAreNotBehindAuthentication(t *testing.T) {
	probeChain := func(next http.Handler) http.Handler { return next }
	apiChain := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	handler := surface(t, &stubProber{}).Mount(probeChain, apiChain)

	for _, path := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200; the probe went through the authenticated chain", path, w.Code)
		}
	}

	// The other direction matters as much. A split that let an API route reach the probe chain
	// would be an unauthenticated mutation endpoint.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/principals", strings.NewReader("{}")))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("POST /v1/principals = %d, want 401; the route escaped the authenticated chain", w.Code)
	}
}

func TestRoutesRejectsMissingDependencies(t *testing.T) {
	handler, err := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	if err != nil {
		t.Fatalf("NewPrincipals: %v", err)
	}

	if _, err := httpapi.Routes(httpapi.RoutesConfig{Database: &stubProber{}}); err == nil {
		t.Error("Routes accepted a nil Principal handler")
	}
	if _, err := httpapi.Routes(httpapi.RoutesConfig{Principals: handler}); err == nil {
		t.Error("Routes accepted a nil database prober")
	}
}
