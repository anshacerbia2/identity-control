package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/kernelevents"
)

// These add to the route tests the exchanges the contract test (contract_test.go) found missing: a
// success or a refusal of a route that no other test sent a request to.

// Every route that acts for a caller answers a request with no caller as an RFC 9457 problem, the
// problem the specification documents for 401.
func TestARouteWithNoCallerAnswersTheDocumentedProblem(t *testing.T) {
	id := mustUUID(t).String()
	for _, c := range []struct {
		handler        http.Handler
		method, target string
	}{
		{registrarHandler(t, &stubRegistrar{}), http.MethodGet, "/v1/registrations/" + id + "/changes"},
		{registrarHandler(t, &stubRegistrar{}), http.MethodPost, "/v1/registrations/" + id + ":restore"},
		{meHandler(t, &stubSelf{}), http.MethodGet, "/v1/me/authenticators"},
		{meHandler(t, &stubSelf{}), http.MethodPost, "/v1/me/sessions/k1.s:terminate"},
		{meHandler(t, &stubSelf{}), http.MethodGet, "/v1/me/security-operations/" + id},
		{consentHandler(t, &stubSelf{}, &stubConsents{}), http.MethodGet, "/v1/me/consents"},
		{consentHandler(t, &stubSelf{}, &stubConsents{}), http.MethodPost, "/v1/me/consents/k1.c:withdraw"},
		{addressHandler(t, &stubAddresses{}), http.MethodGet, "/v1/me/notification-addresses"},
		{addressHandler(t, &stubAddresses{}), http.MethodPost, "/v1/me/notification-addresses/" + id + ":verify"},
		{securityHandler(t, &stubCommander{}), http.MethodGet, "/v1/security-operations:unresolved"},
		{investigationHandler(t, &stubInvestigator{}), http.MethodGet, "/v1/principals/" + id + "/notification-addresses"},
		{investigationHandler(t, &stubInvestigator{}), http.MethodGet, "/v1/principals/" + id + "/security-notifications"},
	} {
		w := serve(t, c.handler, httptest.NewRequest(c.method, c.target, strings.NewReader("{}")))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no caller answered %d, want 401: %s", c.method, c.target, w.Code, w.Body)
		}
	}
}

// A provider rejects a change and a registration request, as it approves them.
func TestAProviderRejectsAChangeAndARequest(t *testing.T) {
	registrar := &stubRegistrar{}
	handler := registrarHandler(t, registrar)
	registrationID, change, request := mustUUID(t), mustUUID(t), mustUUID(t)

	r, _ := asPrincipal(t, changeRequest(http.MethodPost,
		"/v1/registrations/"+registrationID.String()+"/changes/"+change.String()+":reject", ""))
	if w := serve(t, handler, r); w.Code != http.StatusOK {
		t.Errorf("a provider's :reject of a change answered %d: %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, changeRequest(http.MethodPost, "/v1/registration-requests/"+request.String()+":reject", ""))
	if w := serve(t, handler, r); w.Code != http.StatusOK {
		t.Errorf("a provider's :reject of a request answered %d: %s", w.Code, w.Body)
	}
}

type stubKernelEvents struct{ err error }

func (s stubKernelEvents) Sweep(context.Context) (kernelevents.Result, error) {
	return kernelevents.Result{Kinds: []kernelevents.KindResult{}}, s.err
}

func kernelEventsHandler(t *testing.T, sweeper httpapi.KernelEventSweeper) http.Handler {
	t.Helper()
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), KernelEvents: sweeper, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// A provider's sweep answers the kinds it swept; the kernel failing is a 503, and no caller a 401.
func TestTheKernelEventSweepAnswersWhatItSweptAndWhatStopsIt(t *testing.T) {
	for name, c := range map[string]struct {
		sweeper  stubKernelEvents
		provider bool
		want     int
	}{
		"swept":           {stubKernelEvents{}, true, http.StatusOK},
		"the kernel down": {stubKernelEvents{err: context.DeadlineExceeded}, true, http.StatusServiceUnavailable},
		"no caller":       {stubKernelEvents{}, false, http.StatusUnauthorized},
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/kernel-events:sweep", nil)
		if c.provider {
			r, _ = asPrincipal(t, r)
		}
		if w := serve(t, kernelEventsHandler(t, c.sweeper), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d: %s", name, w.Code, c.want, w.Body)
		}
	}
}
