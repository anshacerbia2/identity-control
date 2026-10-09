package httpapi_test

// The projection's operator routes at the transport (TDD-identity-control-002 2.5.0 §Operator Routes).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/tenantcontext"
)

type stubTenantOperator struct {
	err      error
	redriven id.UUID
	by       id.UUID
	reason   string
	class    string
	limit    int
	swept    int
	findings []tenantcontext.Finding
	listed   []tenantcontext.Unconverged
}

func (s *stubTenantOperator) Unconverged(context.Context) ([]tenantcontext.Unconverged, error) {
	return s.listed, s.err
}

func (s *stubTenantOperator) Findings(_ context.Context, class string, limit int) ([]tenantcontext.Finding, error) {
	s.class, s.limit = class, limit
	return s.findings, s.err
}

func (s *stubTenantOperator) Redrive(_ context.Context, tenant, by id.UUID, reason string) error {
	s.redriven, s.by, s.reason = tenant, by, reason
	return s.err
}

func (s *stubTenantOperator) Sweep(context.Context) (tenantcontext.SweepResult, error) {
	s.swept++
	return tenantcontext.SweepResult{Outcome: tenantcontext.OutcomeConverged, Marked: 3}, s.err
}

func tenantRoutes(t *testing.T, operator httpapi.TenantOperator) http.Handler {
	t.Helper()
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Database: &stubProber{}, TenantOperator: operator})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

func TestARedriveNamesTheTenantTheCallerAndTheReason(t *testing.T) {
	stub := &stubTenantOperator{}
	tenant := mustUUID(t)
	r, operator := asPrincipal(t, httptest.NewRequest(http.MethodPost,
		"/v1/projections/tenant-context/tenants/"+tenant.String()+":redrive", nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "the credential's roles are back")
	w := serve(tenantRoutes(t, stub), r)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"state":"pending"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if stub.redriven != tenant || stub.by != operator || stub.reason != "the credential's roles are back" {
		t.Errorf("re-drove %v by %v for %q", stub.redriven, stub.by, stub.reason)
	}

	for name, c := range map[string]struct {
		path, reason string
		err          error
		want         int
	}{
		"no reason":      {"/v1/projections/tenant-context/tenants/" + tenant.String() + ":redrive", "", nil, http.StatusBadRequest},
		"another action": {"/v1/projections/tenant-context/tenants/" + tenant.String() + ":delete", "why", nil, http.StatusNotFound},
		"a malformed id": {"/v1/projections/tenant-context/tenants/nope:redrive", "why", nil, http.StatusBadRequest},
		"unknown Tenant": {"/v1/projections/tenant-context/tenants/" + tenant.String() + ":redrive", "why", tenantcontext.ErrUnknownTenant, http.StatusNotFound},
		"database down":  {"/v1/projections/tenant-context/tenants/" + tenant.String() + ":redrive", "why", errors.New("down"), http.StatusInternalServerError},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, c.path, nil))
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(tenantRoutes(t, &stubTenantOperator{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestTheProjectionListingsAndTheSweepOnRequest(t *testing.T) {
	stub := &stubTenantOperator{listed: []tenantcontext.Unconverged{{TenantID: mustUUID(t), State: "unresolved"}}}
	handler := tenantRoutes(t, stub)

	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/projections/tenant-context:unconverged", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"unresolved"`) {
		t.Errorf("unconverged answered %d: %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/projections/tenant-context:findings?class=extra_member&limit=20", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || stub.class != "extra_member" || stub.limit != 20 {
		t.Errorf("findings answered %d with class %q, limit %d", w.Code, stub.class, stub.limit)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/projections/tenant-context:findings?limit=0", nil))
	if w := serve(handler, r); w.Code != http.StatusBadRequest {
		t.Errorf("a limit of 0 answered %d", w.Code)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/projections/tenant-context:findings?class=x", nil))
	if w := serve(tenantRoutes(t, &stubTenantOperator{err: tenantcontext.ErrUnknownClass}), r); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown class answered %d", w.Code)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/projections/tenant-context:sweep", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || stub.swept != 1 || !strings.Contains(w.Body.String(), `"outcome":"converged"`) {
		t.Errorf("a sweep on request answered %d: %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/projections/tenant-context:sweep", nil))
	if w := serve(tenantRoutes(t, &stubTenantOperator{err: errors.New("kernel down")}), r); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a failed sweep answered %d", w.Code)
	}
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/projections/tenant-context:unconverged", nil),
		httptest.NewRequest(http.MethodGet, "/v1/projections/tenant-context:findings", nil),
		httptest.NewRequest(http.MethodPost, "/v1/projections/tenant-context:sweep", nil),
	} {
		if w := serve(handler, r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a caller answered %d", r.Method, r.URL.Path, w.Code)
		}
	}
}
