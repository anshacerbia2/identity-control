package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/registration"
	"github.com/anshacerbia2/identity-control/internal/workload"
)

type stubWorkloadService struct {
	err        error
	created    *workload.CreateRequest
	reassigned *workload.ReassignRequest
	lifecycle  map[string]workload.LifecycleRequest
	reviewed   *workload.ReviewRequest
}

func (s *stubWorkloadService) act(action string, req workload.LifecycleRequest) (workload.Workload, error) {
	if s.lifecycle == nil {
		s.lifecycle = map[string]workload.LifecycleRequest{}
	}
	s.lifecycle[action] = req
	if s.err != nil {
		return workload.Workload{}, s.err
	}
	return workload.Workload{PrincipalID: req.PrincipalID, State: action}, nil
}

func (s *stubWorkloadService) Suspend(_ context.Context, req workload.LifecycleRequest) (workload.Workload, error) {
	return s.act("suspend", req)
}

func (s *stubWorkloadService) Restore(_ context.Context, req workload.LifecycleRequest) (workload.Workload, error) {
	return s.act("restore", req)
}

func (s *stubWorkloadService) Retire(_ context.Context, req workload.LifecycleRequest) (workload.Workload, error) {
	return s.act("retire", req)
}

func (s *stubWorkloadService) Create(_ context.Context, req workload.CreateRequest) (workload.Workload, error) {
	s.created = &req
	if s.err != nil {
		return workload.Workload{}, s.err
	}
	principalID, _ := id.NewV7()
	return workload.Workload{PrincipalID: principalID, ClientKey: req.ClientKey, Owner: req.Owner, State: workload.StateActive}, nil
}

func (s *stubWorkloadService) Get(_ context.Context, principalID id.UUID) (workload.Workload, error) {
	if s.err != nil {
		return workload.Workload{}, s.err
	}
	return workload.Workload{PrincipalID: principalID, ClientKey: "nightly-job", State: workload.StateActive}, nil
}

func (s *stubWorkloadService) Reassign(_ context.Context, req workload.ReassignRequest) (workload.Workload, error) {
	s.reassigned = &req
	if s.err != nil {
		return workload.Workload{}, s.err
	}
	return workload.Workload{PrincipalID: req.PrincipalID, Owner: req.NewOwner, State: workload.StateActive}, nil
}

func (s *stubWorkloadService) Rebuild(_ context.Context, req workload.LifecycleRequest) (workload.Workload, error) {
	return s.act("rebuild", req)
}

func (s *stubWorkloadService) Review(_ context.Context, req workload.ReviewRequest) (workload.Workload, error) {
	s.reviewed = &req
	if s.err != nil {
		return workload.Workload{}, s.err
	}
	return workload.Workload{PrincipalID: req.PrincipalID, State: workload.StateActive}, nil
}

func (s *stubWorkloadService) Sweep(context.Context) (workload.SweepResult, error) {
	return workload.SweepResult{Orphaned: 1, Unused: 2}, s.err
}

func (s *stubWorkloadService) Orphaned(context.Context) ([]workload.Condition, error) {
	return []workload.Condition{{ClientKey: "orphaned-job", Stage: workload.StageEscalated}}, s.err
}

func (s *stubWorkloadService) Unused(context.Context) ([]workload.Condition, error) {
	return []workload.Condition{{ClientKey: "idle-job"}}, s.err
}

func (s *stubWorkloadService) ReviewsOverdue(context.Context) ([]workload.Condition, error) {
	return []workload.Condition{{ClientKey: "unreviewed-job"}}, s.err
}

func stubWorkloads(t *testing.T) *httpapi.Workloads {
	t.Helper()
	handler, err := httpapi.NewWorkloads(&stubWorkloadService{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func workloadHandler(t *testing.T, service *stubWorkloadService) http.Handler {
	t.Helper()
	workloads, err := httpapi.NewWorkloads(service)
	if err != nil {
		t.Fatal(err)
	}
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: workloads, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

func workloadBody(owner string) string {
	return fmt.Sprintf(`{"display_name":"Nightly payroll export","purpose":"Exports approved payroll to the bank each night",
	  "workload_type":"job","owner_principal_id":%q,"team_reference":"payroll-platform","client_key":"nightly-job",
	  "application_ref":"payroll","audience":["payroll-api"],"public_key":{"kty":"RSA","n":"AQAB","e":"AQAB"}}`, owner)
}

// The caller, not the body, is the creating Principal, and the key is claimed under the caller.
func TestAWorkloadIsCreatedUnderTheCaller(t *testing.T) {
	service := &stubWorkloadService{}
	owner := mustUUID(t)
	r, principal := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(workloadBody(owner.String()))))
	r.Header.Set(httpapi.IdempotencyHeader, "workload-1")
	w := serve(workloadHandler(t, service), r)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"client_key":"nightly-job"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	got := service.created
	if got.CreatedBy != principal || got.CallerScope != "principal:"+principal.String() || got.IdempotencyKey != "workload-1" ||
		got.Owner != owner || got.WorkloadType != "job" || got.TeamReference != "payroll-platform" ||
		!strings.Contains(string(got.PublicKey), `"kty":"RSA"`) || len(got.Audience) != 1 {
		t.Errorf("request = %+v", got)
	}
}

func TestAWorkloadCreationRefusesWhatItCannotRead(t *testing.T) {
	owner := mustUUID(t).String()
	for name, c := range map[string]struct {
		body string
		key  string
	}{
		"no Idempotency-Key":           {workloadBody(owner), ""},
		"an unparseable owner":         {workloadBody("the payroll lead"), "k"},
		"an unknown field":             {`{"display_name":"x","client_secret":"s"}`, "k"},
		"a malformed document":         {`{`, "k"},
		"a creating Principal in body": {`{"display_name":"x","created_by":"someone"}`, "k"},
	} {
		service := &stubWorkloadService{}
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(c.body)))
		if c.key != "" {
			r.Header.Set(httpapi.IdempotencyHeader, c.key)
		}
		if w := serve(workloadHandler(t, service), r); w.Code != http.StatusBadRequest || service.created != nil {
			t.Errorf("%s answered %d", name, w.Code)
		}
	}
}

func TestAWorkloadCreationMapsTheServicesErrors(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"invalid":             {workload.ErrInvalid, http.StatusBadRequest},
		"an agent":            {workload.ErrAgentNotBuilt, http.StatusBadRequest},
		"an ineligible owner": {workload.ErrOwnerNotEligible, http.StatusBadRequest},
		"a private key":       {registration.ErrPrivateKey, http.StatusBadRequest},
		"no workload scope":   {registration.ErrScopeUndeclared, http.StatusBadRequest},
		"a held client_key":   {workload.ErrRefused, http.StatusConflict},
		"a registered key":    {registration.ErrKeyInUse, http.StatusConflict},
		"a reused key":        {idempotency.ErrConflict, http.StatusConflict},
		"in progress":         {idempotency.ErrInProgress, http.StatusConflict},
		"kernel down":         {keycloak.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(workloadBody(mustUUID(t).String()))))
		r.Header.Set(httpapi.IdempotencyHeader, "k")
		if w := serve(workloadHandler(t, &stubWorkloadService{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestAWorkloadIsReadByIdentifier(t *testing.T) {
	principalID := mustUUID(t)
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/workloads/"+principalID.String(), nil))
	if w := serve(workloadHandler(t, &stubWorkloadService{}), r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), principalID.String()) {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/workloads/"+principalID.String(), nil))
	if w := serve(workloadHandler(t, &stubWorkloadService{err: workload.ErrNotFound}), r); w.Code != http.StatusNotFound {
		t.Errorf("an unknown workload answered %d", w.Code)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/workloads/nope", nil))
	if w := serve(workloadHandler(t, &stubWorkloadService{}), r); w.Code != http.StatusBadRequest {
		t.Errorf("a malformed identifier answered %d", w.Code)
	}
}

// A reassignment carries the new owner, the caller, and the caller's reason, which it cannot do
// without.
func TestAWorkloadIsReassignedWithAReason(t *testing.T) {
	principalID, owner := mustUUID(t), mustUUID(t)
	path := "/v1/workloads/" + principalID.String() + ":reassign"
	body := fmt.Sprintf(`{"owner_principal_id":%q}`, owner)
	service := &stubWorkloadService{}
	r, caller := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "the previous owner moved to another team")
	if w := serve(workloadHandler(t, service), r); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := service.reassigned; got.PrincipalID != principalID || got.NewOwner != owner || got.ChangedBy != caller ||
		got.Reason != "the previous owner moved to another team" {
		t.Errorf("reassignment = %+v", got)
	}

	for name, c := range map[string]struct {
		path, body, reason string
		want               int
	}{
		"no reason":         {path, body, "", http.StatusBadRequest},
		"an unknown action": {"/v1/workloads/" + principalID.String() + ":delete", body, "r", http.StatusNotFound},
		"no owner":          {path, `{}`, "r", http.StatusBadRequest},
		"a malformed id":    {"/v1/workloads/nope:reassign", body, "r", http.StatusBadRequest},
	} {
		service := &stubWorkloadService{}
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body)))
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(workloadHandler(t, service), r); w.Code != c.want || service.reassigned != nil {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"an ineligible owner": {workload.ErrOwnerNotEligible, http.StatusBadRequest},
		"a retired workload":  {workload.ErrInvalidTransition, http.StatusConflict},
		"an unknown workload": {workload.ErrNotFound, http.StatusNotFound},
		"the kernel is down":  {keycloak.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		if w := serve(workloadHandler(t, &stubWorkloadService{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

// The lifecycle actions (TDD-identity-control-004 §Suspension, Restoration, and Retirement) take the
// workload, the caller and the reason, and map the service's refusals.
func TestAWorkloadIsSuspendedRestoredAndRetiredWithAReason(t *testing.T) {
	principalID := mustUUID(t)
	for _, action := range []string{"suspend", "restore", "retire"} {
		path := "/v1/workloads/" + principalID.String() + ":" + action
		service := &stubWorkloadService{}
		r, caller := asPrincipal(t, httptest.NewRequest(http.MethodPost, path, nil))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "the job is decommissioned")
		if w := serve(workloadHandler(t, service), r); w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", action, w.Code, w.Body)
		}
		if got := service.lifecycle[action]; got.PrincipalID != principalID || got.ChangedBy != caller ||
			got.Reason != "the job is decommissioned" {
			t.Errorf("%s = %+v", action, got)
		}

		unreasoned := &stubWorkloadService{}
		r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, path, nil))
		if w := serve(workloadHandler(t, unreasoned), r); w.Code != http.StatusBadRequest || unreasoned.lifecycle != nil {
			t.Errorf("%s without a reason answered %d, want 400", action, w.Code)
		}
	}
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"a workload in the wrong state": {workload.ErrInvalidTransition, http.StatusConflict},
		"an owner that has left":        {workload.ErrOwnerNotEligible, http.StatusBadRequest},
		"a client gone from the kernel": {registration.ErrInvalidTransition, http.StatusConflict},
		"an unknown workload":           {workload.ErrNotFound, http.StatusNotFound},
		"the kernel is down":            {keycloak.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/workloads/"+principalID.String()+":restore", nil))
		r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		if w := serve(workloadHandler(t, &stubWorkloadService{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}
}

func TestEveryWorkloadRouteRequiresAnAuthenticatedPrincipal(t *testing.T) {
	service := &stubWorkloadService{}
	handler := workloadHandler(t, service)
	principalID := mustUUID(t).String()
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(workloadBody(principalID))),
		httptest.NewRequest(http.MethodGet, "/v1/workloads/"+principalID, nil),
		httptest.NewRequest(http.MethodPost, "/v1/workloads/"+principalID+":reassign", strings.NewReader(`{}`)),
		httptest.NewRequest(http.MethodPost, "/v1/workloads/"+principalID+":suspend", nil),
		httptest.NewRequest(http.MethodPost, "/v1/workloads/"+principalID+":retire", nil),
	} {
		if w := serve(handler, r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a caller, want 401", r.Method, r.URL.Path, w.Code)
		}
	}
	if service.created != nil || service.reassigned != nil {
		t.Error("an unauthenticated request reached the workload service")
	}
}

func TestTheWorkloadHandlerNeedsAService(t *testing.T) {
	if _, err := httpapi.NewWorkloads(nil); err == nil {
		t.Error("a handler without a service was built")
	}
}

// The owner reviews its workload with a statement; anyone the service says is not the owner is
// answered 404, and an owner token reaches no other workload action (TDD-identity-control-004 1.5.0).
func TestAWorkloadIsReviewedByItsOwnerAlone(t *testing.T) {
	service := &stubWorkloadService{}
	handler := workloadHandler(t, service)
	target, owner := mustUUID(t), mustUUID(t)
	path := "/v1/workloads/" + target.String() + ":review"

	r := asOwner(httptest.NewRequest(http.MethodPost, path, nil), owner)
	if w := serve(handler, r); w.Code != http.StatusBadRequest || service.reviewed != nil {
		t.Errorf("a review without a statement answered %d", w.Code)
	}
	r = asOwner(httptest.NewRequest(http.MethodPost, path, nil), owner)
	r.Header.Set(httpapi.AdministrativeReasonHeader, "still needed: it exports payroll nightly")
	if w := serve(handler, r); w.Code != http.StatusOK {
		t.Fatalf("an owner's review answered %d: %s", w.Code, w.Body)
	}
	if got := service.reviewed; got == nil || got.PrincipalID != target || got.ReviewedBy != owner ||
		got.Statement != "still needed: it exports payroll nightly" {
		t.Errorf("review = %+v", got)
	}

	refusing := workloadHandler(t, &stubWorkloadService{err: workload.ErrNotOwner})
	r = asOwner(httptest.NewRequest(http.MethodPost, path, nil), owner)
	r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
	if w := serve(refusing, r); w.Code != http.StatusNotFound {
		t.Errorf("a review by another answered %d, want 404", w.Code)
	}

	for _, action := range []string{"suspend", "rebuild", "reassign"} {
		r := asOwner(httptest.NewRequest(http.MethodPost, "/v1/workloads/"+target.String()+":"+action, strings.NewReader(`{}`)), owner)
		r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
		if w := serve(handler, r); w.Code != http.StatusForbidden {
			t.Errorf("an owner's :%s answered %d, want 403", action, w.Code)
		}
	}
}

// A provider rebuilds a workload's client with a reason, runs the sweep, and reads what it found.
func TestAProviderRebuildsSweepsAndListsWorkloads(t *testing.T) {
	service := &stubWorkloadService{}
	handler := workloadHandler(t, service)
	target := mustUUID(t)
	r, caller := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/workloads/"+target.String()+":rebuild", nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "its client was deleted in the console")
	if w := serve(handler, r); w.Code != http.StatusOK {
		t.Fatalf("rebuild answered %d: %s", w.Code, w.Body)
	}
	if got := service.lifecycle["rebuild"]; got.PrincipalID != target || got.ChangedBy != caller {
		t.Errorf("rebuild = %+v", got)
	}
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/workloads:sweep", nil))
	if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"orphaned":1`) {
		t.Errorf("sweep answered %d: %s", w.Code, w.Body)
	}
	for path, want := range map[string]string{"/v1/workloads:orphaned": `"stage":"escalated"`,
		"/v1/workloads:unused": "idle-job", "/v1/workloads:reviews-overdue": "unreviewed-job"} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
		if w := serve(handler, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s answered %d: %s", path, w.Code, w.Body)
		}
	}
	failing := workloadHandler(t, &stubWorkloadService{err: workload.ErrClientPresent})
	r, _ = asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/workloads/"+target.String()+":rebuild", nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "r")
	if w := serve(failing, r); w.Code != http.StatusConflict {
		t.Errorf("a rebuild while the client exists answered %d, want 409", w.Code)
	}
}
