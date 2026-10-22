package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
)

type stubCeremony struct {
	err      error
	reviewed *provisioning.CeremonyReviewRequest
}

func (s *stubCeremony) Ceremony(context.Context) (provisioning.CeremonyView, error) {
	return provisioning.CeremonyView{Operator: "Operator", Witness: "Witness", Reviews: []provisioning.CeremonyReview{}}, s.err
}

func (s *stubCeremony) ReviewCeremony(_ context.Context, req provisioning.CeremonyReviewRequest) (provisioning.CeremonyReview, error) {
	s.reviewed = &req
	return provisioning.CeremonyReview{Reviewer: req.Reviewer, Outcome: req.Outcome}, s.err
}

func ceremonyRoutes(t *testing.T, stub *stubCeremony) http.Handler {
	t.Helper()
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Database: &stubProber{}, Ceremony: stub})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// A provider reads the ceremony's record, with its witness, and records a review under its own
// Principal, the statement in the reason header (STD-IAM-001 2.9.0 §3.10).
func TestAProviderReadsAndReviewsTheCeremonyRecord(t *testing.T) {
	stub := &stubCeremony{}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/bootstrap-ceremony", nil))
	if w := serve(t, ceremonyRoutes(t, stub), r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"witness":"Witness"`) {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}
	r, reviewer := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/bootstrap-ceremony:review",
		strings.NewReader(`{"reviewer":"Security Reviewer","outcome":"satisfactory"}`)))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "record matches change ticket 7")
	if w := serve(t, ceremonyRoutes(t, stub), r); w.Code != http.StatusCreated {
		t.Fatalf("review: %d %s", w.Code, w.Body)
	}
	if stub.reviewed == nil || stub.reviewed.RecordedBy != reviewer || stub.reviewed.Statement != "record matches change ticket 7" ||
		stub.reviewed.Reviewer != "Security Reviewer" || stub.reviewed.Correlation == "" {
		t.Errorf("reviewed %+v", stub.reviewed)
	}
}

func TestACeremonyReviewRefusesWhatItCannotRecord(t *testing.T) {
	for name, c := range map[string]struct {
		reason, body string
		err          error
		want         int
	}{
		"no statement":        {"", `{"reviewer":"R","outcome":"satisfactory"}`, nil, http.StatusBadRequest},
		"no reviewer":         {"why", `{"outcome":"satisfactory"}`, nil, http.StatusBadRequest},
		"not independent":     {"why", `{"reviewer":"Operator","outcome":"satisfactory"}`, provisioning.ErrReviewerNotIndependent, http.StatusConflict},
		"an unknown outcome":  {"why", `{"reviewer":"R","outcome":"fine"}`, provisioning.ErrReviewInvalid, http.StatusBadRequest},
		"no ceremony":         {"why", `{"reviewer":"R","outcome":"findings"}`, provisioning.ErrNoCeremony, http.StatusNotFound},
		"an unknown property": {"why", `{"reviewer":"R","outcome":"findings","operator":"me"}`, nil, http.StatusBadRequest},
	} {
		r, _ := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/bootstrap-ceremony:review", strings.NewReader(c.body)))
		if c.reason != "" {
			r.Header.Set(httpapi.AdministrativeReasonHeader, c.reason)
		}
		if w := serve(t, ceremonyRoutes(t, &stubCeremony{err: c.err}), r); w.Code != c.want {
			t.Errorf("%s answered %d, want %d: %s", name, w.Code, c.want, w.Body)
		}
	}
	// An owner, not a provider, is refused before anything is read.
	owner, _ := id.NewV7()
	r := asOwner(httptest.NewRequest(http.MethodGet, "/v1/bootstrap-ceremony", nil), owner)
	if w := serve(t, ceremonyRoutes(t, &stubCeremony{}), r); w.Code != http.StatusForbidden {
		t.Errorf("an owner read the ceremony record: %d", w.Code)
	}
}
