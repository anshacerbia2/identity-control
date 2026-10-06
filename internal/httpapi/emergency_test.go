package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

type stubValidator struct {
	report []providerauthority.EmergencyValidation
}

func (s stubValidator) EmergencyValidation(context.Context, time.Time) ([]providerauthority.EmergencyValidation, error) {
	return s.report, nil
}

// The emergency grant validation report is a provider's, and names each grant's last use
// (ADR-ORG-002 §5.2).
func TestTheEmergencyValidationReportIsAProvidersAndNamesEachUse(t *testing.T) {
	registrations, err := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	if err != nil {
		t.Fatal(err)
	}
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	grant, holder := mustUUID(t), mustUUID(t)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Database: &stubProber{},
		EmergencyGrants: stubValidator{report: []providerauthority.EmergencyValidation{
			{GrantID: grant, PrincipalID: holder, HeldSince: time.Now().Add(-100 * 24 * time.Hour), Overdue: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	handler := built.Mount(identity, identity)
	const path = "/v1/provider-grants:emergency-validation"

	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, path, nil), mustUUID(t))); w.Code != http.StatusForbidden {
		t.Errorf("an owner answered %d, want 403", w.Code)
	}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, path, nil))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "a drill")
	w := serve(handler, r)
	if w.Code != http.StatusOK {
		t.Fatalf("a provider answered %d: %s", w.Code, w.Body)
	}
	var body struct {
		Scope  string `json:"scope"`
		Days   int    `json:"validation_period_days"`
		Grants []struct {
			GrantID    string  `json:"grant_id"`
			LastUsedAt *string `json:"last_used_at"`
			Overdue    bool    `json:"overdue"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Scope != providerauthority.Scope || body.Days != 90 || len(body.Grants) != 1 ||
		body.Grants[0].GrantID != grant.String() || body.Grants[0].LastUsedAt != nil || !body.Grants[0].Overdue {
		t.Errorf("the report reads %+v", body)
	}
}
