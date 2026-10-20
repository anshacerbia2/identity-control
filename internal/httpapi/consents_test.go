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
	"github.com/anshacerbia2/identity-control/internal/securitystate"
)

type stubConsents struct{ caller id.UUID }

func (s *stubConsents) MyConsents(_ context.Context, principal id.UUID) ([]securitystate.MyConsent, error) {
	s.caller = principal
	lifetime := 900
	return []securitystate.MyConsent{{SecurityRef: "k1.c", Client: "partner-web", Scopes: []string{"scnehaux-external"},
		AccessTokenLifetime: &lifetime}}, nil
}

func consentHandler(t *testing.T, stub *stubSelf, consents *stubConsents) http.Handler {
	t.Helper()
	me, err := httpapi.NewMe(stub, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if consents != nil {
		me.UseConsents(consents)
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

// A person lists their own consents and withdraws one, as a self command with no reason and no
// step-up (TDD-identity-control-005 2.13.0, slice 3b).
func TestAPersonListsAndWithdrawsTheirConsents(t *testing.T) {
	consents := &stubConsents{}
	r, person := asPerson(t, httptest.NewRequest(http.MethodGet, "/v1/me/consents", nil), time.Hour)
	w := serve(consentHandler(t, &stubSelf{}, consents), r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"access_token_lifetime_seconds":900`) ||
		consents.caller != person {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}

	stub := &stubSelf{}
	r, person = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/consents/k1.c:withdraw", nil), time.Hour)
	w = serve(consentHandler(t, stub, consents), r)
	c := stub.submitted
	if w.Code != http.StatusOK || c == nil || !c.Self || c.Type != securitystate.TypeConsentWithdraw || c.Subject != person ||
		c.Ref != "k1.c" || c.Reason != "" {
		t.Fatalf("withdraw: %d %s, submitted %+v", w.Code, w.Body, c)
	}
	r, _ = asPerson(t, httptest.NewRequest(http.MethodPost, "/v1/me/consents/k1.c:grant", nil), time.Hour)
	if w := serve(consentHandler(t, &stubSelf{}, consents), r); w.Code != http.StatusNotFound {
		t.Errorf("an unknown consent action answered %d", w.Code)
	}
	// Without a consent service the routes are not mounted.
	r, _ = asPerson(t, httptest.NewRequest(http.MethodGet, "/v1/me/consents", nil), time.Hour)
	if w := serve(consentHandler(t, &stubSelf{}, nil), r); w.Code == http.StatusOK {
		t.Errorf("the consent list was served with no consent service")
	}
}
