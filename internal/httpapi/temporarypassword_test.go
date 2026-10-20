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

	"github.com/anshacerbia2/identity-control/internal/firstcredential"
	"github.com/anshacerbia2/identity-control/internal/httpapi"
)

type stubIssuer struct {
	err    error
	replay bool
	got    *firstcredential.Request
}

const issuedValue = "ABCDEFGHJKMNPQRSTVWXYZ01"

func (s *stubIssuer) Issue(_ context.Context, req firstcredential.Request) (firstcredential.Issuance, bool, error) {
	s.got = &req
	if s.err != nil {
		return firstcredential.Issuance{}, false, s.err
	}
	issuance, _ := id.NewV7()
	now := time.Now().UTC()
	issued := firstcredential.Issuance{IssuanceID: issuance, PrincipalID: req.Subject, IssuedBy: req.Actor.Principal,
		IssuedAt: now, LapsesAt: now.Add(24 * time.Hour)}
	if !s.replay {
		issued.Value = issuedValue
	}
	return issued, s.replay, nil
}

func temporaryPasswordHandler(t *testing.T, stub *stubIssuer) http.Handler {
	t.Helper()
	handler, err := httpapi.NewTemporaryPasswords(stub, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), TemporaryPasswords: handler, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

func issueRequest(t *testing.T, subject string, body string, authAge time.Duration) (*http.Request, id.UUID) {
	t.Helper()
	r, caller := asPrincipal(t, httptest.NewRequest(http.MethodPost, "/v1/principals/"+subject+":issue-temporary-password",
		strings.NewReader(body)))
	r.Header.Set("Idempotency-Key", "k-1")
	r.Header.Set(httpapi.AdministrativeReasonHeader, "first sign-in for a new colleague")
	return r.WithContext(httpapi.WithAssurance(r.Context(), httpapi.AcrAAL2, time.Now().Add(-authAge))), caller
}

// The value is shown once, never cached, and a retry answers the issuance without it (ADR-IAM-010 §5.1).
func TestATemporaryPasswordIsShownOnceAndNeverCached(t *testing.T) {
	subject := mustUUID(t).String()
	stub := &stubIssuer{}
	r, caller := issueRequest(t, subject, "", time.Minute)
	w := serve(temporaryPasswordHandler(t, stub), r)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"value":"`+issuedValue+`"`) {
		t.Fatalf("issue: %d %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control is %q; want no-store", got)
	}
	g := stub.got
	if g == nil || g.Subject.String() != subject || g.Actor.Principal != caller || g.IdempotencyKey != "k-1" ||
		g.Reason != "first sign-in for a new colleague" || !strings.HasPrefix(g.Actor.Assurance, "acr=aal2;auth_time=") ||
		g.Actor.Route == "" || g.Actor.Correlation == "" {
		t.Fatalf("issued as %+v", g)
	}

	replayed := &stubIssuer{replay: true}
	r, _ = issueRequest(t, subject, "{}", time.Minute)
	w = serve(temporaryPasswordHandler(t, replayed), r)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"value"`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("a retry answered %d %s, Cache-Control %q", w.Code, w.Body, w.Header().Get("Cache-Control"))
	}
}

func TestAnIssueIsRefusedBeforeTheServiceWithoutWhatItNeeds(t *testing.T) {
	subject := mustUUID(t).String()
	for name, c := range map[string]struct {
		build func() *http.Request
		want  int
	}{
		"an old authentication": {func() *http.Request { r, _ := issueRequest(t, subject, "", time.Hour); return r },
			http.StatusUnauthorized},
		"no reason": {func() *http.Request {
			r, _ := issueRequest(t, subject, "", time.Minute)
			r.Header.Del(httpapi.AdministrativeReasonHeader)
			return r
		}, http.StatusBadRequest},
		"no key": {func() *http.Request {
			r, _ := issueRequest(t, subject, "", time.Minute)
			r.Header.Del("Idempotency-Key")
			return r
		}, http.StatusBadRequest},
		"a chosen value": {func() *http.Request {
			r, _ := issueRequest(t, subject, `{"value":"chosen-by-the-provider"}`, time.Minute)
			return r
		}, http.StatusBadRequest},
		"a malformed principal_id": {func() *http.Request { r, _ := issueRequest(t, "not-an-id", "", time.Minute); return r },
			http.StatusBadRequest},
	} {
		stub := &stubIssuer{}
		// Served as is: serve() would supply a missing key.
		w := httptest.NewRecorder()
		temporaryPasswordHandler(t, stub).ServeHTTP(w, c.build())
		if w.Code != c.want || stub.got != nil {
			t.Errorf("%s: %d (service reached: %t); want %d", name, w.Code, stub.got != nil, c.want)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: a refusal is cacheable", name)
		}
	}
	// The step-up challenge names aal2 and the age, as RFC 9470 defines.
	r, _ := issueRequest(t, subject, "", time.Hour)
	w := serve(temporaryPasswordHandler(t, &stubIssuer{}), r)
	if challenge := w.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, `acr_values="aal2"`) ||
		!strings.Contains(challenge, "max_age=300") {
		t.Fatalf("the challenge is %q", challenge)
	}
	// A provider cannot issue for its own Principal.
	r, caller := issueRequest(t, subject, "", time.Minute)
	r2, _ := issueRequest(t, caller.String(), "", time.Minute)
	r2 = r2.WithContext(r.Context())
	if w := serve(temporaryPasswordHandler(t, &stubIssuer{}), r2); w.Code != http.StatusForbidden {
		t.Fatalf("an issue for the caller's own Principal answered %d", w.Code)
	}
}

func TestIssueRefusalsAreTold(t *testing.T) {
	subject := mustUUID(t).String()
	for err, c := range map[error]struct {
		status int
		detail string
	}{
		firstcredential.ErrCredentialEstablished: {http.StatusConflict, "credential-established"},
		firstcredential.ErrState:                 {http.StatusConflict, "active human"},
		firstcredential.ErrNotFound:              {http.StatusNotFound, ""},
		firstcredential.ErrSelf:                  {http.StatusForbidden, ""},
		firstcredential.ErrInvalid:               {http.StatusBadRequest, ""},
		firstcredential.ErrKeyReuse:              {http.StatusConflict, "Idempotency-Key"},
		firstcredential.ErrInProgress:            {http.StatusConflict, "in progress"},
		firstcredential.ErrUnavailable:           {http.StatusServiceUnavailable, ""},
		errors.New("boom"):                       {http.StatusInternalServerError, ""},
	} {
		r, _ := issueRequest(t, subject, "", time.Minute)
		w := serve(temporaryPasswordHandler(t, &stubIssuer{err: err}), r)
		if w.Code != c.status || !strings.Contains(w.Body.String(), c.detail) {
			t.Errorf("%v answered %d %s; want %d naming %q", err, w.Code, w.Body, c.status, c.detail)
		}
	}
}

func TestTheHandlerNeedsAnIssuerAndAStepUpAge(t *testing.T) {
	if _, err := httpapi.NewTemporaryPasswords(nil, time.Minute); err == nil {
		t.Error("a handler without an issuer was built")
	}
	if _, err := httpapi.NewTemporaryPasswords(&stubIssuer{}, 0); err == nil {
		t.Error("a handler without a step-up age was built")
	}
}
