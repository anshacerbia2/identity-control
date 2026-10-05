package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/investigation"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

type stubInvestigator struct {
	err     error
	actor   investigation.Actor
	query   string
	subject id.UUID
}

func (s *stubInvestigator) seen(actor investigation.Actor, subject id.UUID) error {
	s.actor, s.subject = actor, subject
	return s.err
}

func (s *stubInvestigator) Search(_ context.Context, actor investigation.Actor, query string) ([]investigation.Summary, error) {
	s.actor, s.query = actor, query
	if s.err != nil {
		return nil, s.err
	}
	return []investigation.Summary{{Username: "alice", SubjectType: "human", State: "active"}}, nil
}

func (s *stubInvestigator) Principal(_ context.Context, actor investigation.Actor, subject id.UUID) (investigation.Principal, error) {
	if err := s.seen(actor, subject); err != nil {
		return investigation.Principal{}, err
	}
	return investigation.Principal{Summary: investigation.Summary{PrincipalID: subject, Username: "alice"}}, nil
}

func (s *stubInvestigator) Sessions(_ context.Context, actor investigation.Actor, subject id.UUID) ([]investigation.Session, error) {
	if err := s.seen(actor, subject); err != nil {
		return nil, err
	}
	return []investigation.Session{{Clients: []string{"identity-experience"}}}, nil
}

func (s *stubInvestigator) Authenticators(_ context.Context, actor investigation.Actor, subject id.UUID) ([]investigation.Authenticator, error) {
	if err := s.seen(actor, subject); err != nil {
		return nil, err
	}
	return []investigation.Authenticator{{SecurityRef: "k1.sealed", Type: "password"}}, nil
}

func (s *stubInvestigator) FederationLinks(_ context.Context, actor investigation.Actor, subject id.UUID) ([]investigation.FederationLink, error) {
	if err := s.seen(actor, subject); err != nil {
		return nil, err
	}
	return []investigation.FederationLink{{Provider: "google", UserName: "alice@example.com"}}, nil
}

func (s *stubInvestigator) Findings(_ context.Context, actor investigation.Actor, subject id.UUID) ([]investigation.Finding, error) {
	if err := s.seen(actor, subject); err != nil {
		return nil, err
	}
	return []investigation.Finding{}, nil
}

func (s *stubInvestigator) Events(_ context.Context, actor investigation.Actor, subject id.UUID) ([]investigation.Event, error) {
	if err := s.seen(actor, subject); err != nil {
		return nil, err
	}
	return []investigation.Event{}, nil
}

func investigationHandler(t *testing.T, stub *stubInvestigator) http.Handler {
	t.Helper()
	investigations, err := httpapi.NewInvestigation(stub)
	if err != nil {
		t.Fatal(err)
	}
	registrations, _ := httpapi.NewRegistrations(&stubRegistrar{}, &stubReconciler{})
	principals, _ := httpapi.NewPrincipals(&stubProvisioner{}, realm)
	built, err := httpapi.Routes(httpapi.RoutesConfig{Principals: principals, Registrations: registrations,
		Workloads: stubWorkloads(t), Investigation: investigations, Database: &stubProber{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(next http.Handler) http.Handler { return next }
	return built.Mount(identity, identity)
}

// Every read answers under its key, and the service is told who reads, on which route.
func TestAProviderReadsAPrincipalsSecurityState(t *testing.T) {
	subject := mustUUID(t)
	for path, key := range map[string]string{
		"":                  "principal_id",
		"/sessions":         "sessions",
		"/authenticators":   "authenticators",
		"/federation-links": "federation_links",
		"/findings":         "findings",
		"/events":           "events",
	} {
		t.Run("principal"+path, func(t *testing.T) {
			stub := &stubInvestigator{}
			r, caller := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/principals/"+subject.String()+path, nil))
			w := serve(investigationHandler(t, stub), r)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body[key] == nil {
				t.Errorf("body %s has no %q", w.Body, key)
			}
			if stub.subject != subject || stub.actor.Principal != caller {
				t.Errorf("read %s as %s; want %s as %s", stub.subject, stub.actor.Principal, subject, caller)
			}
			if want := "GET /v1/principals/{principal_id}" + path; stub.actor.Route != want {
				t.Errorf("route %q; want the pattern %q", stub.actor.Route, want)
			}
			if stub.actor.Emergency {
				t.Error("an activation's read was marked emergency")
			}
		})
	}
}

func TestASearchPassesTheQueryTrimmed(t *testing.T) {
	stub := &stubInvestigator{}
	r, caller := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/principals:search?q=%20ali%20", nil))
	w := serve(investigationHandler(t, stub), r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"principals"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if stub.query != "ali" || stub.actor.Principal != caller {
		t.Errorf("searched %q as %s", stub.query, stub.actor.Principal)
	}
}

func TestInvestigationErrorsMapToTheirStatus(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
	}{
		"a broad search":     {investigation.ErrQuery, http.StatusBadRequest},
		"no such Principal":  {investigation.ErrNotFound, http.StatusNotFound},
		"no kernel user":     {investigation.ErrUnlinked, http.StatusConflict},
		"the kernel failing": {fmt.Errorf("read: %w", keycloak.ErrUnavailable), http.StatusServiceUnavailable},
		"anything else":      {errors.New("evidence not written"), http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/principals/"+mustUUID(t).String()+"/sessions", nil))
			if w := serve(investigationHandler(t, &stubInvestigator{err: c.err}), r); w.Code != c.status {
				t.Errorf("status %d; want %d: %s", w.Code, c.status, w.Body)
			}
		})
	}
}

func TestAMalformedPrincipalIdentifierIsRefusedBeforeAnyRead(t *testing.T) {
	stub := &stubInvestigator{}
	r, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/principals/nope/sessions", nil))
	if w := serve(investigationHandler(t, stub), r); w.Code != http.StatusBadRequest {
		t.Errorf("status %d; want 400", w.Code)
	}
	if !stub.actor.Principal.IsNil() {
		t.Error("the service was asked to read")
	}
}

// Only a provider reads another Principal: an owner's token and no token are both refused before
// the service is reached (TDD-identity-control-005 §Read Authorization and Disclosure).
func TestOnlyAProviderReadsAnotherPrincipal(t *testing.T) {
	subject := mustUUID(t).String()
	for _, path := range []string{"/v1/principals:search?q=alice", "/v1/principals/" + subject,
		"/v1/principals/" + subject + "/sessions", "/v1/principals/" + subject + "/authenticators",
		"/v1/principals/" + subject + "/federation-links", "/v1/principals/" + subject + "/findings",
		"/v1/principals/" + subject + "/events"} {
		stub := &stubInvestigator{}
		handler := investigationHandler(t, stub)
		anonymous := serve(handler, httptest.NewRequest(http.MethodGet, path, nil))
		owner := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, path, nil), mustUUID(t)))
		if anonymous.Code != http.StatusUnauthorized || owner.Code != http.StatusForbidden {
			t.Errorf("%s: anonymous %d, owner %d; want 401, 403", path, anonymous.Code, owner.Code)
		}
		if !stub.actor.Principal.IsNil() || stub.query != "" {
			t.Errorf("%s: the service was reached", path)
		}
	}
}

func TestTheInvestigationHandlerNeedsAService(t *testing.T) {
	if _, err := httpapi.NewInvestigation(nil); err == nil {
		t.Error("a handler without an investigator was built")
	}
}
