package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/securitynotify"
)

type stubMatcher struct {
	match     bool
	err       error
	principal id.UUID
	address   string
}

func (s *stubMatcher) Match(_ context.Context, principal id.UUID, address string) (bool, error) {
	s.principal, s.address = principal, address
	return s.match, s.err
}

func askMatch(t *testing.T, handler http.Handler, authorization, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	root := http.NewServeMux()
	root.Handle("POST /v1/principals/{principal_id}/identifiers:match", handler)
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	root.ServeHTTP(recorder, request)
	return recorder
}

// The match answers a boolean and nothing else, to Organization Control's workload alone
// (TDD-identity-control-008 1.7.0, ADR-ORG-007 §5.3).
func TestTheIdentifierMatchAnswersABooleanToOrganizationControlAlone(t *testing.T) {
	principal, _ := id.NewV7()
	path := "/v1/principals/" + principal.String() + "/identifiers:match"
	for _, want := range []bool{true, false} {
		matcher := &stubMatcher{match: want}
		w := askMatch(t, identifierMatch(deliveryVerifier{}, matcher, nil), "Bearer token", path, `{"address":"p@example.test"}`)
		expected := `{"match":false}`
		if want {
			expected = `{"match":true}`
		}
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != expected || matcher.principal != principal ||
			matcher.address != "p@example.test" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("match %t: %d %s", want, w.Code, w.Body)
		}
	}
	matcher := &stubMatcher{match: true}
	if w := askMatch(t, identifierMatch(deliveryVerifier{}, matcher, nil), "", path, `{"address":"p@example.test"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token answered %d", w.Code)
	}
	if w := askMatch(t, identifierMatch(deliveryVerifier{err: errors.New("not organization")}, matcher, nil), "Bearer token", path,
		`{"address":"p@example.test"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("another caller answered %d", w.Code)
	}
	if w := askMatch(t, identifierMatch(nil, nil, nil), "Bearer token", path, `{"address":"p@example.test"}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unconfigured match answered %d", w.Code)
	}
	for name, c := range map[string]struct{ path, body string }{
		"a malformed principal_id": {"/v1/principals/x/identifiers:match", `{"address":"p@example.test"}`},
		"no address":               {path, `{}`},
		"an unknown field":         {path, `{"address":"p@example.test","principal_id":"x"}`},
		"not JSON":                 {path, `address=p@example.test`},
	} {
		m := &stubMatcher{}
		w := askMatch(t, identifierMatch(deliveryVerifier{}, m, nil), "Bearer token", c.path, c.body)
		if name != "no address" && w.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d; want 400", name, w.Code)
		}
	}
	invalid := &stubMatcher{err: securitynotify.ErrInvalidAddress}
	if w := askMatch(t, identifierMatch(deliveryVerifier{}, invalid, nil), "Bearer token", path, `{"address":"nope"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an invalid address answered %d", w.Code)
	}
	failing := &stubMatcher{err: errors.New("database down")}
	if w := askMatch(t, identifierMatch(deliveryVerifier{}, failing, nil), "Bearer token", path, `{"address":"p@example.test"}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a failed read answered %d", w.Code)
	}
}

// The route is mounted apart from every caller route: a provider's token, which the API chain admits,
// never reaches it through that chain.
func TestTheIdentifierMatchIsMountedBehindItsOwnVerification(t *testing.T) {
	surface := Surface{Probes: http.NewServeMux(), API: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), Identifiers: identifierMatch(deliveryVerifier{err: errors.New("not organization")}, &stubMatcher{match: true}, nil)}
	identity := func(next http.Handler) http.Handler { return next }
	principal, _ := id.NewV7()
	request := httptest.NewRequest(http.MethodPost, "/v1/principals/"+principal.String()+"/identifiers:match",
		strings.NewReader(`{"address":"p@example.test"}`))
	request.Header.Set("Authorization", "Bearer provider-token")
	recorder := httptest.NewRecorder()
	surface.Mount(identity, identity).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("the match answered %d through the mount; want its own 401", recorder.Code)
	}
}
