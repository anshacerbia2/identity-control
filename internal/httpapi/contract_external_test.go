package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
)

// serveChecked runs a request through a handler and holds the exchange to api/openapi.yaml
// (contract_test.go).
func serveChecked(t testing.TB, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	return httpapi.ServeChecked(t, handler, request)
}

// serveInjected runs a request without checking it. It is for a test that makes a stub fail with each
// error the handler maps, on a route that cannot produce all of them (a list cannot answer "not the
// proposer"), or that asks a route the mux does not mount: the answer is the mapping's, not the route's,
// so it is not held to the route's documented answers.
func serveInjected(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	withKey(request)
	recorded := httptest.NewRecorder()
	handler.ServeHTTP(recorded, request)
	return recorded
}
