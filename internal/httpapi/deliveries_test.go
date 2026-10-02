package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/outbox"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

type deliveryVerifier struct{ err error }

func (v deliveryVerifier) Verify(string) (verify.Claims, error) { return verify.Claims{}, v.err }

type fakeApplier struct {
	outcome providerauthority.Outcome
	err     error
	calls   int
}

func (f *fakeApplier) Apply(context.Context, event.Envelope) (providerauthority.Outcome, error) {
	f.calls++
	return f.outcome, f.err
}

const deliveryBody = `{"specversion":"1.0","id":"01a0fc67-3cc0-7011-95cb-e160cc46b540","source":"/systems/organization-control",
"type":"com.scnehaux.organization.provider.security.revoked","time":"2026-10-02T10:00:00Z",
"datacontenttype":"application/json","data":{}}`

func deliver(t *testing.T, handler http.Handler, authorization, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/deliveries", strings.NewReader(body))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// The marker asserts this consumer holds the event's effect, and is set exactly where that is true.
func TestTheIntakeMarksOnlyWhatItHolds(t *testing.T) {
	for name, c := range map[string]struct {
		outcome providerauthority.Outcome
		marked  bool
	}{
		"applied":    {providerauthority.Outcome{}, true},
		"duplicate":  {providerauthority.Outcome{Duplicate: true}, true},
		"superseded": {providerauthority.Outcome{Superseded: true}, false},
	} {
		applier := &fakeApplier{outcome: c.outcome}
		got := deliver(t, deliveryIntake(deliveryVerifier{}, applier), "Bearer token", deliveryBody)
		if got.Code != http.StatusAccepted {
			t.Errorf("%s answered %d", name, got.Code)
		}
		if marked := got.Header().Get(outbox.ApplicationReceiptHeader) == outbox.ApplicationReceiptApplied; marked != c.marked {
			t.Errorf("%s: marked = %v, want %v", name, marked, c.marked)
		}
	}
}

// Poison is 400, which the dispatcher dead-letters; a fault of ours is 503, which it retries.
func TestTheIntakeTellsPoisonFromAFault(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		code int
	}{
		"unknown type": {providerauthority.ErrUnknownType, http.StatusBadRequest},
		"malformed":    {providerauthority.ErrMalformed, http.StatusBadRequest},
		"database":     {errors.New("connection refused"), http.StatusServiceUnavailable},
	} {
		got := deliver(t, deliveryIntake(deliveryVerifier{}, &fakeApplier{err: c.err}), "Bearer token", deliveryBody)
		if got.Code != c.code || got.Header().Get(outbox.ApplicationReceiptHeader) != "" {
			t.Errorf("%s answered %d with marker %q", name, got.Code, got.Header().Get(outbox.ApplicationReceiptHeader))
		}
	}
	if got := deliver(t, deliveryIntake(deliveryVerifier{}, &fakeApplier{}), "Bearer token", "not json"); got.Code != http.StatusBadRequest {
		t.Errorf("a body that is not an envelope answered %d", got.Code)
	}
}

// Nothing is applied for a caller that is not the delivering workload, or while unconfigured.
func TestTheIntakeAdmitsOnlyTheDeliveringWorkload(t *testing.T) {
	applier := &fakeApplier{}
	if got := deliver(t, deliveryIntake(deliveryVerifier{}, applier), "", deliveryBody); got.Code != http.StatusUnauthorized {
		t.Errorf("no token answered %d", got.Code)
	}
	if got := deliver(t, deliveryIntake(deliveryVerifier{err: errors.New("not organization")}, applier),
		"Bearer token", deliveryBody); got.Code != http.StatusUnauthorized {
		t.Errorf("a refused token answered %d", got.Code)
	}
	if got := deliver(t, deliveryIntake(nil, nil), "Bearer token", deliveryBody); got.Code != http.StatusServiceUnavailable {
		t.Errorf("an unconfigured intake answered %d", got.Code)
	}
	if applier.calls != 0 {
		t.Errorf("%d events applied for refused callers", applier.calls)
	}
}

// The intake is mounted apart from the caller routes, so the caller chain's authentication never
// sees a delivery and the delivery's never sees a caller.
func TestTheIntakeIsMountedApartFromTheCallerRoutes(t *testing.T) {
	var reached []string
	mark := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = append(reached, name) })
	}
	surface := Surface{Probes: mark("probes"), API: mark("api"), Deliveries: mark("deliveries")}
	chain := func(h http.Handler) http.Handler { return h }
	handler := surface.Mount(chain, chain)
	for _, path := range []string{"/v1/deliveries", "/v1/registrations"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil))
	}
	if len(reached) != 2 || reached[0] != "deliveries" || reached[1] != "api" {
		t.Errorf("reached %v, want the intake then the API", reached)
	}
}
