package httpapi_test

// Registration requests (ADR-IAM-003 §5.3, TDD-identity-control-003 §Registration Requests): an
// application developer proposes and withdraws; a provider approves, rejects and reads the queue.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

func proposeRequest(owners ...id.UUID) *http.Request {
	quoted := make([]string, 0, len(owners))
	for _, owner := range owners {
		quoted = append(quoted, `"`+owner.String()+`"`)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/registration-requests", strings.NewReader(
		`{"client_key":"orders-web","profile":"public","audience_class":"internal","application_ref":"orders",`+
			`"redirect_uris":["https://orders.example.com/cb"],"owners":[`+strings.Join(quoted, ",")+`]}`))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "orders goes live")
	return r
}

func TestAnApplicationDeveloperProposesAProductionRegistration(t *testing.T) {
	developer, stranger, other := mustUUID(t), mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{developers: map[id.UUID]bool{developer: true}}
	handler := registrarHandler(t, registrar)

	if w := serve(handler, asOwner(proposeRequest(developer, other), stranger)); w.Code != http.StatusForbidden || registrar.regProposal != nil {
		t.Fatalf("a caller without the standing answered %d and reached the service: %v", w.Code, registrar.regProposal != nil)
	}
	w := serve(handler, asOwner(proposeRequest(developer, other), developer))
	if w.Code != http.StatusCreated {
		t.Fatalf("a developer's request answered %d: %s", w.Code, w.Body)
	}
	got := registrar.regProposal
	if got == nil || !got.Request.Developer || got.Request.RegisteredBy != developer || len(got.Owners) != 2 ||
		got.Reason != "orders goes live" || got.Request.ClientKey != "orders-web" {
		t.Fatalf("the request reached the service as %+v", got)
	}
	registrar.replayed = true
	if w := serve(handler, asOwner(proposeRequest(developer, other), developer)); w.Code != http.StatusOK {
		t.Errorf("a retried request answered %d, want 200", w.Code)
	}
	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, "/v1/registration-requests:mine", nil), developer)); w.Code != http.StatusOK {
		t.Errorf("a developer's own requests answered %d", w.Code)
	}
}

func TestOnlyAProviderDecidesARequestOrReadsTheQueue(t *testing.T) {
	developer, request := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{developers: map[id.UUID]bool{developer: true}}
	handler := registrarHandler(t, registrar)
	action := func(name string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/registration-requests/"+request.String()+":"+name, nil)
		r.Header.Set(httpapi.AdministrativeReasonHeader, "reviewed")
		return r
	}
	for _, name := range []string{"approve", "reject"} {
		if w := serve(handler, asOwner(action(name), developer)); w.Code != http.StatusForbidden || registrar.regDecision != nil {
			t.Errorf("a developer's :%s answered %d", name, w.Code)
		}
	}
	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, "/v1/registration-requests", nil), developer)); w.Code != http.StatusForbidden {
		t.Errorf("a developer reading the queue answered %d, want 403", w.Code)
	}
	if w := serve(handler, asOwner(action("withdraw"), developer)); w.Code != http.StatusOK || registrar.regDecision.Decision != "withdraw" || registrar.asProvider {
		t.Errorf("a developer's withdrawal answered %d as %+v", w.Code, registrar.regDecision)
	}
	r, provider := asPrincipal(t, action("approve"))
	if w := serve(handler, r); w.Code != http.StatusOK || registrar.regDecision.DecidedBy != provider || !registrar.asProvider {
		t.Errorf("a provider's approval answered %d as %+v", w.Code, registrar.regDecision)
	}
	q, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registration-requests", nil))
	if w := serve(handler, q); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"requests"`) {
		t.Errorf("a provider's queue answered %d: %s", w.Code, w.Body)
	}
}

func TestRequestRoutesRefuseMalformedRequestsAndMapRefusals(t *testing.T) {
	developer, other := mustUUID(t), mustUUID(t)
	handler := registrarHandler(t, &stubRegistrar{developers: map[id.UUID]bool{developer: true}})
	noReason := proposeRequest(developer, other)
	noReason.Header.Del(httpapi.AdministrativeReasonHeader)
	badOwner := httptest.NewRequest(http.MethodPost, "/v1/registration-requests", strings.NewReader(`{"owners":["x"]}`))
	badOwner.Header.Set(httpapi.AdministrativeReasonHeader, "r")
	unknown := httptest.NewRequest(http.MethodPost, "/v1/registration-requests", strings.NewReader(`{"tenant":"x"}`))
	unknown.Header.Set(httpapi.AdministrativeReasonHeader, "r")
	merge := httptest.NewRequest(http.MethodPost, "/v1/registration-requests/"+other.String()+":merge", nil)
	merge.Header.Set(httpapi.AdministrativeReasonHeader, "r")
	malformed := httptest.NewRequest(http.MethodPost, "/v1/registration-requests/x:withdraw", nil)
	malformed.Header.Set(httpapi.AdministrativeReasonHeader, "r")
	decisionNoReason := httptest.NewRequest(http.MethodPost, "/v1/registration-requests/"+other.String()+":withdraw", nil)
	for name, c := range map[string]struct {
		r    *http.Request
		want int
	}{
		"no reason":          {noReason, http.StatusBadRequest},
		"bad owner":          {badOwner, http.StatusBadRequest},
		"unknown field":      {unknown, http.StatusBadRequest},
		"unknown action":     {merge, http.StatusNotFound},
		"malformed request":  {malformed, http.StatusBadRequest},
		"decision no reason": {decisionNoReason, http.StatusBadRequest},
	} {
		if w := serve(handler, asOwner(c.r, developer)); w.Code != c.want {
			t.Errorf("%s answered %d, want %d", name, w.Code, c.want)
		}
	}

	for err, want := range map[error]int{
		registration.ErrRequestNotNeeded:                       http.StatusConflict,
		registration.ErrRequestOpen:                            http.StatusConflict,
		registration.ErrChangeDecided:                          http.StatusConflict,
		registration.ErrSelfApproval:                           http.StatusForbidden,
		registration.ErrNotProposer:                            http.StatusForbidden,
		registration.ErrNotProvider:                            http.StatusForbidden,
		registration.ErrRequestNotFound:                        http.StatusNotFound,
		registration.ErrOwnerNotEligible:                       http.StatusBadRequest,
		fmt.Errorf("%w: rule", registration.ErrDeveloperScope): http.StatusForbidden,
		fmt.Errorf("%w: rule", registration.ErrInvalid):        http.StatusBadRequest,
		registration.ErrKeyTaken:                               http.StatusConflict,
	} {
		h := registrarHandler(t, &stubRegistrar{developers: map[id.UUID]bool{developer: true}, err: err})
		if w := serve(h, asOwner(proposeRequest(developer, other), developer)); w.Code != want {
			t.Errorf("a request refused with %v answered %d, want %d", err, w.Code, want)
		}
	}
	failing := registrarHandler(t, &stubRegistrar{developers: map[id.UUID]bool{developer: true}, readErr: errors.New("down")})
	q, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registration-requests", nil))
	if w := serve(failing, q); w.Code != http.StatusInternalServerError {
		t.Errorf("a failed queue read answered %d, want 500", w.Code)
	}
	m, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registration-requests:mine", nil))
	if w := serve(failing, m); w.Code != http.StatusInternalServerError {
		t.Errorf("a failed own read answered %d, want 500", w.Code)
	}
}
