package httpapi_test

// The change routes (ADR-IAM-003 §5.2, TDD-identity-control-003 §Registration Changes): an owner
// proposes and withdraws on a registration it owns, and never approves, rejects or reads the queue.

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

func changeRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set(httpapi.AdministrativeReasonHeader, "move the callback to the new host")
	return r
}

func TestAnOwnerProposesAChangeToItsRegistration(t *testing.T) {
	owner, owned, other := mustUUID(t), mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{owners: map[id.UUID]id.UUID{owned: owner}}
	handler := registrarHandler(t, registrar)
	body := `{"redirect_uris":["https://billing.example.com/callback"],"expected_version":3}`

	w := serve(handler, asOwner(changeRequest(http.MethodPost, "/v1/registrations/"+owned.String()+"/changes", body), owner))
	if w.Code != http.StatusCreated {
		t.Fatalf("an owner's proposal answered %d, want 201: %s", w.Code, w.Body)
	}
	got := registrar.proposal
	if got == nil || got.RegistrationID != owned || got.ProposedBy != owner || got.ExpectedVersion != 3 ||
		len(got.RedirectURIs) != 1 || got.Reason != "move the callback to the new host" {
		t.Fatalf("the proposal reached the service as %+v", got)
	}

	// The same proposal retried is answered with the open change, not created again.
	registrar.replayed = true
	if w := serve(handler, asOwner(changeRequest(http.MethodPost, "/v1/registrations/"+owned.String()+"/changes", body), owner)); w.Code != http.StatusOK {
		t.Errorf("a retried proposal answered %d, want 200", w.Code)
	}

	// Another registration is not found, and the list of changes is an owner's too.
	if w := serve(handler, asOwner(changeRequest(http.MethodPost, "/v1/registrations/"+other.String()+"/changes", body), owner)); w.Code != http.StatusNotFound {
		t.Errorf("a proposal on a registration the owner does not own answered %d, want 404", w.Code)
	}
	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, "/v1/registrations/"+owned.String()+"/changes", nil), owner)); w.Code != http.StatusOK {
		t.Errorf("an owner listing its registration's changes answered %d, want 200", w.Code)
	}
}

func TestOnlyAProviderApprovesRejectsOrReadsTheQueue(t *testing.T) {
	owner, owned, change := mustUUID(t), mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{owners: map[id.UUID]id.UUID{owned: owner}}
	handler := registrarHandler(t, registrar)
	base := "/v1/registrations/" + owned.String() + "/changes/" + change.String()

	for _, action := range []string{"approve", "reject"} {
		w := serve(handler, asOwner(changeRequest(http.MethodPost, base+":"+action, ""), owner))
		if w.Code != http.StatusForbidden {
			t.Errorf("an owner's :%s answered %d, want 403", action, w.Code)
		}
		if registrar.decision != nil {
			t.Fatalf("an owner's :%s reached the service", action)
		}
	}
	if w := serve(handler, asOwner(httptest.NewRequest(http.MethodGet, "/v1/registrations:changes", nil), owner)); w.Code != http.StatusForbidden {
		t.Errorf("an owner reading the approval queue answered %d, want 403", w.Code)
	}

	// The proposer withdraws its own; the service decides whether this caller proposed it.
	w := serve(handler, asOwner(changeRequest(http.MethodPost, base+":withdraw", ""), owner))
	if w.Code != http.StatusOK || registrar.decision == nil || registrar.decision.Decision != "withdraw" || registrar.asProvider {
		t.Fatalf("an owner's withdrawal answered %d, reaching the service as %+v (provider %v)", w.Code, registrar.decision, registrar.asProvider)
	}

	r, provider := asPrincipal(t, changeRequest(http.MethodPost, base+":approve", ""))
	if w := serve(handler, r); w.Code != http.StatusOK {
		t.Fatalf("a provider's approval answered %d: %s", w.Code, w.Body)
	}
	if got := registrar.decision; got.Decision != "approve" || got.DecidedBy != provider || got.ChangeID != change || !registrar.asProvider {
		t.Errorf("the approval reached the service as %+v (provider %v)", got, registrar.asProvider)
	}
	q, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations:changes", nil))
	if w := serve(handler, q); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changes"`) {
		t.Errorf("a provider reading the queue answered %d: %s", w.Code, w.Body)
	}
}

func TestChangeRoutesRefuseMalformedRequests(t *testing.T) {
	owner, owned := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{owners: map[id.UUID]id.UUID{owned: owner}}
	handler := registrarHandler(t, registrar)
	base := "/v1/registrations/" + owned.String() + "/changes"

	for name, c := range map[string]struct {
		r    *http.Request
		want int
	}{
		"no reason": {func() *http.Request {
			r := changeRequest(http.MethodPost, base, `{"redirect_uris":["https://a.example.com/cb"],"expected_version":1}`)
			r.Header.Del(httpapi.AdministrativeReasonHeader)
			return r
		}(), http.StatusBadRequest},
		"unknown field":    {changeRequest(http.MethodPost, base, `{"lifetime_class":"L0","expected_version":1}`), http.StatusBadRequest},
		"not json":         {changeRequest(http.MethodPost, base, `redirect`), http.StatusBadRequest},
		"unknown action":   {changeRequest(http.MethodPost, base+"/"+owned.String()+":merge", ""), http.StatusNotFound},
		"malformed change": {changeRequest(http.MethodPost, base+"/nope:withdraw", ""), http.StatusBadRequest},
		"decision, no reason": {func() *http.Request {
			r := changeRequest(http.MethodPost, base+"/"+owned.String()+":withdraw", "")
			r.Header.Del(httpapi.AdministrativeReasonHeader)
			return r
		}(), http.StatusBadRequest},
	} {
		if w := serve(handler, asOwner(c.r, owner)); w.Code != c.want {
			t.Errorf("%s answered %d, want %d: %s", name, w.Code, c.want, w.Body)
		}
	}
}

func TestChangeRefusalsAreMappedToTheirStatus(t *testing.T) {
	owner, owned := mustUUID(t), mustUUID(t)
	for err, want := range map[error]int{
		fmt.Errorf("%w: rule", registration.ErrInvalid):     http.StatusBadRequest,
		registration.ErrVersionConflict:                     http.StatusConflict,
		registration.ErrChangeOpen:                          http.StatusConflict,
		registration.ErrChangeDecided:                       http.StatusConflict,
		registration.ErrSuperseded:                          http.StatusConflict,
		registration.ErrInvalidTransition:                   http.StatusConflict,
		registration.ErrSelfApproval:                        http.StatusForbidden,
		registration.ErrNotProposer:                         http.StatusForbidden,
		registration.ErrNotProvider:                         http.StatusForbidden,
		registration.ErrChangeNotFound:                      http.StatusNotFound,
		registration.ErrNotFound:                            http.StatusNotFound,
		errors.New("registration: write the redirect URIs"): http.StatusServiceUnavailable,
	} {
		registrar := &stubRegistrar{owners: map[id.UUID]id.UUID{owned: owner}, err: err}
		handler := registrarHandler(t, registrar)
		propose := changeRequest(http.MethodPost, "/v1/registrations/"+owned.String()+"/changes",
			`{"redirect_uris":["https://a.example.com/cb"],"expected_version":1}`)
		if w := serve(handler, asOwner(propose, owner)); w.Code != want {
			t.Errorf("a proposal refused with %v answered %d, want %d", err, w.Code, want)
		}
		withdraw := changeRequest(http.MethodPost, "/v1/registrations/"+owned.String()+"/changes/"+owned.String()+":withdraw", "")
		if w := serve(handler, asOwner(withdraw, owner)); w.Code != want {
			t.Errorf("a withdrawal refused with %v answered %d, want %d", err, w.Code, want)
		}
		list := httptest.NewRequest(http.MethodGet, "/v1/registrations/"+owned.String()+"/changes", nil)
		if w := serve(handler, asOwner(list, owner)); w.Code != want {
			t.Errorf("a list refused with %v answered %d, want %d", err, w.Code, want)
		}
	}

	failing := &stubRegistrar{readErr: errors.New("database down")}
	q, _ := asPrincipal(t, httptest.NewRequest(http.MethodGet, "/v1/registrations:changes", nil))
	if w := serve(registrarHandler(t, failing), q); w.Code != http.StatusInternalServerError {
		t.Errorf("a failed queue read answered %d, want 500", w.Code)
	}
}

// An audience change carries its list as given, an empty one included, and says whether the
// proposer is a provider: an owner adds only resources it owns, which the service decides.
func TestAnAudienceChangeReachesTheServiceAsAsked(t *testing.T) {
	owner, owned := mustUUID(t), mustUUID(t)
	registrar := &stubRegistrar{owners: map[id.UUID]id.UUID{owned: owner}}
	handler := registrarHandler(t, registrar)
	path := "/v1/registrations/" + owned.String() + "/changes"

	if w := serve(handler, asOwner(changeRequest(http.MethodPost, path, `{"audience":["identity-control-api"],"expected_version":2}`), owner)); w.Code != http.StatusCreated {
		t.Fatalf("an owner's audience change answered %d: %s", w.Code, w.Body)
	}
	got := registrar.proposal
	if got == nil || got.Audience == nil || len(*got.Audience) != 1 || (*got.Audience)[0] != "identity-control-api" ||
		got.RedirectURIs != nil || got.Provider {
		t.Fatalf("the audience change reached the service as %+v", got)
	}

	if w := serve(handler, asOwner(changeRequest(http.MethodPost, path, `{"audience":[],"expected_version":3}`), owner)); w.Code != http.StatusCreated {
		t.Fatalf("an empty audience answered %d: %s", w.Code, w.Body)
	}
	if got := registrar.proposal; got.Audience == nil || len(*got.Audience) != 0 {
		t.Errorf("an empty audience reached the service as %v; it must stay distinct from absent", got.Audience)
	}

	registrar.err = registration.ErrNotResourceOwner
	if w := serve(handler, asOwner(changeRequest(http.MethodPost, path, `{"audience":["orders-api"],"expected_version":4}`), owner)); w.Code != http.StatusForbidden {
		t.Errorf("adding a resource the owner does not own answered %d, want 403", w.Code)
	}
}
