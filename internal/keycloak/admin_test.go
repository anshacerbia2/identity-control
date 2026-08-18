package keycloak_test

// These tests run the real Admin client against an httptest server, because the properties
// worth asserting are about what it sends, what it does with a status, and what class it
// assigns a failure — none of which a mock of the port would exercise.
//
// The assertion that matters most is the ambiguity asymmetry in TestTransportFailureClass. A
// create whose response is lost must be reported as possibly-succeeded; the same failure on a
// read must not be. Getting that backwards on a create is how a second Principal appears for
// one request.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

const (
	testRealm  = keycloak.Realm("scnehaux")
	testSecret = "super-secret-client-value"
)

// kernel is a scripted stand-in for the Admin REST surface.
type kernel struct {
	tokenStatus   int
	tokenBody     string
	tokenCalls    atomic.Int32
	adminStatus   int
	adminBody     string
	adminLocation string
	adminCalls    atomic.Int32
	lastMethod    string
	lastPath      string
	lastQuery     string
	lastBody      []byte
	lastAuth      string
}

func (k *kernel) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/realms/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		k.tokenCalls.Add(1)
		status := k.tokenStatus
		if status == 0 {
			status = http.StatusOK
		}
		body := k.tokenBody
		if body == "" {
			body = `{"access_token":"admin-token","expires_in":300,"token_type":"Bearer"}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})

	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		k.adminCalls.Add(1)
		k.lastMethod, k.lastPath, k.lastQuery = r.Method, r.URL.Path, r.URL.RawQuery
		k.lastAuth = r.Header.Get("Authorization")
		k.lastBody, _ = io.ReadAll(r.Body)

		if k.adminLocation != "" {
			w.Header().Set("Location", k.adminLocation)
		}
		status := k.adminStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if k.adminBody != "" {
			_, _ = io.WriteString(w, k.adminBody)
		}
	})

	return mux
}

func newAdmin(t *testing.T, k *kernel) (*keycloak.Admin, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(k.handler())
	t.Cleanup(server.Close)

	admin, err := keycloak.NewAdmin(keycloak.AdminConfig{
		BaseURL:      server.URL,
		Realm:        testRealm,
		ClientID:     "identity-control",
		ClientSecret: testSecret,
		Timeout:      2 * time.Second,
	}, server.Client())
	if err != nil {
		t.Fatalf("NewAdmin: %v", err)
	}
	return admin, server
}

func newUUID(t *testing.T) id.UUID {
	t.Helper()
	value, err := id.NewV7()
	if err != nil {
		t.Fatalf("NewV7: %v", err)
	}
	return value
}

func TestCreateUserSendsTheClaimSourceInOneCall(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated}
	principalID := newUUID(t)
	owner := newUUID(t)
	k.adminLocation = "/admin/realms/scnehaux/users/8f2c-created"

	admin, _ := newAdmin(t, k)
	userID, err := admin.CreateUser(context.Background(), keycloak.CreateUserRequest{
		Realm: testRealm, Username: "nightly-job", Email: "job@example.com",
		PrincipalID: principalID, SubjectType: keycloak.SubjectWorkload, WorkloadOwner: owner,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if userID != keycloak.UserID("8f2c-created") {
		t.Errorf("userID = %q, want the Location tail", userID)
	}

	// One admin call, not two. Setting the attribute separately would leave a Principal
	// without its canonical identifier for the duration of the gap.
	if got := k.adminCalls.Load(); got != 1 {
		t.Errorf("admin calls = %d, want 1", got)
	}

	var sent struct {
		Username   string              `json:"username"`
		Enabled    bool                `json:"enabled"`
		Attributes map[string][]string `json:"attributes"`
	}
	if err := json.Unmarshal(k.lastBody, &sent); err != nil {
		t.Fatalf("unmarshal sent body: %v", err)
	}
	if !sent.Enabled {
		t.Error("the created user is not enabled")
	}
	for attribute, want := range map[string]string{
		keycloak.AttrPrincipalID:   principalID.String(),
		keycloak.AttrSubjectType:   string(keycloak.SubjectWorkload),
		keycloak.AttrWorkloadOwner: owner.String(),
	} {
		values := sent.Attributes[attribute]
		if len(values) != 1 || values[0] != want {
			t.Errorf("attribute %s = %v, want [%s]", attribute, values, want)
		}
	}
}

func TestCreateUserOmitsWorkloadOwnerForAHuman(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated, adminLocation: "/users/human-1"}
	admin, _ := newAdmin(t, k)

	if _, err := admin.CreateUser(context.Background(), keycloak.CreateUserRequest{
		Realm: testRealm, Username: "operator",
		PrincipalID: newUUID(t), SubjectType: keycloak.SubjectHuman,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if strings.Contains(string(k.lastBody), keycloak.AttrWorkloadOwner) {
		t.Errorf("a human carries a workload owner attribute: %s", k.lastBody)
	}
}

// TestCreateWithoutALocationIsAmbiguous covers the case where the kernel created the user and
// did not say which one. It is not a failure: the user exists, and recovery resolves it by
// attribute search on exactly the path a lost response takes.
func TestCreateWithoutALocationIsAmbiguous(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated}
	admin, _ := newAdmin(t, k)

	_, err := admin.CreateUser(context.Background(), keycloak.CreateUserRequest{
		Realm: testRealm, Username: "operator",
		PrincipalID: newUUID(t), SubjectType: keycloak.SubjectHuman,
	})
	if !errors.Is(err, keycloak.ErrAmbiguous) {
		t.Fatalf("error = %v, want ErrAmbiguous", err)
	}
}

// TestTransportFailureClass is the asymmetry. The server is closed before the call, so no
// status is ever received; a create must report that as possibly-succeeded and a read must not.
func TestTransportFailureClass(t *testing.T) {
	k := &kernel{}
	admin, server := newAdmin(t, k)
	server.Close()

	_, createErr := admin.CreateUser(context.Background(), keycloak.CreateUserRequest{
		Realm: testRealm, Username: "operator",
		PrincipalID: newUUID(t), SubjectType: keycloak.SubjectHuman,
	})
	if !errors.Is(createErr, keycloak.ErrUnavailable) && !errors.Is(createErr, keycloak.ErrAmbiguous) {
		t.Fatalf("create error = %v, want an unavailable or ambiguous class", createErr)
	}

	_, findErr := admin.FindByPrincipalID(context.Background(), testRealm, newUUID(t))
	if !errors.Is(findErr, keycloak.ErrUnavailable) {
		t.Fatalf("find error = %v, want ErrUnavailable", findErr)
	}
	if errors.Is(findErr, keycloak.ErrAmbiguous) {
		t.Error("a read reported an ambiguous outcome; only a mutation may")
	}
}

// TestMutationAmbiguityAfterAStatuslessRoundTrip isolates the mutating branch with a token
// already cached, so the failure is on the create rather than on the token acquisition.
func TestMutationAmbiguityAfterAStatuslessRoundTrip(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated, adminLocation: "/users/first"}
	admin, server := newAdmin(t, k)

	// Warm the token cache with a successful call.
	if _, err := admin.CreateUser(context.Background(), keycloak.CreateUserRequest{
		Realm: testRealm, Username: "first",
		PrincipalID: newUUID(t), SubjectType: keycloak.SubjectHuman,
	}); err != nil {
		t.Fatalf("warm-up CreateUser: %v", err)
	}
	server.Close()

	_, err := admin.CreateUser(context.Background(), keycloak.CreateUserRequest{
		Realm: testRealm, Username: "second",
		PrincipalID: newUUID(t), SubjectType: keycloak.SubjectHuman,
	})
	if !errors.Is(err, keycloak.ErrAmbiguous) {
		t.Fatalf("error = %v, want ErrAmbiguous: a lost create response may have landed", err)
	}
}

func TestStatusMapping(t *testing.T) {
	cases := map[int]error{
		http.StatusUnauthorized:        keycloak.ErrForbidden,
		http.StatusForbidden:           keycloak.ErrForbidden,
		http.StatusNotFound:            keycloak.ErrNotFound,
		http.StatusConflict:            keycloak.ErrConflict,
		http.StatusTooManyRequests:     keycloak.ErrUnavailable,
		http.StatusInternalServerError: keycloak.ErrUnavailable,
		http.StatusBadGateway:          keycloak.ErrUnavailable,
		http.StatusTeapot:              keycloak.ErrUnavailable,
	}

	for status, want := range cases {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			k := &kernel{adminStatus: status}
			admin, _ := newAdmin(t, k)

			err := admin.DisableUser(context.Background(), testRealm, "kc-user-1")
			if !errors.Is(err, want) {
				t.Errorf("error = %v, want %v", err, want)
			}
		})
	}
}

// TestForbiddenIsNotTransient states why 403 maps to its own class. Retrying cannot grant a
// role, and treating it as unavailable would hide a deployment defect behind a backoff.
func TestForbiddenIsNotTransient(t *testing.T) {
	k := &kernel{adminStatus: http.StatusForbidden}
	admin, _ := newAdmin(t, k)

	err := admin.DisableUser(context.Background(), testRealm, "kc-user-1")
	if !errors.Is(err, keycloak.ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}
	if errors.Is(err, keycloak.ErrUnavailable) {
		t.Error("a rejected credential is classed as transient; it would be retried forever")
	}
}

// TestFindFiltersToExactEquality is the seam for the unanswered attribute-query question. The
// kernel is scripted to return a near-match, and the client must discard it.
func TestFindFiltersToExactEquality(t *testing.T) {
	wanted := newUUID(t)
	other := newUUID(t)

	k := &kernel{adminBody: fmt.Sprintf(`[
	  {"id":"kc-1","username":"wanted","enabled":true,"attributes":{"scnehaux_principal_id":["%s"],"scnehaux_subject_type":["human"]}},
	  {"id":"kc-2","username":"other","enabled":true,"attributes":{"scnehaux_principal_id":["%s"],"scnehaux_subject_type":["human"]}}
	]`, wanted, other)}

	admin, _ := newAdmin(t, k)
	found, err := admin.FindByPrincipalID(context.Background(), testRealm, wanted)
	if err != nil {
		t.Fatalf("FindByPrincipalID: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d users, want 1: a widened query must not widen the result", len(found))
	}
	if found[0].PrincipalID != wanted {
		t.Errorf("found %s, want %s", found[0].PrincipalID, wanted)
	}
	if !strings.Contains(k.lastQuery, keycloak.AttrPrincipalID) {
		t.Errorf("the query does not name the attribute: %s", k.lastQuery)
	}
}

// TestUnparseableAttributeReportsUnmapped covers the reconciler's input. A malformed identifier
// must leave the user unmapped rather than failing the enumeration, or the sweep meant to detect
// it would stop at it.
func TestUnparseableAttributeReportsUnmapped(t *testing.T) {
	k := &kernel{adminBody: `[
	  {"id":"kc-1","username":"broken","enabled":true,"attributes":{"scnehaux_principal_id":["not-a-uuid"]}},
	  {"id":"kc-2","username":"absent","enabled":true,"attributes":{}}
	]`}

	admin, _ := newAdmin(t, k)
	users, err := admin.ListUsers(context.Background(), testRealm, keycloak.Page{First: 0, Max: 10})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("listed %d users, want 2: a malformed attribute must not fail the sweep", len(users))
	}
	for _, user := range users {
		if user.Mapped() {
			t.Errorf("user %q reports itself mapped", user.ID)
		}
	}
}

func TestListUsersPagesThroughQueryParameters(t *testing.T) {
	k := &kernel{adminBody: `[]`}
	admin, _ := newAdmin(t, k)

	if _, err := admin.ListUsers(context.Background(), testRealm, keycloak.Page{First: 40, Max: 20}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, want := range []string{"first=40", "max=20"} {
		if !strings.Contains(k.lastQuery, want) {
			t.Errorf("query %q does not carry %s", k.lastQuery, want)
		}
	}
}

func TestDisableUserSetsEnabledFalse(t *testing.T) {
	k := &kernel{adminStatus: http.StatusNoContent}
	admin, _ := newAdmin(t, k)

	if err := admin.DisableUser(context.Background(), testRealm, "kc-user-9"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if k.lastMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", k.lastMethod)
	}
	if !strings.Contains(string(k.lastBody), `"enabled":false`) {
		t.Errorf("body does not disable the user: %s", k.lastBody)
	}
	// Disable must never delete. A DELETE here would make a reconciler defect unrecoverable.
	if k.lastMethod == http.MethodDelete {
		t.Error("DisableUser issued a DELETE")
	}
}

// TestTokenIsAcquiredOnceAndReused asserts the cache. Acquiring per call would put a token
// request on every administrative operation and multiply load on the kernel's token endpoint.
func TestTokenIsAcquiredOnceAndReused(t *testing.T) {
	k := &kernel{adminBody: `[]`}
	admin, _ := newAdmin(t, k)

	for range 3 {
		if _, err := admin.ListUsers(context.Background(), testRealm, keycloak.Page{First: 0, Max: 5}); err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
	}
	if got := k.tokenCalls.Load(); got != 1 {
		t.Errorf("token acquired %d times, want 1", got)
	}
	if k.lastAuth != "Bearer admin-token" {
		t.Errorf("Authorization = %q, want the cached bearer token", k.lastAuth)
	}
}

// TestATokenWithoutALifetimeIsNotCached states the safer branch. Caching an unknown lifetime is
// how a service starts presenting an expired token and reads the resulting 401 as a permission
// problem rather than as a stale credential.
func TestATokenWithoutALifetimeIsNotCached(t *testing.T) {
	k := &kernel{
		adminBody: `[]`,
		tokenBody: `{"access_token":"no-expiry-token","token_type":"Bearer"}`,
	}
	admin, _ := newAdmin(t, k)

	for range 2 {
		if _, err := admin.ListUsers(context.Background(), testRealm, keycloak.Page{First: 0, Max: 5}); err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
	}
	if got := k.tokenCalls.Load(); got != 2 {
		t.Errorf("token acquired %d times, want 2: an unknown lifetime must not be cached", got)
	}
}

// TestRejectedCredentialIsForbiddenNotUnavailable covers the deployment defect. The token
// endpoint answering 400 or 401 means the client secret is wrong, and retrying will never fix it.
func TestRejectedCredentialIsForbiddenNotUnavailable(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("token status %d", status), func(t *testing.T) {
			k := &kernel{tokenStatus: status, tokenBody: `{"error":"invalid_client"}`}
			admin, _ := newAdmin(t, k)

			_, err := admin.ListUsers(context.Background(), testRealm, keycloak.Page{First: 0, Max: 5})
			if !errors.Is(err, keycloak.ErrForbidden) {
				t.Errorf("error = %v, want ErrForbidden", err)
			}
			if k.adminCalls.Load() != 0 {
				t.Error("an administrative call was attempted without a token")
			}
		})
	}
}

// TestNoErrorCarriesTheSecretOrTheToken is the redaction assertion at this boundary. Both
// strings grant user creation and credential rotation across the realm, and an error message is
// the least controlled place either could end up.
func TestNoErrorCarriesTheSecretOrTheToken(t *testing.T) {
	probes := []func(*keycloak.Admin) error{
		func(a *keycloak.Admin) error {
			_, err := a.CreateUser(context.Background(), keycloak.CreateUserRequest{
				Realm: testRealm, Username: "operator",
				PrincipalID: newUUID(t), SubjectType: keycloak.SubjectHuman,
			})
			return err
		},
		func(a *keycloak.Admin) error {
			_, err := a.FindByPrincipalID(context.Background(), testRealm, newUUID(t))
			return err
		},
		func(a *keycloak.Admin) error {
			_, err := a.ListUsers(context.Background(), testRealm, keycloak.Page{First: 0, Max: 5})
			return err
		},
		func(a *keycloak.Admin) error {
			return a.DisableUser(context.Background(), testRealm, "kc-user-1")
		},
	}

	// Both a kernel error body quoting the request and a rejected credential are exercised,
	// because those are the two responses most likely to echo something sensitive.
	kernels := []*kernel{
		{adminStatus: http.StatusInternalServerError, adminBody: `{"error":"` + testSecret + `"}`},
		{tokenStatus: http.StatusUnauthorized, tokenBody: `{"error":"` + testSecret + `"}`},
		{adminStatus: http.StatusConflict, adminBody: `{"errorMessage":"admin-token"}`},
	}

	for i, k := range kernels {
		admin, _ := newAdmin(t, k)
		for j, probe := range probes {
			err := probe(admin)
			if err == nil {
				continue
			}
			message := err.Error()
			for _, forbidden := range []string{testSecret, "admin-token", "client_secret"} {
				if strings.Contains(message, forbidden) {
					t.Errorf("kernel %d probe %d error carries %q: %s", i, j, forbidden, message)
				}
			}
		}
	}
}

func TestNewAdminValidatesItsConfiguration(t *testing.T) {
	base := keycloak.AdminConfig{
		BaseURL: "https://identity.example.com", Realm: testRealm,
		ClientID: "identity-control", ClientSecret: testSecret,
	}

	cases := map[string]func(keycloak.AdminConfig) keycloak.AdminConfig{
		"no base URL":      func(c keycloak.AdminConfig) keycloak.AdminConfig { c.BaseURL = ""; return c },
		"no realm":         func(c keycloak.AdminConfig) keycloak.AdminConfig { c.Realm = ""; return c },
		"no client id":     func(c keycloak.AdminConfig) keycloak.AdminConfig { c.ClientID = ""; return c },
		"no client secret": func(c keycloak.AdminConfig) keycloak.AdminConfig { c.ClientSecret = ""; return c },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := keycloak.NewAdmin(mutate(base), nil); err == nil {
				t.Fatal("NewAdmin accepted an incomplete configuration")
			}
		})
	}

	if _, err := keycloak.NewAdmin(base, nil); err != nil {
		t.Errorf("NewAdmin rejected a complete configuration: %v", err)
	}
}

func TestCreateUserRefusesAnInvalidRequestBeforeCalling(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated}
	admin, _ := newAdmin(t, k)

	_, err := admin.CreateUser(context.Background(), keycloak.CreateUserRequest{
		Realm: testRealm, Username: "job", PrincipalID: newUUID(t),
		SubjectType: keycloak.SubjectWorkload, // no owner
	})
	if err == nil {
		t.Fatal("CreateUser accepted a workload without an owner")
	}
	if k.adminCalls.Load() != 0 {
		t.Error("an invalid request reached the kernel")
	}
}
