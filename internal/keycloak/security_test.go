package keycloak_test

// A user's security state through the supported Admin REST API (TDD-identity-control-005
// §Component Design).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func TestSecurityStateIsReadFromTheUserSubresources(t *testing.T) {
	k := &kernel{}
	k.route = func(method, path string) (int, string) {
		switch {
		case strings.HasSuffix(path, "/users/u1/sessions"):
			return http.StatusOK, `[
			  {"id":"s-old","ipAddress":"203.0.113.9","start":1000,"lastAccess":2000,"clients":{"c1":"web"}},
			  {"id":"s-new","ipAddress":"203.0.113.9","start":3000,"lastAccess":9000,"clients":{"c2":"admin","c1":"web"}}]`
		case strings.HasSuffix(path, "/users/u1/credentials"):
			return http.StatusOK, `[
			  {"id":"k2","type":"webauthn","userLabel":"laptop","createdDate":5000,"secretData":"SECRET","credentialData":"{}"},
			  {"id":"k1","type":"password","createdDate":1000,"secretData":"SECRET"},
			  {"id":"k3","type":"recovery-authn-codes","createdDate":6000,"secretData":"SECRET",
			   "credentialData":"{\"hashIterations\":null,\"algorithm\":\"RS512\",\"remaining\":11,\"total\":12}"}]`
		case strings.HasSuffix(path, "/users/u1/federated-identity"):
			return http.StatusOK, `[{"identityProvider":"github","userId":"77","userName":"ansha"}]`
		}
		return http.StatusNotFound, ""
	}
	admin, _ := newAdmin(t, k)
	ctx := context.Background()

	sessions, err := admin.UserSessions(ctx, testRealm, "u1")
	if err != nil || len(sessions) != 2 || sessions[0].ID != "s-new" ||
		strings.Join(sessions[0].Clients, ",") != "admin,web" || !sessions[0].LastAccess.Equal(time.UnixMilli(9000)) {
		t.Errorf("sessions: %+v, %v", sessions, err)
	}

	credentials, err := admin.UserCredentials(ctx, testRealm, "u1")
	if err != nil || len(credentials) != 3 || credentials[0].ID != "k1" || credentials[1].Label != "laptop" {
		t.Fatalf("credentials: %+v, %v", credentials, err)
	}
	if r, n := credentials[2].Remaining, credentials[2].Total; r == nil || *r != 11 || n == nil || *n != 12 ||
		credentials[1].Remaining != nil {
		t.Errorf("recovery codes: %v of %v; a key's: %v", r, n, credentials[1].Remaining)
	}
	for _, c := range credentials {
		if strings.Contains(c.ID+c.Type+c.Label, "SECRET") {
			t.Errorf("a credential carries its secret data: %+v", c)
		}
	}

	links, err := admin.UserFederatedIdentities(ctx, testRealm, "u1")
	if err != nil || len(links) != 1 || links[0].Provider != "github" || links[0].UserName != "ansha" {
		t.Errorf("links: %+v, %v", links, err)
	}

	if _, err := admin.UserSessions(ctx, testRealm, ""); err == nil {
		t.Error("a read with no user was sent")
	}
	if _, err := admin.UserSessions(ctx, testRealm, "gone"); err == nil {
		t.Error("an absent user's sessions answered no error")
	}
}

// Each containment call is the documented endpoint, with nothing but enabled in a user update, so
// the partial update keeps the user's attributes (identity-kernel compat/user_containment_test.go).
func TestContainmentCallsTheDocumentedEndpoints(t *testing.T) {
	k := &kernel{}
	k.route = func(method, path string) (int, string) {
		if strings.HasSuffix(path, "/credentials/gone") {
			return http.StatusNotFound, ""
		}
		return http.StatusNoContent, ""
	}
	admin, _ := newAdmin(t, k)
	ctx := context.Background()

	if err := admin.EnableUser(ctx, testRealm, "u1"); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodPut || !strings.HasSuffix(k.lastPath, "/users/u1") || string(k.lastBody) != `{"enabled":true}` {
		t.Errorf("enable sent %s %s %s", k.lastMethod, k.lastPath, k.lastBody)
	}
	if err := admin.LogoutUser(ctx, testRealm, "u1"); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodPost || !strings.HasSuffix(k.lastPath, "/users/u1/logout") {
		t.Errorf("logout sent %s %s", k.lastMethod, k.lastPath)
	}
	if err := admin.DeleteCredential(ctx, testRealm, "u1", "k1"); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodDelete || !strings.HasSuffix(k.lastPath, "/users/u1/credentials/k1") {
		t.Errorf("delete sent %s %s", k.lastMethod, k.lastPath)
	}
	if err := admin.DeleteCredential(ctx, testRealm, "u1", "gone"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("an absent credential: %v, want ErrNotFound", err)
	}
	if err := admin.DeleteSession(ctx, testRealm, "s1"); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodDelete || !strings.HasSuffix(k.lastPath, "/realms/scnehaux/sessions/s1") {
		t.Errorf("session delete sent %s %s", k.lastMethod, k.lastPath)
	}
	for name, call := range map[string]func() error{
		"session": func() error { return admin.DeleteSession(ctx, testRealm, "") },
		"enable":  func() error { return admin.EnableUser(ctx, testRealm, "") },
		"logout":  func() error { return admin.LogoutUser(ctx, testRealm, "") },
		"delete":  func() error { return admin.DeleteCredential(ctx, testRealm, "u1", "") },
	} {
		if err := call(); err == nil {
			t.Errorf("%s with no identifier was sent", name)
		}
	}
}

// Consents are listed and withdrawn through the user's consent sub-resource (TDD-identity-control-005
// 2.13.0): "Get consents granted by the user" and "Revoke consent and offline tokens for particular
// client from user".
func TestConsentsAreListedAndWithdrawnThroughTheUserSubresource(t *testing.T) {
	k := &kernel{}
	k.route = func(method, path string) (int, string) {
		switch {
		case method == http.MethodGet && strings.HasSuffix(path, "/users/u1/consents"):
			return http.StatusOK, `[
			  {"clientId":"partner-web","grantedClientScopes":["scnehaux-external","basic"],"createdDate":5000,"lastUpdatedDate":6000},
			  {"clientId":"another","grantedClientScopes":[],"createdDate":1000}]`
		case method == http.MethodDelete && strings.HasSuffix(path, "/users/u1/consents/partner-web"):
			return http.StatusNoContent, ""
		}
		return http.StatusNotFound, ""
	}
	admin, _ := newAdmin(t, k)
	ctx := context.Background()
	consents, err := admin.UserConsents(ctx, testRealm, "u1")
	if err != nil || len(consents) != 2 || consents[0].ClientID != "another" || consents[1].ClientID != "partner-web" ||
		strings.Join(consents[1].Scopes, ",") != "basic,scnehaux-external" || !consents[1].Granted.Equal(time.UnixMilli(5000)) ||
		!consents[1].Updated.Equal(time.UnixMilli(6000)) || !consents[0].Updated.IsZero() {
		t.Fatalf("consents: %+v, %v", consents, err)
	}
	if err := admin.RevokeConsent(ctx, testRealm, "u1", "partner-web"); err != nil {
		t.Errorf("RevokeConsent: %v", err)
	}
	if err := admin.RevokeConsent(ctx, testRealm, "u1", "gone"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("a consent already gone: %v, want ErrNotFound", err)
	}
}

// A user's creation is read from the admin events that created it, filtered by the kernel and again
// here, with the principal_id its representation carried (ADR-IAM-001 §5.11 check 4).
func TestAUsersCreationIsReadFromItsAdminEvents(t *testing.T) {
	k := &kernel{adminStatus: http.StatusOK, adminBody: `[
	  {"id":"e1","time":7000,"operationType":"CREATE","resourceType":"USER","resourcePath":"users/u1",
	   "authDetails":{"clientId":"c-ic","userId":"sa-ic"},
	   "representation":"{\"username\":\"p\",\"attributes\":{\"scnehaux_principal_id\":[\"019a0000-0000-7000-8000-000000000001\"]}}"},
	  {"id":"e2","time":8000,"operationType":"UPDATE","resourceType":"USER","resourcePath":"users/u1",
	   "authDetails":{"userId":"sa-ic"}},
	  {"id":"e3","time":9000,"operationType":"CREATE","resourceType":"USER","resourcePath":"users/u2",
	   "authDetails":{"userId":"sa-ic"}}]`}
	admin, _ := newAdmin(t, k)
	creations, err := admin.UserCreations(context.Background(), testRealm, "u1")
	if err != nil || len(creations) != 1 || creations[0].EventID != "e1" || creations[0].ActorUserID != "sa-ic" ||
		creations[0].ClaimedPrincipalID != "019a0000-0000-7000-8000-000000000001" {
		t.Fatalf("creations: %+v, %v", creations, err)
	}
	for _, want := range []string{"operationTypes=CREATE", "resourceTypes=USER", "resourcePath=users%2Fu1"} {
		if !strings.Contains(k.lastQuery, want) {
			t.Errorf("the query %q does not filter by %s", k.lastQuery, want)
		}
	}
}
