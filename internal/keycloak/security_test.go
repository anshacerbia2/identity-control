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
