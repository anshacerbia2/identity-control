package keycloak_test

// A user's security state through the supported Admin REST API (TDD-identity-control-005
// §Component Design).

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
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
			  {"id":"k1","type":"password","createdDate":1000,"secretData":"SECRET"}]`
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
	if err != nil || len(credentials) != 2 || credentials[0].ID != "k1" || credentials[1].Label != "laptop" {
		t.Errorf("credentials: %+v, %v", credentials, err)
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
