package keycloak_test

// A first credential through the supported Admin REST API (ADR-IAM-010, TDD-identity-control-005
// 2.12.0): the required actions read, and reset-password with temporary on.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func TestAFirstCredentialCallsTheDocumentedEndpoints(t *testing.T) {
	k := &kernel{}
	k.route = func(method, path string) (int, string) {
		switch {
		case method == http.MethodGet && strings.HasSuffix(path, "/users/u1"):
			return http.StatusOK, `{"id":"u1","username":"new.person","requiredActions":["UPDATE_PASSWORD","CONFIGURE_TOTP"]}`
		case method == http.MethodGet && strings.HasSuffix(path, "/users/u2"):
			return http.StatusOK, `{"id":"u2","username":"settled.person","requiredActions":[]}`
		case method == http.MethodPut && strings.HasSuffix(path, "/users/u1/reset-password"):
			return http.StatusNoContent, ""
		case strings.HasSuffix(path, "/users/refused/reset-password"):
			return http.StatusBadRequest, `{"error":"invalidPasswordHistoryMessage"}`
		}
		return http.StatusNotFound, ""
	}
	admin, _ := newAdmin(t, k)
	ctx := context.Background()

	actions, err := admin.UserRequiredActions(ctx, testRealm, "u1")
	if err != nil || !keycloak.OwesPassword(actions) {
		t.Fatalf("u1's actions: %v, %v", actions, err)
	}
	if actions, err := admin.UserRequiredActions(ctx, testRealm, "u2"); err != nil || keycloak.OwesPassword(actions) {
		t.Fatalf("u2's actions: %v, %v", actions, err)
	}
	if _, err := admin.UserRequiredActions(ctx, testRealm, "gone"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("an absent user: %v", err)
	}

	const value = "ABCDEFGHJKMNPQRSTVWXYZ01"
	if err := admin.SetTemporaryPassword(ctx, testRealm, "u1", value); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodPut || !strings.HasSuffix(k.lastPath, "/users/u1/reset-password") ||
		string(k.lastBody) != `{"temporary":true,"type":"password","value":"`+value+`"}` {
		t.Fatalf("reset-password sent %s %s %s", k.lastMethod, k.lastPath, k.lastBody)
	}
	// A refusal names the call and never the value.
	err = admin.SetTemporaryPassword(ctx, testRealm, "refused", value)
	if err == nil || strings.Contains(err.Error(), value) {
		t.Fatalf("a refused set answered %v", err)
	}
	for name, call := range map[string]func() error{
		"set without a user":  func() error { return admin.SetTemporaryPassword(ctx, testRealm, "", value) },
		"set without a value": func() error { return admin.SetTemporaryPassword(ctx, testRealm, "u1", "") },
		"read without a user": func() error { _, err := admin.UserRequiredActions(ctx, testRealm, ""); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s was sent", name)
		}
	}
}
