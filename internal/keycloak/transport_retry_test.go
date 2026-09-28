package keycloak_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// A kernel that restarted can refuse a token it issued before. The client drops the cached token
// and sends the request once more; a 403, which is the role rather than the token, is not retried.
func TestAStaleTokenIsReplacedOnce(t *testing.T) {
	for name, c := range map[string]struct {
		statuses   []int
		wantErr    error
		wantAdmin  int32
		wantTokens int32
	}{
		"a restarted kernel":   {[]int{http.StatusUnauthorized, http.StatusOK}, nil, 2, 2},
		"a credential refused": {[]int{http.StatusUnauthorized, http.StatusUnauthorized}, keycloak.ErrForbidden, 2, 2},
		"a role missing":       {[]int{http.StatusForbidden}, keycloak.ErrForbidden, 1, 1},
	} {
		t.Run(name, func(t *testing.T) {
			var tokens, admin atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("/realms/", func(w http.ResponseWriter, _ *http.Request) {
				tokens.Add(1)
				_, _ = io.WriteString(w, `{"access_token":"t","expires_in":300}`)
			})
			mux.HandleFunc("/admin/", func(w http.ResponseWriter, _ *http.Request) {
				call := int(admin.Add(1)) - 1
				w.WriteHeader(c.statuses[min(call, len(c.statuses)-1)])
				_, _ = io.WriteString(w, `{"id":"c1","clientId":"web"}`)
			})
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			client, err := keycloak.NewAdmin(keycloak.AdminConfig{BaseURL: server.URL, Realm: testRealm,
				ClientID: "identity-control-registration", ClientSecret: testSecret}, nil)
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.GetClient(context.Background(), testRealm, "c1")
			if (c.wantErr == nil) != (err == nil) || (c.wantErr != nil && !errors.Is(err, c.wantErr)) {
				t.Errorf("GetClient answered %v, want %v", err, c.wantErr)
			}
			if admin.Load() != c.wantAdmin || tokens.Load() != c.wantTokens {
				t.Errorf("%d admin call(s) and %d token call(s), want %d and %d",
					admin.Load(), tokens.Load(), c.wantAdmin, c.wantTokens)
			}
			if err != nil && strings.Contains(err.Error(), testSecret) {
				t.Error("the error carries the secret")
			}
		})
	}
}
