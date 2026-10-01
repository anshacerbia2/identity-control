package registration

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

// Each profile's closed sets (TDD-identity-control-003 §Profiles).
func TestEachProfileHoldsItsScopeSets(t *testing.T) {
	for _, c := range []struct {
		profile, class    string
		defaults, options []string
		governed          bool
	}{
		{ProfileConfidential, "internal", []string{"acr", "basic", "scnehaux-internal"}, []string{"scnehaux-profile"}, true},
		{ProfilePublic, "external", []string{"acr", "basic", "scnehaux-external"}, []string{}, true},
		{ProfileWorkload, "workload", []string{"basic", "scnehaux-workload", "service_account"}, []string{}, true},
		{ProfileResource, "internal", nil, nil, false},
	} {
		got, governed := DesiredScopes(c.profile, c.class)
		if governed != c.governed || !slices.Equal(got.Default, c.defaults) || !slices.Equal(got.Optional, c.options) {
			t.Errorf("%s/%s: %+v governed %v, want %v %v", c.profile, c.class, got, governed, c.defaults, c.options)
		}
	}
	if !SameScopes(ScopeSets{Default: []string{"basic", "acr", "basic"}}, ScopeSets{Default: []string{"acr", "basic"}}) {
		t.Error("the same sets in another order compared different")
	}
	if SameScopes(ScopeSets{Default: []string{"acr", "basic"}, Optional: []string{"email"}}, ScopeSets{Default: []string{"acr", "basic"}}) {
		t.Error("an extra optional scope compared the same")
	}
}

// Converging detaches every scope outside the sets, attaches every missing one, skips one the realm
// does not declare, and leaves a converged client as it is.
func TestScopesConvergeToTheSets(t *testing.T) {
	kernel := keycloakfake.NewRegistry("service-account")
	client := keycloak.ClientUUID("kc-bff")
	kernel.Put(keycloak.Client{ID: client, ClientID: "bff", Enabled: true})
	kernel.HoldScopes(client, []string{"acr", "basic", "email", "profile", "web-origins"}, []string{"email", "offline_access"})
	desired, _ := DesiredScopes(ProfileConfidential, "internal")
	if err := ConvergeScopes(context.Background(), kernel, "realm", client, desired, time.Second); err != nil {
		t.Fatal(err)
	}
	live, err := LiveScopes(context.Background(), kernel, "realm", client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// web-origins and offline_access are not declared to the fake, so they are skipped: the realm has no
	// scope by that name to detach, and the client is left holding the identifier.
	want := ScopeSets{Default: []string{"acr", "basic", "scnehaux-internal", "web-origins"},
		Optional: []string{"offline_access", "scnehaux-profile"}}
	if !SameScopes(live, want) {
		t.Errorf("after converging: %+v, want %+v", live, want)
	}
	if err := ConvergeScopes(context.Background(), kernel, "realm", client, desired, time.Second); err != nil {
		t.Errorf("converging again: %v", err)
	}
}
