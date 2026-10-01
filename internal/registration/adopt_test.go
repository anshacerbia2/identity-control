package registration

import (
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func adoptable(converge ...string) AdoptRequest {
	return AdoptRequest{Request: Request{ClientKey: "bff", Profile: ProfileConfidential, AudienceClass: "internal",
		RedirectURIs: []string{"https://bff.example.com/cb"}}, Converge: converge}
}

// bffScopes are the sets a confidential internal client holds (tokenprofile.go).
func bffScopes() ScopeSets {
	return ScopeSets{Default: []string{"acr", "basic", "scnehaux-internal"}, Optional: []string{"scnehaux-profile"}}
}

var bffKey = keycloak.JWK{KID: "k1", N: "bg", E: "AQAB"}

func runningBFF() keycloak.Client {
	return keycloak.Client{ID: "c", ClientID: "bff", Enabled: true, RedirectURIs: []string{"https://bff.example.com/cb"},
		AccessTokenLifespan: 240, Credential: keycloak.ClientCredential{Authenticator: "client-jwt", HeldJWKS: true,
			Keys: []keycloak.JWK{bffKey}}, RFC9068: true, ClientIDClaim: "bff"}
}

func differs(plan Plan, class string) bool {
	for _, difference := range plan.Differences {
		if difference.FieldClass == class {
			return difference.Differs
		}
	}
	return false
}

// A client that already runs as declared is adoptable with nothing to converge.
func TestAMatchingClientIsAdoptable(t *testing.T) {
	plan := planAdoption(adoptable(), runningBFF(), bffScopes(), "scnehaux-internal", 240,
		[]keycloak.JWK{bffKey})
	if !plan.Adoptable || plan.Refusal != "" {
		t.Errorf("plan = %+v", plan)
	}
	for _, difference := range plan.Differences {
		if difference.Differs {
			t.Errorf("%s differs", difference.FieldClass)
		}
	}
}

// A blocking difference refuses whatever the request names; a repairable one refuses unless named.
func TestThePlanRefusesWhatTheDeclarationDoesNotMatch(t *testing.T) {
	for name, c := range map[string]struct {
		change    func(*keycloak.Client)
		converge  []string
		class     string
		adoptable bool
	}{
		"a redirect URI":            {func(c *keycloak.Client) { c.RedirectURIs = append(c.RedirectURIs, "https://evil") }, nil, ClassRedirectURIs, false},
		"a redirect URI, converged": {func(c *keycloak.Client) { c.RedirectURIs = nil }, []string{ClassTokenLifespan}, ClassRedirectURIs, false},
		"another key":               {func(c *keycloak.Client) { c.Credential.Keys = []keycloak.JWK{{KID: "k2", N: "x", E: "AQAB"}} }, nil, ClassClientKeys, false},
		"a client secret":           {func(c *keycloak.Client) { c.Credential.Authenticator = "client-secret" }, nil, ClassClientKeys, false},
		"a JWKS URL":                {func(c *keycloak.Client) { c.Credential.HeldJWKS = false }, nil, ClassClientKeys, false},
		"a lifespan, not named":     {func(c *keycloak.Client) { c.AccessTokenLifespan = 300 }, nil, ClassTokenLifespan, false},
		"a lifespan, named":         {func(c *keycloak.Client) { c.AccessTokenLifespan = 300 }, []string{ClassTokenLifespan}, ClassTokenLifespan, true},
		"disabled, not named":       {func(c *keycloak.Client) { c.Enabled = false }, nil, ClassEnabled, false},
		"disabled, named":           {func(c *keycloak.Client) { c.Enabled = false }, []string{ClassEnabled}, ClassEnabled, true},
		"no at+jwt, not named":      {func(c *keycloak.Client) { c.RFC9068 = false }, nil, ClassTokenFormat, false},
		"no client_id, named":       {func(c *keycloak.Client) { c.ClientIDClaim = "" }, []string{ClassTokenFormat}, ClassTokenFormat, true},
	} {
		client := runningBFF()
		c.change(&client)
		plan := planAdoption(adoptable(c.converge...), client, bffScopes(), "scnehaux-internal", 240,
			[]keycloak.JWK{bffKey})
		if plan.Adoptable != c.adoptable || !differs(plan, c.class) {
			t.Errorf("%s: adoptable %v, %s differs %v; plan %+v", name, plan.Adoptable, c.class, differs(plan, c.class), plan)
		}
		if !c.adoptable && plan.Refusal == "" {
			t.Errorf("%s: the refusal names nothing", name)
		}
	}

	for name, scopes := range map[string]ScopeSets{
		"without its managed scope":   {Default: []string{"acr", "basic"}, Optional: []string{"scnehaux-profile"}},
		"holding the profile scope":   {Default: []string{"acr", "basic", "profile", "scnehaux-internal"}, Optional: []string{"scnehaux-profile"}},
		"holding email as optional":   {Default: []string{"acr", "basic", "scnehaux-internal"}, Optional: []string{"email", "scnehaux-profile"}},
		"without its sign-in profile": {Default: []string{"acr", "basic", "scnehaux-internal"}, Optional: []string{}},
	} {
		plan := planAdoption(adoptable(), runningBFF(), scopes, "scnehaux-internal", 240, []keycloak.JWK{bffKey})
		if plan.Adoptable || !differs(plan, ClassAudienceScope) {
			t.Errorf("a client %s was adoptable: %+v", name, plan)
		}
	}
}
