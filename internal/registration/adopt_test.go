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
	return ScopeSets{Default: []string{"acr", "basic", "scnehaux-internal"}, Optional: []string{"organization", "scnehaux-profile"}}
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

// The audience profile scope blocks (ADR-IAM-001 §5.12 rule 3, TDD-identity-control-003 1.30.0). A BFF
// the script made with scnehaux-provider, declared internal, is refused even with audience_scope named
// in converge: converging it would have replaced the provider profile, and every provider route would
// have refused the next token. Declared as what it runs, privileged in the provider-scope form, it is
// adoptable with its other scopes converged.
func TestTheProfileScopeBlocksAWrongDeclaration(t *testing.T) {
	provider := ScopeSets{Default: []string{"acr", "basic", "email", "scnehaux-provider"}, Optional: []string{}}

	wrong := adoptable(ClassAudienceScope)
	plan := planAdoption(wrong, runningBFF(), provider, "scnehaux-internal", 240, []keycloak.JWK{bffKey})
	if plan.Adoptable || !differs(plan, ClassAudienceProfile) {
		t.Fatalf("a provider client declared internal was adoptable: %+v", plan)
	}
	if plan.Refusal == "" || plan.Refusal[:len(ClassAudienceProfile)] != ClassAudienceProfile {
		t.Errorf("the refusal %q does not name %s", plan.Refusal, ClassAudienceProfile)
	}

	right := adoptable(ClassAudienceScope)
	right.AudienceClass, right.PrivilegedForm = "privileged", FormProviderScope
	plan = planAdoption(right, runningBFF(), provider, "scnehaux-provider", 240, []keycloak.JWK{bffKey})
	if !plan.Adoptable || differs(plan, ClassAudienceProfile) || !differs(plan, ClassAudienceScope) {
		t.Errorf("the same client declared as it runs: %+v; want adoptable with audience_scope converged", plan)
	}

	// No profile scope at all is a different claim surface too.
	none := ScopeSets{Default: []string{"acr", "basic"}, Optional: []string{}}
	plan = planAdoption(right, runningBFF(), none, "scnehaux-provider", 240, []keycloak.JWK{bffKey})
	if plan.Adoptable || !differs(plan, ClassAudienceProfile) {
		t.Errorf("a client holding no profile scope was adoptable: %+v", plan)
	}
}
