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
			Keys: []keycloak.JWK{bffKey}}, RFC9068: true, ClientIDClaim: "bff",
		Logout: keycloak.DesiredLogout("")}
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
	plan := planAdoption(adoptable(), runningBFF(), bffScopes(), 240,
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
		// ADR-IAM-009 §5.2: a client using front-channel logout gets no back channel from the kernel.
		"front-channel logout, not named": {func(c *keycloak.Client) { c.Logout.FrontChannel = true }, nil, ClassLogout, false},
		"front-channel logout, named":     {func(c *keycloak.Client) { c.Logout.FrontChannel = true }, []string{ClassLogout}, ClassLogout, true},
		"a back-channel URL nobody declared": {func(c *keycloak.Client) { c.Logout.BackChannelURL = "https://elsewhere/logout" },
			[]string{ClassLogout}, ClassLogout, true},
	} {
		client := runningBFF()
		c.change(&client)
		plan := planAdoption(adoptable(c.converge...), client, bffScopes(), 240,
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
		plan := planAdoption(adoptable(), runningBFF(), scopes, 240, []keycloak.JWK{bffKey})
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
	plan := planAdoption(wrong, runningBFF(), provider, 240, []keycloak.JWK{bffKey})
	if plan.Adoptable || !differs(plan, ClassAudienceProfile) {
		t.Fatalf("a provider client declared internal was adoptable: %+v", plan)
	}
	if plan.Refusal == "" || plan.Refusal[:len(ClassAudienceProfile)] != ClassAudienceProfile {
		t.Errorf("the refusal %q does not name %s", plan.Refusal, ClassAudienceProfile)
	}

	right := adoptable(ClassAudienceScope)
	right.AudienceClass, right.PrivilegedForm = "privileged", FormProviderScope
	plan = planAdoption(right, runningBFF(), provider, 240, []keycloak.JWK{bffKey})
	if !plan.Adoptable || differs(plan, ClassAudienceProfile) || !differs(plan, ClassAudienceScope) {
		t.Errorf("the same client declared as it runs: %+v; want adoptable with audience_scope converged", plan)
	}

	// No profile scope at all is a different claim surface too.
	none := ScopeSets{Default: []string{"acr", "basic"}, Optional: []string{}}
	plan = planAdoption(right, runningBFF(), none, 240, []keycloak.JWK{bffKey})
	if plan.Adoptable || !differs(plan, ClassAudienceProfile) {
		t.Errorf("a client holding no profile scope was adoptable: %+v", plan)
	}
}

// A per-sign-in client holds no profile scope as a default (ADR-IAM-008 §5.1): one holding both
// forms' scopes as optional ones is adoptable, and one holding either as a default is refused, since
// every token it is issued would then carry that form whatever the sign-in asked for.
func TestAPerSignInClientHoldsNoDefaultProfile(t *testing.T) {
	perSignIn := adoptable(ClassAudienceScope)
	perSignIn.AudienceClass, perSignIn.PrivilegedForm = "privileged", FormPerSignIn
	held := ScopeSets{Default: []string{"acr", "basic"},
		Optional: []string{"organization", "scnehaux-privileged", "scnehaux-profile", "scnehaux-provider"}}
	plan := planAdoption(perSignIn, runningBFF(), held, 240, []keycloak.JWK{bffKey})
	if !plan.Adoptable || differs(plan, ClassAudienceProfile) || differs(plan, ClassAudienceScope) {
		t.Errorf("a per-sign-in client holding its sets: %+v; want adoptable as it is", plan)
	}

	provider := ScopeSets{Default: []string{"acr", "basic", "scnehaux-provider"}, Optional: held.Optional}
	plan = planAdoption(perSignIn, runningBFF(), provider, 240, []keycloak.JWK{bffKey})
	if plan.Adoptable || !differs(plan, ClassAudienceProfile) {
		t.Errorf("a per-sign-in client holding scnehaux-provider as a default was adoptable: %+v", plan)
	}
}

// The declaration's back-channel logout URI is what the logout class compares and converges to
// (ADR-IAM-009 §5.1).
func TestAdoptionComparesTheDeclaredBackChannelLogoutURI(t *testing.T) {
	declared := adoptable(ClassLogout)
	declared.BackChannelLogoutURI = "https://bff.example.com/auth/back-channel-logout"
	plan := planAdoption(declared, runningBFF(), bffScopes(), 240, []keycloak.JWK{bffKey})
	if !plan.Adoptable || !differs(plan, ClassLogout) || plan.backChannelLogoutURI != declared.BackChannelLogoutURI {
		t.Errorf("a client without the declared URI: %+v", plan)
	}
	client := runningBFF()
	client.Logout = keycloak.DesiredLogout(declared.BackChannelLogoutURI)
	if plan := planAdoption(declared, client, bffScopes(), 240, []keycloak.JWK{bffKey}); differs(plan, ClassLogout) {
		t.Errorf("a client holding the declared URI differs: %+v", plan)
	}
}
