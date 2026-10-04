package registration

// Adoption against a real PostgreSQL and a fake kernel (TDD-identity-control-003 §Adoption): a
// client a bootstrap script created is planned, held to its declaration and keys, and recorded.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// bootstrapped puts a client in the kernel as a bootstrap script leaves it: confidential, holding the
// given keys by client-jwt, with the token profile a confidential internal client holds, and no
// registration. legacy leaves it as one made before the token profile: no at+jwt attribute, no
// client_id mapper, and the realm's old default scopes.
func (h *harness) bootstrapped(clientKey string, keys ...testKeyPair) keycloak.ClientUUID {
	h.t.Helper()
	var held []keycloak.JWK
	for _, key := range keys {
		parsed, err := parsePublicKey(key.public)
		if err != nil {
			h.t.Fatal(err)
		}
		held = append(held, parsed.JWK)
	}
	client := keycloak.ClientUUID("kc-" + clientKey)
	h.kernel.Put(keycloak.Client{ID: client, ClientID: clientKey, Enabled: true,
		RedirectURIs: []string{"https://bff.example.com/callback"}, AccessTokenLifespan: 240,
		Credential: keycloak.ClientCredential{Authenticator: "client-jwt", HeldJWKS: true, Keys: held},
		RFC9068:    true, ClientIDClaim: clientKey})
	desired, _ := DesiredScopes(ProfileConfidential, "internal")
	h.kernel.HoldScopes(client, desired.Default, desired.Optional)
	return client
}

func (h *harness) legacy(client keycloak.ClientUUID) {
	h.kernel.ConsoleChange("", client, func(c *keycloak.Client) { c.RFC9068, c.ClientIDClaim = false, "" })
	h.kernel.HoldScopes(client, []string{"acr", "basic", "email", "profile", "scnehaux-internal"}, nil)
}

func (h *harness) adoption(clientKey string, keys ...testKeyPair) AdoptRequest {
	req := h.request(clientKey, ProfileConfidential)
	req.RedirectURIs = []string{"https://bff.example.com/callback"}
	var public []json.RawMessage
	for _, key := range keys {
		public = append(public, key.public)
	}
	return AdoptRequest{Request: req, PublicKeys: public, Reason: "bring the bootstrap BFF under registration"}
}

func (h *harness) adoptions(registrationID id.UUID) (int, string, []string) {
	h.t.Helper()
	var (
		count     int
		observed  string
		converged []string
	)
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity.registration_adoption WHERE registration_id = $1`,
			registrationID.String()).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		return tx.QueryRow(ctx, `SELECT observed::text, converged FROM identity.registration_adoption
		    WHERE registration_id = $1 AND adopted_by = $2 AND reason = 'bring the bootstrap BFF under registration'`,
			registrationID.String(), h.caller.String()).Scan(&observed, &converged)
	}); err != nil {
		h.t.Fatalf("read the adoption: %v", err)
	}
	return count, observed, converged
}

func (h *harness) registrationsNamed(clientKey string) int {
	h.t.Helper()
	var count int
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.client_registration WHERE realm = $1 AND client_key = $2`,
			string(testRealm), clientKey).Scan(&count)
	}); err != nil {
		h.t.Fatal(err)
	}
	return count
}

// A dry run reports the plan and changes nothing; the adoption then records the client as an active
// registration holding its keys, with the adoption beside it.
func TestABootstrapClientIsPlannedThenAdopted(t *testing.T) {
	h := newHarness(t)
	key := testKey(t)
	client := h.bootstrapped("bootstrap-bff", key)

	req := h.adoption("bootstrap-bff", key)
	req.DryRun = true
	planned, err := h.service.Adopt(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !planned.Plan.Adoptable || planned.Registration != nil || h.registrationsNamed("bootstrap-bff") != 0 ||
		h.kernel.Patches != 0 {
		t.Fatalf("a dry run answered %+v, and recorded or changed something", planned)
	}

	req.DryRun = false
	adopted, err := h.service.Adopt(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if adopted.Registration == nil || adopted.Registration.State != "active" || adopted.Registration.Profile != ProfileConfidential {
		t.Fatalf("adopted = %+v", adopted)
	}
	if _, kc := h.state(adopted.Registration.ID); kc != string(client) {
		t.Errorf("the registration names kernel client %s, want the adopted %s", kc, client)
	}
	keys := h.keys(adopted.Registration.ID)
	if len(keys) != 1 || keys[0].State != KeyActive || keys[0].KID != key.kid {
		t.Errorf("keys = %+v", keys)
	}
	count, observed, converged := h.adoptions(adopted.Registration.ID)
	if count != 1 || len(converged) != 0 {
		t.Errorf("%d adoption record(s), converged %v", count, converged)
	}
	var snapshot map[string]any
	if err := json.Unmarshal([]byte(observed), &snapshot); err != nil || snapshot[ClassClientKeys] == nil {
		t.Errorf("the adoption records no observed credential: %s", observed)
	}

	// A replay returns the same registration and records nothing more.
	again, err := h.service.Adopt(context.Background(), req)
	if err != nil || again.Registration == nil || again.Registration.ID != adopted.Registration.ID {
		t.Errorf("a replay answered %+v, %v", again, err)
	}
	if count, _, _ := h.adoptions(adopted.Registration.ID); count != 1 {
		t.Errorf("a replay recorded %d adoptions", count)
	}
}

// A client whose redirect URIs or keys differ, or that authenticates with a secret, is refused
// before anything is changed or recorded, and the refusal carries the plan.
func TestAClientThatDoesNotMatchIsNotAdopted(t *testing.T) {
	for name, change := range map[string]func(*keycloak.Client){
		"another redirect URI": func(c *keycloak.Client) { c.RedirectURIs = append(c.RedirectURIs, "https://evil.example.net/cb") },
		"another key":          func(c *keycloak.Client) { c.Credential.Keys = []keycloak.JWK{{KID: "k", N: "n", E: "AQAB"}} },
		"a client secret":      func(c *keycloak.Client) { c.Credential.Authenticator = "client-secret" },
		"a longer lifespan":    func(c *keycloak.Client) { c.AccessTokenLifespan = 3600 },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			key := testKey(t)
			client := h.bootstrapped("mismatched-bff", key)
			h.kernel.ConsoleChange("", client, change)
			patches := h.kernel.Patches
			result, err := h.service.Adopt(context.Background(), h.adoption("mismatched-bff", key))
			if !errors.Is(err, ErrNotAdoptable) || result.Plan.Adoptable || result.Plan.Refusal == "" {
				t.Fatalf("Adopt answered %+v, %v; want ErrNotAdoptable with the plan", result, err)
			}
			if h.registrationsNamed("mismatched-bff") != 0 || h.kernel.Patches != patches {
				t.Error("a refused adoption recorded or changed something")
			}
		})
	}
}

// A repairable difference converges when named, before the record, and the record says so. A
// second key is recorded retiring, as an adoption in the middle of a rotation.
func TestANamedRepairableDifferenceConverges(t *testing.T) {
	h := newHarness(t)
	active, retiring := testKey(t), testKey(t)
	client := h.bootstrapped("rotating-bff", active, retiring)
	h.kernel.ConsoleChange("", client, func(c *keycloak.Client) {
		c.AccessTokenLifespan = 3600
		c.Enabled = false
	})
	req := h.adoption("rotating-bff", active, retiring)
	req.Converge = []string{ClassTokenLifespan, ClassEnabled}
	adopted, err := h.service.Adopt(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	live, _ := h.kernel.Client(client)
	if live.AccessTokenLifespan != 240 || !live.Enabled {
		t.Errorf("after the adoption the client is %+v, want its derived lifespan and enabled", live)
	}
	if _, _, converged := h.adoptions(adopted.Registration.ID); !slices.Equal(converged, []string{ClassTokenLifespan, ClassEnabled}) {
		t.Errorf("converged %v", converged)
	}
	keys := h.keys(adopted.Registration.ID)
	if byKID(keys, active.kid).State != KeyActive || byKID(keys, retiring.kid).State != KeyRetiring {
		t.Errorf("keys = %+v, want the first active and the second retiring", keys)
	}
}

func TestAnAdoptionRefusesWhatItCannotTake(t *testing.T) {
	h := newHarness(t)
	key := testKey(t)
	if _, err := h.service.Adopt(context.Background(), h.adoption("nowhere", key)); !errors.Is(err, ErrNoClient) {
		t.Errorf("adopting a client that does not exist answered %v", err)
	}

	registered := testKey(t)
	h.registerConfidential("already-registered", registered)
	if _, err := h.service.Adopt(context.Background(), h.adoption("already-registered", registered)); !errors.Is(err, ErrKeyTaken) {
		t.Errorf("adopting a registered client answered %v", err)
	}

	h.bootstrapped("borrowed-key", registered)
	if _, err := h.service.Adopt(context.Background(), h.adoption("borrowed-key", registered)); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("adopting with a key another client holds answered %v", err)
	}

	for name, change := range map[string]func(*AdoptRequest){
		"no reason":                    func(r *AdoptRequest) { r.Reason = " " },
		"a public client":              func(r *AdoptRequest) { r.Profile = ProfilePublic },
		"no key":                       func(r *AdoptRequest) { r.PublicKeys = nil },
		"an unknown class to converge": func(r *AdoptRequest) { r.Converge = []string{ClassRedirectURIs} },
	} {
		req := h.adoption("any-bff", key)
		change(&req)
		if _, err := h.service.Adopt(context.Background(), req); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s answered %v, want ErrInvalid", name, err)
		}
	}
}

// A client a bootstrap script made before the token profile differs in token_format and
// audience_scope. Unnamed, the adoption is refused; named, both converge before the record: the
// at+jwt attribute and the client_id mapper are written, profile and email are detached, and the
// sign-in scope is attached as an optional one.
func TestABootstrapClientMadeBeforeTheTokenProfileConvergesWhenNamed(t *testing.T) {
	h := newHarness(t)
	key := testKey(t)
	client := h.bootstrapped("legacy-bff", key)
	h.legacy(client)

	refused, err := h.service.Adopt(context.Background(), h.adoption("legacy-bff", key))
	if !errors.Is(err, ErrNotAdoptable) || !planDiffers(refused.Plan, ClassTokenFormat) ||
		!planDiffers(refused.Plan, ClassAudienceScope) {
		t.Fatalf("an unnamed legacy adoption answered %+v, %v", refused, err)
	}

	req := h.adoption("legacy-bff", key)
	req.Converge = []string{ClassTokenFormat, ClassAudienceScope}
	adopted, err := h.service.Adopt(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	live := h.live(client)
	defaults, _ := h.kernel.DefaultClientScopes(context.Background(), testRealm, client)
	optional, _ := h.kernel.OptionalClientScopes(context.Background(), testRealm, client)
	if !live.RFC9068 || live.ClientIDClaim != "legacy-bff" ||
		!sameIDs(defaults, "acr", "basic", "scnehaux-internal") || !sameIDs(optional, "organization", "scnehaux-profile") {
		t.Errorf("after the adoption: %+v, default %v, optional %v", live, defaults, optional)
	}
	if _, _, converged := h.adoptions(adopted.Registration.ID); !slices.Equal(converged,
		[]string{ClassAudienceScope, ClassTokenFormat}) {
		t.Errorf("converged %v", converged)
	}
}

func planDiffers(plan Plan, class string) bool {
	for _, difference := range plan.Differences {
		if difference.FieldClass == class {
			return difference.Differs
		}
	}
	return false
}
