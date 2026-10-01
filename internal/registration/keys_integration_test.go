package registration

// Client key registration, rotation and revocation against a real PostgreSQL and a fake kernel
// (TDD-identity-control-003 §Testing Strategy, Client Keys). The kernel half of the mechanism, that
// the pinned Keycloak accepts two keys, refuses a removed one at once and refuses a replayed
// assertion, is proven by identity-kernel's compat/client_keys_test.go and is not re-proven here.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// confidential is a confidential client's registration request holding the given key.
func (h *harness) confidential(clientKey string, key testKeyPair) Request {
	req := h.request(clientKey, ProfileConfidential)
	req.RedirectURIs = []string{"https://bff.example.com/callback"}
	req.PublicKey = key.public
	return req
}

func (h *harness) registerConfidential(clientKey string, key testKeyPair) (Registration, keycloak.ClientUUID) {
	h.t.Helper()
	registration, err := h.service.Register(context.Background(), h.confidential(clientKey, key))
	if err != nil {
		h.t.Fatalf("register %s: %v", clientKey, err)
	}
	_, client := h.state(registration.ID)
	return registration, keycloak.ClientUUID(client)
}

// kernelKIDs are the kids the kernel client holds now, in order.
func (h *harness) kernelKIDs(client keycloak.ClientUUID) []string {
	var kids []string
	for _, key := range h.kernel.Keys(client) {
		kids = append(kids, key.KID)
	}
	return kids
}

func byKID(keys []Key, kid string) Key {
	for _, key := range keys {
		if key.KID == kid {
			return key
		}
	}
	return Key{}
}

func (h *harness) keys(registrationID id.UUID) []Key {
	h.t.Helper()
	keys, err := h.service.Keys(context.Background(), registrationID)
	if err != nil {
		h.t.Fatalf("list keys: %v", err)
	}
	return keys
}

// A confidential client is created holding its first key, and the key is recorded as the active
// one. Nothing secret is returned, because nothing secret exists.
func TestAConfidentialClientIsCreatedHoldingItsKey(t *testing.T) {
	h := newHarness(t)
	key := testKey(t)
	before := time.Now()
	registration, client := h.registerConfidential("bff", key)

	if registration.State != "active" || registration.Profile != ProfileConfidential || registration.AccessTokenLifespan != 240 {
		t.Errorf("registration = %+v", registration)
	}
	spec, scopes, ok := h.kernel.Spec(client)
	if !ok || !spec.Confidential || !slices.Equal(spec.RedirectURIs, []string{"https://bff.example.com/callback"}) ||
		!sameIDs(scopes, "scope-acr", "scope-basic", "scope-internal") ||
		!sameIDs(h.kernel.OptionalScopes(client), "scope-sign-in") {
		t.Errorf("client spec = %+v, scopes %v and optional %v", spec, scopes, h.kernel.OptionalScopes(client))
	}
	if kids := h.kernelKIDs(client); !slices.Equal(kids, []string{key.kid}) {
		t.Errorf("the kernel holds %v, want the registered key", kids)
	}

	keys := h.keys(registration.ID)
	if len(keys) != 1 {
		t.Fatalf("%d keys recorded, want 1", len(keys))
	}
	got := keys[0]
	if got.State != KeyActive || got.KID != key.kid || got.RegisteredBy != h.caller || got.RetiringAt != nil ||
		got.ExpiresAt.Before(before.Add(DefaultKeyLifetime-time.Minute)) {
		t.Errorf("key = %+v", got)
	}
	body, _ := json.Marshal(keys)
	if strings.Contains(string(body), `"d"`) || strings.Contains(string(body), "secret") {
		t.Errorf("the key listing carries more than the public key: %s", body)
	}
}

// A private key is refused before anything is recorded or created.
func TestAPrivateKeyIsRefusedAtRegistration(t *testing.T) {
	h := newHarness(t)
	key := testKey(t)
	req := h.confidential("leaky", key)
	req.PublicKey = jwkWith(t, key, map[string]any{"d": b64(key.private.D.Bytes())})
	if _, err := h.service.Register(context.Background(), req); !errors.Is(err, ErrPrivateKey) {
		t.Fatalf("a private key answered %v, want ErrPrivateKey", err)
	}
	if n := len(h.clientsNamed("leaky")); n != 0 {
		t.Errorf("a refused registration created %d client(s)", n)
	}
	var rows int
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.client_registration WHERE realm = $1 AND client_key = 'leaky'`,
			string(testRealm)).Scan(&rows)
	}); err != nil || rows != 0 {
		t.Errorf("%d registration(s) recorded for a refused key, %v", rows, err)
	}
}

// One key pair authenticates one client only.
func TestAKeyRegisteredToOneClientIsRefusedForAnother(t *testing.T) {
	h := newHarness(t)
	key := testKey(t)
	h.registerConfidential("first", key)
	if _, err := h.service.Register(context.Background(), h.confidential("second", key)); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("a second client with the same key answered %v, want ErrKeyInUse", err)
	}
	if n := len(h.clientsNamed("second")); n != 0 {
		t.Errorf("the refused client was created %d time(s)", n)
	}
}

// A workload is refused while the realm declares no workload scope, and registered once it does.
func TestAWorkloadWaitsForTheKernelsWorkloadScope(t *testing.T) {
	h := newHarness(t)
	req := h.request("nightly-job", ProfileWorkload)
	req.AudienceClass, req.PublicKey = "workload", testKey(t).public
	if _, err := h.service.Register(context.Background(), req); !errors.Is(err, ErrScopeUndeclared) {
		t.Fatalf("a workload answered %v, want ErrScopeUndeclared", err)
	}
	// A realm made before identity-kernel narrowed its defaults attaches profile and acr to every new
	// client, as the real kernel did. A workload keeps neither: acr puts acr=1 into a client credentials
	// token, and profile puts names into it.
	h.kernel.Scopes["scnehaux-workload"] = "scope-workload"
	h.kernel.RealmDefaults = []string{"scope-profile", "scope-acr"}
	idempotencyKey, _ := id.NewV7()
	req.IdempotencyKey = idempotencyKey.String()
	workload, err := h.service.Register(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_, client := h.state(workload.ID)
	if spec, scopes, _ := h.kernel.Spec(keycloak.ClientUUID(client)); !spec.Workload || len(spec.RedirectURIs) != 0 ||
		len(spec.Keys) != 1 || !sameIDs(scopes, "scope-basic", "scope-workload") {
		t.Errorf("workload spec = %+v, scopes %v; want basic and the managed scope, and no acr or profile", spec, scopes)
	}

	// A confidential client keeps acr, which STD-IAM-002 permits outside the workload profile, and loses
	// profile, which puts personal data into an access token.
	registration, bff := h.registerConfidential("keeps-acr", testKey(t))
	if _, scopes, _ := h.kernel.Spec(bff); !sameIDs(scopes, "scope-acr", "scope-basic", "scope-internal") {
		t.Errorf("a confidential client holds %v (registration %s)", scopes, registration.ID)
	}

	// A workload's client is not recreated alone: its identity lives on the service-account user a
	// new client would not have.
	h.kernel.Remove("console-admin", keycloak.ClientUUID(client))
	if _, err := h.service.Recreate(context.Background(), workload.ID); !errors.Is(err, ErrWorkloadRecreate) {
		t.Errorf("recreating a workload's client answered %v, want ErrWorkloadRecreate", err)
	}
}

// A rotation adds the next key before the previous one goes: the kernel accepts both until the
// overlap ends. A retry of a rotation already made changes nothing, and a second rotation waits.
func TestARotationOverlapsTheKeys(t *testing.T) {
	h := newHarness(t)
	first, second := testKey(t), testKey(t)
	registration, client := h.registerConfidential("rotating", first)

	before := time.Now()
	keys, added, err := h.service.AddKey(context.Background(), registration.ID, second.public, h.caller)
	if err != nil || !added {
		t.Fatalf("AddKey = %v, added %v", err, added)
	}
	if kids := h.kernelKIDs(client); !slices.Equal(kids, []string{second.kid, first.kid}) {
		t.Errorf("the kernel holds %v, want the new key and the retiring one", kids)
	}
	previous, next := byKID(keys, first.kid), byKID(keys, second.kid)
	if previous.State != KeyRetiring || previous.RetiringAt == nil ||
		previous.RetiringAt.Before(before.Add(DefaultRotationOverlap-time.Minute)) || next.State != KeyActive {
		t.Errorf("after the rotation: previous %+v, next %+v", previous, next)
	}

	patches := h.kernel.Patches
	if _, added, err := h.service.AddKey(context.Background(), registration.ID, second.public, h.caller); err != nil || added {
		t.Errorf("a retry of the rotation answered added %v, %v; want the rotation already made", added, err)
	}
	if h.kernel.Patches != patches {
		t.Error("a retry of the rotation changed the kernel")
	}

	if _, _, err := h.service.AddKey(context.Background(), registration.ID, testKey(t).public, h.caller); !errors.Is(err, ErrRotationInProgress) {
		t.Errorf("a second rotation during the overlap answered %v", err)
	}
	if _, _, err := h.service.AddKey(context.Background(), registration.ID, first.public, h.caller); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("re-registering the retiring key answered %v", err)
	}
}

// The retiring key is removed when its overlap ends, without anyone asking, and an expired key is
// removed when its lifetime ends.
func TestKeysAreRemovedWhenTheirTimeEnds(t *testing.T) {
	h := newHarness(t)
	first, second := testKey(t), testKey(t)
	registration, client := h.registerConfidential("expiring", first)
	if _, _, err := h.service.AddKey(context.Background(), registration.ID, second.public, h.caller); err != nil {
		t.Fatal(err)
	}

	if n, err := h.service.ExpireKeys(context.Background()); n != 0 || err != nil {
		t.Errorf("ExpireKeys removed %d before any overlap ended, %v", n, err)
	}

	h.service.now = func() time.Time { return time.Now().UTC().Add(DefaultRotationOverlap + time.Hour) }
	if n, err := h.service.ExpireKeys(context.Background()); n != 1 || err != nil {
		t.Fatalf("ExpireKeys removed %d at the end of the overlap, %v; want the retiring key", n, err)
	}
	if kids := h.kernelKIDs(client); !slices.Equal(kids, []string{second.kid}) {
		t.Errorf("the kernel holds %v after the overlap, want only the new key", kids)
	}
	retired := byKID(h.keys(registration.ID), first.kid)
	if retired.State != KeyRevoked || retired.RevokedBy != nil || retired.RevocationReason != overlapEnded {
		t.Errorf("the retiring key after its overlap = %+v", retired)
	}
	if n, _ := h.service.ExpireKeys(context.Background()); n != 0 {
		t.Errorf("a second pass removed %d more", n)
	}

	h.service.now = func() time.Time { return time.Now().UTC().Add(DefaultKeyLifetime + time.Hour) }
	if n, err := h.service.ExpireKeys(context.Background()); n != 1 || err != nil {
		t.Fatalf("ExpireKeys removed %d at the end of the key's lifetime, %v", n, err)
	}
	if kids := h.kernelKIDs(client); len(kids) != 0 {
		t.Errorf("the kernel holds %v after every key expired", kids)
	}
	if expired := byKID(h.keys(registration.ID), second.kid); expired.State != KeyRevoked || expired.RevocationReason != lifetimeEnded {
		t.Errorf("the expired key = %+v", expired)
	}
}

// Revocation removes one key at once and records who and why. Revoking the last key is permitted,
// and a revoked key is never registered again.
func TestAKeyIsRevokedAtOnce(t *testing.T) {
	h := newHarness(t)
	leaked, replacement := testKey(t), testKey(t)
	registration, client := h.registerConfidential("revoking", leaked)
	leakedID := byKID(h.keys(registration.ID), leaked.kid).ID

	if _, err := h.service.RevokeKey(context.Background(), registration.ID, leakedID, h.caller, " "); !errors.Is(err, ErrInvalid) {
		t.Errorf("a revocation without a reason answered %v", err)
	}
	keys, err := h.service.RevokeKey(context.Background(), registration.ID, leakedID, h.caller, "found in a public paste")
	if err != nil {
		t.Fatal(err)
	}
	if kids := h.kernelKIDs(client); len(kids) != 0 {
		t.Errorf("the kernel still holds %v after the only key was revoked", kids)
	}
	revoked := byKID(keys, leaked.kid)
	if revoked.State != KeyRevoked || revoked.RevokedBy == nil || *revoked.RevokedBy != h.caller ||
		revoked.RevocationReason != "found in a public paste" || revoked.RevokedAt == nil {
		t.Errorf("revoked key = %+v", revoked)
	}
	if _, err := h.service.RevokeKey(context.Background(), registration.ID, leakedID, h.caller, "again"); !errors.Is(err, ErrKeyNotLive) {
		t.Errorf("revoking a revoked key answered %v", err)
	}
	if _, _, err := h.service.AddKey(context.Background(), registration.ID, leaked.public, h.caller); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("re-registering a revoked key answered %v, want ErrKeyInUse", err)
	}

	// With no active key there is nothing to retire: the replacement is simply the active key.
	keys, added, err := h.service.AddKey(context.Background(), registration.ID, replacement.public, h.caller)
	if err != nil || !added {
		t.Fatalf("AddKey after revocation = %v, added %v", err, added)
	}
	if kids := h.kernelKIDs(client); !slices.Equal(kids, []string{replacement.kid}) {
		t.Errorf("the kernel holds %v, want the replacement only", kids)
	}
	if next := byKID(keys, replacement.kid); next.State != KeyActive {
		t.Errorf("the replacement = %+v", next)
	}
}

// A kernel that refuses the change leaves the rows as they were, so the table never records a key
// the kernel was not given, and the same request succeeds once the kernel is back.
func TestAKernelRefusalLeavesTheKeysUnchanged(t *testing.T) {
	h := newHarness(t)
	first, second := testKey(t), testKey(t)
	registration, client := h.registerConfidential("refused-rotation", first)

	h.kernel.FailPatch = keycloak.ErrUnavailable
	if _, _, err := h.service.AddKey(context.Background(), registration.ID, second.public, h.caller); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("a rotation the kernel refused answered %v", err)
	}
	if keys := h.keys(registration.ID); len(keys) != 1 || keys[0].State != KeyActive {
		t.Errorf("after a refused rotation the rows are %+v, want the first key alone and active", keys)
	}

	h.kernel.FailPatch = nil
	if _, added, err := h.service.AddKey(context.Background(), registration.ID, second.public, h.caller); err != nil || !added {
		t.Fatalf("the same rotation once the kernel was back answered %v, added %v", err, added)
	}
	if kids := h.kernelKIDs(client); !slices.Equal(kids, []string{second.kid, first.kid}) {
		t.Errorf("the kernel holds %v", kids)
	}
}

func TestKeyOperationsRefuseWhatHoldsNoKey(t *testing.T) {
	h := newHarness(t)
	public, err := h.service.Register(context.Background(), h.request("keyless", ProfilePublic))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.service.AddKey(context.Background(), public.ID, testKey(t).public, h.caller); !errors.Is(err, ErrNotKeyed) {
		t.Errorf("a key for a public client answered %v", err)
	}
	nobody, _ := id.NewV7()
	if _, _, err := h.service.AddKey(context.Background(), nobody, testKey(t).public, h.caller); !errors.Is(err, ErrNotFound) {
		t.Errorf("a key for an unknown registration answered %v", err)
	}
	if _, err := h.service.Keys(context.Background(), nobody); !errors.Is(err, ErrNotFound) {
		t.Errorf("listing an unknown registration's keys answered %v", err)
	}

	h.kernel.FailCreate = keycloak.ErrUnavailable
	if _, err := h.service.Register(context.Background(), h.confidential("still-pending", testKey(t))); err == nil {
		t.Fatal("a failed create succeeded")
	}
	h.kernel.FailCreate = nil
	if _, _, err := h.service.AddKey(context.Background(), h.pendingID("still-pending"), testKey(t).public, h.caller); !errors.Is(err, ErrNotActive) {
		t.Errorf("a key for a pending registration answered %v", err)
	}
}

// A client built again, after a lost create or a console deletion, holds exactly the keys the rows
// describe: the key pairs that authenticated it before, and no other.
func TestAKeyedClientIsBuiltAgainHoldingItsKeys(t *testing.T) {
	h := newHarness(t)
	first, second := testKey(t), testKey(t)
	registration, client := h.registerConfidential("rebuilt", first)
	if _, _, err := h.service.AddKey(context.Background(), registration.ID, second.public, h.caller); err != nil {
		t.Fatal(err)
	}
	h.kernel.Remove("console-admin", client)
	recreated, err := h.service.Recreate(context.Background(), registration.ID)
	if err != nil {
		t.Fatal(err)
	}
	if kids := h.kernelKIDs(recreated); !slices.Equal(kids, []string{second.kid, first.kid}) {
		t.Errorf("the recreated client holds %v", kids)
	}

	key := testKey(t)
	h.kernel.FailCreate = keycloak.ErrUnavailable
	if _, err := h.service.Register(context.Background(), h.confidential("recovered", key)); err == nil {
		t.Fatal("a failed create succeeded")
	}
	h.kernel.FailCreate = nil
	h.age("recovered")
	if n, err := h.service.RecoverPending(context.Background()); n != 1 || err != nil {
		t.Fatalf("recovery resolved %d, %v", n, err)
	}
	found := h.clientsNamed("recovered")
	if len(found) != 1 || !slices.Equal(h.kernelKIDs(found[0].ID), []string{key.kid}) {
		t.Errorf("the recovered client holds %v", h.kernelKIDs(found[0].ID))
	}
}

// A registration refused because an unregistered client holds its client_key closes the key it
// recorded: the key never reached the kernel, and it stays on record, revoked.
func TestARefusedRegistrationClosesItsKey(t *testing.T) {
	h := newHarness(t)
	h.kernel.Put(keycloak.Client{ID: "hand-made-bff", ClientID: "hand-made-bff", Enabled: true})
	key := testKey(t)
	if _, err := h.service.Register(context.Background(), h.confidential("hand-made-bff", key)); !errors.Is(err, ErrKeyTaken) {
		t.Fatalf("registering over an unregistered client answered %v", err)
	}
	var state string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT k.state FROM identity.client_key k
		    JOIN identity.client_registration r ON r.registration_id = k.registration_id
		    WHERE r.realm = $1 AND r.client_key = 'hand-made-bff'`, string(testRealm)).Scan(&state)
	}); err != nil {
		t.Fatal(err)
	}
	if state != KeyRevoked {
		t.Errorf("the refused registration's key is %s, want revoked", state)
	}
}
