package registration

// Registration against a real PostgreSQL and a fake kernel. Each test owns the rows of its own
// realm and deletes only those: the reconcile package's tests run beside these in CI, against the
// same tables.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

const testRealm = keycloak.Realm("registration-test")

type harness struct {
	t       *testing.T
	pool    *db.Pool
	kernel  *keycloakfake.Registry
	service *Service
	caller  id.UUID
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{Name: "registration-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, statement := range []string{
			`DELETE FROM identity.registration_finding WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.drift_exception WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.client_registration WHERE realm = $1`,
		} {
			if _, err := tx.Exec(ctx, statement, string(testRealm)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("empty this realm's registrations: %v", err)
	}
	kernel := keycloakfake.NewRegistry("service-account")
	service, err := New(pool, kernel, Config{Realm: testRealm, CallTimeout: time.Second, PendingRecoveryAfter: time.Minute},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	caller, _ := id.NewV7()
	return &harness{t: t, pool: pool, kernel: kernel, service: service, caller: caller}
}

func (h *harness) request(key, profile string) Request {
	idempotencyKey, _ := id.NewV7()
	req := Request{CallerScope: "principal:" + h.caller.String(), IdempotencyKey: idempotencyKey.String(),
		RegisteredBy: h.caller, ClientKey: key, Profile: profile, AudienceClass: "internal", ApplicationRef: "app-" + key}
	if profile == ProfilePublic {
		req.RedirectURIs = []string{"https://app.example.com/callback"}
	}
	return req
}

func (h *harness) resource(key, class string) Registration {
	h.t.Helper()
	req := h.request(key, ProfileResource)
	req.LifetimeClass = class
	registration, err := h.service.Register(context.Background(), req)
	if err != nil {
		h.t.Fatalf("register resource %s: %v", key, err)
	}
	return registration
}

func (h *harness) state(registrationID id.UUID) (string, string) {
	h.t.Helper()
	var state, client string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, coalesce(kc_client_id, '') FROM identity.client_registration
		    WHERE registration_id = $1`, registrationID.String()).Scan(&state, &client)
	}); err != nil {
		h.t.Fatalf("read state: %v", err)
	}
	return state, client
}

func (h *harness) clientsNamed(key string) []keycloak.Client {
	found, _ := h.kernel.FindClients(context.Background(), testRealm, key)
	return found
}

// A public client is created from desired state: exact redirect URIs, the managed scope of its
// audience class, an audience mapper per resource, and a lifespan derived from those resources.
func TestAPublicClientIsCreatedFromDesiredState(t *testing.T) {
	h := newHarness(t)
	h.resource("orders", "L1")
	h.resource("partners", "L2")

	req := h.request("web", ProfilePublic)
	req.Audience = []string{"orders", "partners"}
	registration, err := h.service.Register(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if registration.State != "active" || registration.AccessTokenLifespan != 540 || registration.SigningAlgorithm != "PS256" ||
		registration.ApplicationAuthority != "manual" || registration.RegisteredBy != h.caller {
		t.Errorf("registration = %+v", registration)
	}
	_, client := h.state(registration.ID)
	spec, scopes, ok := h.kernel.Spec(keycloak.ClientUUID(client))
	if !ok {
		t.Fatalf("no client %s was created", client)
	}
	if !spec.Public || spec.AccessTokenLifespan != 540 || !slices.Equal(spec.Audience, req.Audience) ||
		!slices.Equal(spec.RedirectURIs, req.RedirectURIs) {
		t.Errorf("client spec = %+v", spec)
	}
	if !slices.Equal(scopes, []string{"scope-internal"}) {
		t.Errorf("default scopes = %v, want exactly the internal managed scope", scopes)
	}

	read, err := h.service.Get(context.Background(), registration.ID)
	if err != nil || read.ClientKey != "web" || read.AccessTokenLifespan != 540 {
		t.Errorf("Get = %+v, %v", read, err)
	}
}

func TestAReplayedKeyCreatesNothingMore(t *testing.T) {
	h := newHarness(t)
	req := h.request("replayed", ProfilePublic)
	first, err := h.service.Register(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.service.Register(context.Background(), req)
	if err != nil || second.ID != first.ID {
		t.Errorf("a replay answered %+v, %v; want the first registration", second, err)
	}
	if n := len(h.clientsNamed("replayed")); n != 1 {
		t.Errorf("%d clients exist after a replay, want 1", n)
	}
}

func TestTheValidationRulesRefuse(t *testing.T) {
	h := newHarness(t)
	h.resource("orders", "L1")
	for name, c := range map[string]struct {
		change func(*Request)
		want   error
	}{
		"a wildcard redirect":        {func(r *Request) { r.RedirectURIs = []string{"https://*.example.com/cb"} }, ErrInvalid},
		"plain http off loopback":    {func(r *Request) { r.RedirectURIs = []string{"http://app.example.com/cb"} }, ErrInvalid},
		"a fragment":                 {func(r *Request) { r.RedirectURIs = []string{"https://app.example.com/cb#x"} }, ErrInvalid},
		"a traversal":                {func(r *Request) { r.RedirectURIs = []string{"https://app.example.com/a/../cb"} }, ErrInvalid},
		"credentials in the URI":     {func(r *Request) { r.RedirectURIs = []string{"https://u:p@app.example.com/cb"} }, ErrInvalid},
		"a relative redirect":        {func(r *Request) { r.RedirectURIs = []string{"/callback"} }, ErrInvalid},
		"no redirect":                {func(r *Request) { r.RedirectURIs = nil }, ErrInvalid},
		"no Application reference":   {func(r *Request) { r.ApplicationRef = " " }, ErrInvalid},
		"a confidential client":      {func(r *Request) { r.Profile = ProfileConfidential }, ErrProfileNotBuilt},
		"an unknown profile":         {func(r *Request) { r.Profile = "native" }, ErrInvalid},
		"a declared client lifetime": {func(r *Request) { r.LifetimeClass = "L2" }, ErrInvalid},
		"an unknown audience class":  {func(r *Request) { r.AudienceClass = "everyone" }, ErrInvalid},
		"an undeclared scope":        {func(r *Request) { r.AudienceClass = "workload" }, ErrScopeUndeclared},
		"a malformed client_key":     {func(r *Request) { r.ClientKey = "Web App" }, ErrInvalid},
		"an unregistered audience":   {func(r *Request) { r.Audience = []string{"orders", "nobody"} }, ErrInvalid},
		"no caller":                  {func(r *Request) { r.RegisteredBy = id.UUID{} }, ErrInvalid},
		"no Idempotency-Key":         {func(r *Request) { r.IdempotencyKey = "" }, ErrInvalid},
	} {
		req := h.request("checked", ProfilePublic)
		c.change(&req)
		if _, err := h.service.Register(context.Background(), req); !errors.Is(err, c.want) {
			t.Errorf("%s: Register answered %v, want %v", name, err, c.want)
		}
	}
	for name, change := range map[string]func(*Request){
		"a resource without a lifetime class": func(r *Request) { r.LifetimeClass = "" },
		"a resource with redirect URIs":       func(r *Request) { r.RedirectURIs = []string{"https://a.example.com/cb"} },
		"a resource with an audience":         func(r *Request) { r.Audience = []string{"orders"} },
	} {
		req := h.request("resource-checked", ProfileResource)
		req.LifetimeClass = "L1"
		change(&req)
		if _, err := h.service.Register(context.Background(), req); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Register answered %v, want ErrInvalid", name, err)
		}
	}
	if n := len(h.clientsNamed("checked")) + len(h.clientsNamed("resource-checked")); n != 0 {
		t.Errorf("a refused registration created %d client(s)", n)
	}
	loopback := h.request("loopback", ProfilePublic)
	loopback.RedirectURIs = []string{"http://127.0.0.1:8099/callback"}
	if _, err := h.service.Register(context.Background(), loopback); err != nil {
		t.Errorf("a loopback http redirect for local development was refused: %v", err)
	}
}

// A key an active registration holds is refused, and so is one a Keycloak client nobody registered
// holds: adopting it would take over a client someone else configured.
func TestAKeyInUseIsRefused(t *testing.T) {
	h := newHarness(t)
	if _, err := h.service.Register(context.Background(), h.request("taken", ProfilePublic)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Register(context.Background(), h.request("taken", ProfilePublic)); !errors.Is(err, ErrKeyTaken) {
		t.Errorf("a second registration of an active key answered %v", err)
	}

	h.kernel.Put(keycloak.Client{ID: "hand-made", ClientID: "identity-control-caller", Enabled: true})
	req := h.request("identity-control-caller", ProfilePublic)
	if _, err := h.service.Register(context.Background(), req); !errors.Is(err, ErrKeyTaken) {
		t.Fatalf("registering over an unregistered Keycloak client answered %v", err)
	}
	if _, err := h.service.Register(context.Background(), req); !errors.Is(err, ErrKeyTaken) {
		t.Errorf("a retry of the refused request answered %v, want the same refusal", err)
	}
	if got := h.live("hand-made"); got.ClientID != "identity-control-caller" || len(h.clientsNamed("identity-control-caller")) != 1 {
		t.Error("the unregistered client was changed or duplicated")
	}
}

func (h *harness) live(client keycloak.ClientUUID) keycloak.Client {
	c, _ := h.kernel.Client(client)
	return c
}

func (h *harness) age(key string) {
	h.t.Helper()
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.client_registration SET created_at = now() - interval '1 hour'
		    WHERE realm = $1 AND client_key = $2`, string(testRealm), key)
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) pendingID(key string) id.UUID {
	h.t.Helper()
	var raw string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT registration_id::text FROM identity.client_registration
		    WHERE realm = $1 AND client_key = $2 AND state = 'pending'`, string(testRealm), key).Scan(&raw)
	}); err != nil {
		h.t.Fatalf("find the pending registration: %v", err)
	}
	parsed, _ := id.Parse(raw)
	return parsed
}

// A create whose response was lost leaves the registration pending, and recovery adopts the client
// the kernel did create rather than creating a second one.
func TestRecoveryAdoptsAClientWhoseCreationWasNotConfirmed(t *testing.T) {
	h := newHarness(t)
	h.kernel.FailCreate, h.kernel.AmbiguousCreateSucceeds = keycloak.ErrAmbiguous, true
	if _, err := h.service.Register(context.Background(), h.request("lost-response", ProfilePublic)); !errors.Is(err, keycloak.ErrAmbiguous) {
		t.Fatalf("an ambiguous create answered %v", err)
	}
	pending := h.pendingID("lost-response")
	h.kernel.FailCreate, h.kernel.AmbiguousCreateSucceeds = nil, false

	if n, _ := h.service.RecoverPending(context.Background()); n != 0 {
		t.Errorf("recovery resolved %d registration(s) younger than the threshold", n)
	}
	h.age("lost-response")
	if n, err := h.service.RecoverPending(context.Background()); n != 1 || err != nil {
		t.Fatalf("recovery resolved %d, %v", n, err)
	}
	state, client := h.state(pending)
	if state != "active" || len(h.clientsNamed("lost-response")) != 1 || h.clientsNamed("lost-response")[0].ID != keycloak.ClientUUID(client) {
		t.Errorf("after recovery: state %s, client %s, %d client(s)", state, client, len(h.clientsNamed("lost-response")))
	}
	if _, scopes, _ := h.kernel.Spec(keycloak.ClientUUID(client)); !slices.Equal(scopes, []string{"scope-internal"}) {
		t.Errorf("the adopted client's scopes = %v", scopes)
	}
}

func TestRecoveryCreatesAClientThatNeverLanded(t *testing.T) {
	h := newHarness(t)
	h.kernel.FailCreate = keycloak.ErrUnavailable
	if _, err := h.service.Register(context.Background(), h.request("never-landed", ProfilePublic)); err == nil {
		t.Fatal("a failed create succeeded")
	}
	pending := h.pendingID("never-landed")
	h.kernel.FailCreate = nil
	h.age("never-landed")
	if n, err := h.service.RecoverPending(context.Background()); n != 1 || err != nil {
		t.Fatalf("recovery resolved %d, %v", n, err)
	}
	if state, _ := h.state(pending); state != "active" || len(h.clientsNamed("never-landed")) != 1 {
		t.Errorf("after recovery: state %s, %d client(s)", state, len(h.clientsNamed("never-landed")))
	}
}

func TestRecreateBuildsADeletedClientAgain(t *testing.T) {
	h := newHarness(t)
	registration, err := h.service.Register(context.Background(), h.request("deleted", ProfilePublic))
	if err != nil {
		t.Fatal(err)
	}
	_, before := h.state(registration.ID)
	h.kernel.Remove("console-admin", keycloak.ClientUUID(before))

	client, err := h.service.Recreate(context.Background(), registration.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, after := h.state(registration.ID); after != string(client) || after == before {
		t.Errorf("kc_client_id is %s after recreation, want the new client %s", after, client)
	}
	if spec, scopes, ok := h.kernel.Spec(client); !ok || !spec.Public || len(scopes) != 1 {
		t.Errorf("recreated client spec %+v scopes %v", spec, scopes)
	}
}

func TestAnUnknownRegistrationIsNotFound(t *testing.T) {
	h := newHarness(t)
	nobody, _ := id.NewV7()
	if _, err := h.service.Get(context.Background(), nobody); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get answered %v", err)
	}
	if _, err := h.service.Recreate(context.Background(), nobody); !errors.Is(err, ErrNotFound) {
		t.Errorf("Recreate answered %v", err)
	}
}
