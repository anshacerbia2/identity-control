package reconcile

// The reconciler against a real PostgreSQL and a fake kernel, one test per behaviour
// TDD-identity-control-003 §Drift Reconciliation states. The database is real because the rules
// that matter live in it: one open finding per divergence, one sweep at a time, and a lifespan
// derived from the audience's lifetime classes.
//
// Skips without TEST_DATABASE_URL, and fails on a skip when REQUIRE_INTEGRATION is set. Each test
// empties this realm's rows first.

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
	clientregistration "github.com/anshacerbia2/identity-control/internal/registration"
)

const (
	realm          = keycloak.Realm("scnehaux")
	serviceAccount = "service-account-identity-control-registration"
	admin          = "console-admin"
	callbackURI    = "https://app.example.com/callback"
	takeoverURI    = "https://attacker.example.net/callback"
)

type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

type harness struct {
	t          *testing.T
	pool       *db.Pool
	kernel     *keycloakfake.Registry
	reconciler *Reconciler
	clock      *clock
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
	pool, err := db.Open(ctx, db.Config{Name: "reconcile-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// This realm's rows only: the registration package's tests use the same tables beside
		// these in CI, in a realm of their own. Runs carry no realm and are this package's alone.
		for _, statement := range []string{
			`DELETE FROM identity.registration_finding WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.drift_exception WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.client_key WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.registration_adoption WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.registration_finding WHERE registration_id IS NULL AND $1 <> ''`,
			`DELETE FROM identity.reconcile_run WHERE $1 <> ''`,
			`DELETE FROM identity.client_registration WHERE realm = $1`,
		} {
			if _, err := tx.Exec(ctx, statement, string(realm)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("empty the registration tables: %v", err)
	}

	c := &clock{at: time.Now().UTC().Truncate(time.Millisecond)}
	kernel := keycloakfake.NewRegistry(serviceAccount)
	kernel.Now = c.now
	reconciler, err := New(pool, kernel, Config{Realm: realm, Interval: time.Minute, ExemptClients: BuiltInClients},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	reconciler.now = c.now
	return &harness{t: t, pool: pool, kernel: kernel, reconciler: reconciler, clock: c}
}

// tick moves time on, past the previous run, as the next scheduled sweep would find it.
func (h *harness) tick(d time.Duration) { h.clock.at = h.clock.at.Add(d) }

type registered struct {
	id     id.UUID
	client keycloak.ClientUUID

	// key is the one key a confidential or workload registration holds.
	key keycloak.JWK
}

// register stores an active registration and the client Keycloak holds for it, in sync.
func (h *harness) register(key, profile, lifetimeClass string, audience, redirects []string) registered {
	h.t.Helper()
	registrationID, _ := id.NewV7()
	client := keycloak.ClientUUID("kc-" + key)
	var lifetime any
	if lifetimeClass != "" {
		lifetime = lifetimeClass
	}
	audienceClass := "internal"
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.client_registration
		    (registration_id, kc_client_id, realm, client_key, profile, application_authority, application_ref,
		     registered_by, audience_class, lifetime_class, audience, redirect_uris, state)
		    VALUES ($1, $2, $3, $4, $5, 'manual', 'test', $6, $7, $8, $9, $10, 'active')`,
			registrationID.String(), string(client), string(realm), key, profile, registrationID.String(),
			audienceClass, lifetime, audience, redirects)
		if err != nil {
			return err
		}
		if profile != "confidential" && profile != "workload" {
			return nil
		}
		keyID, _ := id.NewV7()
		_, err = tx.Exec(ctx, `INSERT INTO identity.client_key
		    (key_id, registration_id, kid, thumbprint, public_jwk, state, registered_by, expires_at)
		    VALUES ($1, $2, $3, $4, $5::jsonb, 'active', $2, now() + interval '90 days')`,
			keyID.String(), registrationID.String(), "kid-"+key, "tp-"+keyID.String(),
			`{"kty":"RSA","kid":"kid-`+key+`","use":"sig","alg":"PS256","n":"n-`+key+`","e":"AQAB"}`)
		return err
	}); err != nil {
		h.t.Fatalf("register %s: %v", key, err)
	}
	out := registered{id: registrationID, client: client}
	if profile == "confidential" || profile == "workload" {
		out.key = keycloak.JWK{KID: "kid-" + key, N: "n-" + key, E: "AQAB"}
	}
	return out
}

// heldBy is the credential a client holding exactly the given keys has.
func heldBy(keys ...keycloak.JWK) keycloak.ClientCredential {
	return keycloak.ClientCredential{Authenticator: "client-jwt", HeldJWKS: true, Keys: keys}
}

// caller registers a confidential client whose audience is one L0 resource, so its lifespan is
// 240 seconds, and puts the matching client in the kernel.
func (h *harness) caller() registered {
	resource := h.register("identity-control", "resource", "L0", nil, nil)
	h.kernel.Put(keycloak.Client{ID: resource.client, ClientID: "identity-control", Enabled: true})
	r := h.register("identity-control-caller", "confidential", "", []string{"identity-control"}, []string{callbackURI})
	h.kernel.Put(keycloak.Client{ID: r.client, ClientID: "identity-control-caller", Enabled: true,
		RedirectURIs: []string{callbackURI}, AccessTokenLifespan: 240, Credential: heldBy(r.key)})
	return r
}

func (h *harness) sweep() Run {
	h.t.Helper()
	run, err := h.reconciler.Sweep(context.Background())
	if err != nil {
		h.t.Fatalf("sweep: %v", err)
	}
	return run
}

type findingRow struct {
	id                              id.UUID
	class, field, actor, resolvedBy string
	changedAt, convergedAt          *time.Time
	detectedAt                      time.Time
}

func (h *harness) findings(client keycloak.ClientUUID) []findingRow {
	h.t.Helper()
	var out []findingRow
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT finding_id::text, finding_class, coalesce(field_class, ''), coalesce(actor, ''),
		    coalesce(resolved_by::text, ''), changed_at, converged_at, detected_at
		    FROM identity.registration_finding WHERE kc_client_id = $1 ORDER BY detected_at, finding_id`, string(client))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw string
				f   findingRow
			)
			if err := rows.Scan(&raw, &f.class, &f.field, &f.actor, &f.resolvedBy, &f.changedAt, &f.convergedAt, &f.detectedAt); err != nil {
				return err
			}
			f.id, _ = id.Parse(raw)
			out = append(out, f)
		}
		return rows.Err()
	}); err != nil {
		h.t.Fatalf("read findings: %v", err)
	}
	return out
}

func (h *harness) live(client keycloak.ClientUUID) keycloak.Client {
	h.t.Helper()
	c, ok := h.kernel.Client(client)
	if !ok {
		h.t.Fatalf("the kernel has no client %s", client)
	}
	return c
}

// The first scenario of the drift proof: an administrator changes a client's access token lifespan
// in the console, and the next sweep restores it, attributed, with its convergence time.
func TestALifespanChangedInTheConsoleIsRepaired(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()

	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 3600 })
	h.tick(2 * time.Second)
	run := h.sweep()

	if run.Outcome != Drift || run.Findings != 1 || run.Attribution == nil || !*run.Attribution {
		t.Errorf("run = %+v, want drift with one finding and attribution", run)
	}
	if got := h.live(caller.client).AccessTokenLifespan; got != 240 {
		t.Errorf("the lifespan is %d after the sweep, want 240 restored", got)
	}
	findings := h.findings(caller.client)
	if len(findings) != 1 {
		t.Fatalf("%d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.class != string(Repaired) || f.field != string(TokenLifespan) || f.actor != admin {
		t.Errorf("finding = %+v, want repaired token_lifespan attributed to %s", f, admin)
	}
	if f.changedAt == nil || f.convergedAt == nil || f.convergedAt.Sub(*f.changedAt) != 2*time.Second {
		t.Errorf("convergence is changed_at %v to converged_at %v, want the 2s between the change and the sweep",
			f.changedAt, f.convergedAt)
	}

	// Idempotent against a consistent state.
	h.tick(time.Minute)
	patches := h.kernel.Patches
	if again := h.sweep(); again.Outcome != Converged || again.Findings != 0 || h.kernel.Patches != patches {
		t.Errorf("a sweep over a consistent state reported %+v and patched %d time(s)", again, h.kernel.Patches-patches)
	}
}

// The second scenario: a redirect URI changed in the console is blocked, not restored, and stays
// blocked until an operator lifts it, even if someone fixes the URI by hand.
func TestARedirectURIChangedInTheConsoleIsBlocked(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()

	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) {
		c.RedirectURIs = append(c.RedirectURIs, takeoverURI)
	})
	h.tick(time.Second)
	h.sweep()

	client := h.live(caller.client)
	if client.Enabled {
		t.Error("the client is still enabled after its redirect URIs changed in the console")
	}
	if !slices.Contains(client.RedirectURIs, takeoverURI) {
		t.Error("the changed redirect URI was removed; it must be kept for whoever investigates")
	}
	findings := h.findings(caller.client)
	if len(findings) != 1 || findings[0].class != string(Blocked) || findings[0].convergedAt != nil {
		t.Fatalf("findings = %+v, want one open blocked finding", findings)
	}

	// The next sweep keeps the one finding and does not patch the client again.
	h.tick(time.Minute)
	patches := h.kernel.Patches
	h.sweep()
	if len(h.findings(caller.client)) != 1 || h.kernel.Patches != patches {
		t.Errorf("a second sweep opened another finding or patched again")
	}

	// A console fix does not lift the block.
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.RedirectURIs = []string{callbackURI} })
	h.tick(time.Minute)
	h.sweep()
	if f := h.findings(caller.client); f[0].convergedAt != nil || h.live(caller.client).Enabled {
		t.Fatal("a console fix of the URIs lifted the block without an operator")
	}

	operator, _ := id.NewV7()
	if err := h.reconciler.Resolve(context.Background(), Resolution{Findings: []id.UUID{findings[0].id},
		ResolvedBy: operator, Reason: "investigated: the URI was added by mistake"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	client = h.live(caller.client)
	if !client.Enabled || !sameSet(client.RedirectURIs, []string{callbackURI}) {
		t.Errorf("after the operator's reconcile the client is %+v, want enabled with its desired URIs", client)
	}
	if f := h.findings(caller.client)[0]; f.convergedAt == nil || f.resolvedBy != operator.String() {
		t.Errorf("the finding is %+v, want converged and resolved by the operator", f)
	}
}

// A change an unexpired exception covers is left in place. When the exception expires, the next
// sweep repairs it: the attribution stays on the finding after the admin event leaves the window.
func TestASanctionedChangeIsRepairedOnceItsExceptionExpires(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()

	grantor, _ := id.NewV7()
	if _, err := h.reconciler.GrantException(context.Background(), Exception{Registration: caller.id,
		FieldClass: TokenLifespan, Actor: admin, Reason: "load test", GrantedBy: grantor}, 10*time.Minute); err != nil {
		t.Fatalf("grant exception: %v", err)
	}
	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 900 })
	h.tick(time.Second)
	h.sweep()

	if got := h.live(caller.client).AccessTokenLifespan; got != 900 {
		t.Errorf("a sanctioned lifespan was changed to %d", got)
	}
	if f := h.findings(caller.client); len(f) != 1 || f[0].class != string(Sanctioned) || f[0].convergedAt != nil {
		t.Fatalf("findings = %+v, want one open sanctioned finding", f)
	}

	h.tick(15 * time.Minute)
	h.sweep()
	if got := h.live(caller.client).AccessTokenLifespan; got != 240 {
		t.Errorf("the lifespan is %d after the exception expired, want 240", got)
	}
	f := h.findings(caller.client)
	if len(f) != 1 || f[0].class != string(Repaired) || f[0].actor != admin || f[0].convergedAt == nil {
		t.Errorf("findings = %+v, want the same finding repaired and still attributed to %s", f, admin)
	}

	// The expired exception is still listed, as the record of why the change was left in place, and
	// a later one is listed before it.
	if _, err := h.reconciler.GrantException(context.Background(), Exception{Registration: caller.id,
		FieldClass: RedirectURIs, Actor: admin, Reason: "second fix", GrantedBy: grantor}, time.Hour); err != nil {
		t.Fatalf("grant a second exception: %v", err)
	}
	listed, err := h.reconciler.ExceptionsFor(context.Background(), caller.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].FieldClass != RedirectURIs || listed[1].FieldClass != TokenLifespan ||
		listed[1].Reason != "load test" || listed[1].GrantedBy != grantor || !listed[1].ExpiresAt.Before(h.clock.now()) {
		t.Errorf("exceptions = %+v, want the second, then the expired first", listed)
	}
}

// Another administrator's change is not covered by an exception naming someone else.
func TestAnExceptionCoversOnlyTheUserItNames(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()
	grantor, _ := id.NewV7()
	if _, err := h.reconciler.GrantException(context.Background(), Exception{Registration: caller.id,
		FieldClass: TokenLifespan, Actor: "someone-else", Reason: "load test", GrantedBy: grantor}, time.Hour); err != nil {
		t.Fatal(err)
	}
	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 900 })
	h.tick(time.Second)
	h.sweep()
	if got := h.live(caller.client).AccessTokenLifespan; got != 240 {
		t.Errorf("an exception naming another user left the change in place (%d)", got)
	}
}

// No attribution, no automatic repair: neither when admin events cannot be read, nor when a
// change left no admin event. The reconciler's own earlier repair is no attribution either.
func TestAChangeNobodyCanBeNamedForIsNotRepaired(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()

	// A repair first, so the kernel holds an admin event by the reconciler's own service account.
	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 60 })
	h.tick(time.Second)
	h.sweep()

	// Then a change that leaves no event: only the service account's own is in the window.
	h.tick(time.Second)
	h.kernel.ConsoleChange("", caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 900 })
	h.tick(time.Second)
	h.sweep()
	if got := h.live(caller.client).AccessTokenLifespan; got != 900 {
		t.Errorf("a change no admin event explains was repaired (%d)", got)
	}
	open := h.findings(caller.client)
	last := open[len(open)-1]
	if last.class != string(Unattributed) || last.convergedAt != nil {
		t.Fatalf("finding = %+v, want an open unattributed finding", last)
	}

	// Unreadable events: attribution is false for the whole run.
	h.kernel.FailEvents = keycloak.ErrForbidden
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 1200 })
	h.tick(time.Minute)
	run := h.sweep()
	if run.Attribution == nil || *run.Attribution {
		t.Errorf("run attribution = %v, want false while admin events cannot be read", run.Attribution)
	}
	if got := h.live(caller.client).AccessTokenLifespan; got != 1200 {
		t.Errorf("a change found without attribution was repaired (%d)", got)
	}

	operator, _ := id.NewV7()
	if err := h.reconciler.Resolve(context.Background(), Resolution{Findings: []id.UUID{last.id},
		ResolvedBy: operator, Reason: "checked with the team"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := h.live(caller.client).AccessTokenLifespan; got != 240 {
		t.Errorf("the operator's reconcile left the lifespan at %d", got)
	}
}

// An unreachable kernel is unresolved: nothing is opened, closed, converged or patched.
func TestAnUnreachableKernelLeavesTheRunUnresolved(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.kernel.ConsoleChange("", caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 900 })
	h.sweep()
	before := h.findings(caller.client)

	for _, c := range []struct {
		name        string
		get, events error
	}{
		{"the client read", keycloak.ErrUnavailable, nil},
		{"the event read", nil, keycloak.ErrUnavailable},
		{"a refused client read", keycloak.ErrForbidden, nil},
	} {
		name := c.name
		h.kernel.FailGet, h.kernel.FailEvents = c.get, c.events
		h.tick(time.Minute)
		patches := h.kernel.Patches
		run := h.sweep()
		if run.Outcome != Unresolved || run.FinishedAt == nil {
			t.Errorf("%s: run = %+v, want a finished unresolved run", name, run)
		}
		after := h.findings(caller.client)
		if len(after) != len(before) || after[0].class != before[0].class || h.kernel.Patches != patches {
			t.Errorf("%s: an unresolved run changed findings or patched the kernel", name)
		}
	}
}

func TestOneSweepAtATime(t *testing.T) {
	h := newHarness(t)
	h.reconciler.cfg.Interval = time.Hour
	running, _ := id.NewV7()
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.reconcile_run (run_id, sweep, started_at) VALUES ($1, 'registration', $2)`,
			running.String(), h.clock.at.Add(-time.Minute))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reconciler.Sweep(context.Background()); !errors.Is(err, ErrSweepInProgress) {
		t.Fatalf("a sweep beside a running one answered %v, want ErrSweepInProgress", err)
	}

	// A run unfinished after two intervals belonged to a replica that stopped.
	h.tick(3 * time.Hour)
	if _, err := h.reconciler.Sweep(context.Background()); err != nil {
		t.Fatalf("a stale unfinished run still blocked the sweep: %v", err)
	}
	status, err := h.reconciler.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.LastRun == nil || status.LastRun.ID == running || status.LastRun.Outcome != Converged {
		t.Errorf("the last run is %+v, want the new converged one", status.LastRun)
	}
}

// STD-IAM-002 §3.3: the shortest lifetime class in the audience decides, and what nobody declared
// takes the shortest class of all.
func TestTheLifespanIsDerivedFromTheAudience(t *testing.T) {
	h := newHarness(t)
	h.register("orders", "resource", "L1", nil, nil)
	h.register("partners", "resource", "L2", nil, nil)
	for key, audience := range map[string][]string{
		"both":         {"partners", "orders"},
		"partner-only": {"partners"},
		"unregistered": {"partners", "nobody"},
		"no-audience":  nil,
	} {
		h.register(key, "confidential", "", audience, []string{callbackURI})
	}
	var desired []registration
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		var err error
		desired, err = readDesired(ctx, tx, realm)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"both": 540, "partner-only": 900, "unregistered": 240, "no-audience": 240}
	for _, reg := range desired {
		if expected, ok := want[reg.clientKey]; ok && reg.lifespan != expected {
			t.Errorf("%s: derived lifespan %d, want %d", reg.clientKey, reg.lifespan, expected)
		}
	}
}

func TestAnExceptionIsBoundedAndNamesAnActiveRegistration(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	grantor, _ := id.NewV7()
	nobody, _ := id.NewV7()
	base := Exception{Registration: caller.id, FieldClass: TokenLifespan, Actor: admin, Reason: "why", GrantedBy: grantor}

	if _, err := h.reconciler.GrantException(context.Background(), base, 25*time.Hour); !errors.Is(err, ErrInvalid) {
		t.Errorf("a 25-hour exception answered %v, want ErrInvalid", err)
	}
	unknown := base
	unknown.Registration = nobody
	if _, err := h.reconciler.GrantException(context.Background(), unknown, time.Hour); !errors.Is(err, ErrNoSuchRegistration) {
		t.Errorf("an exception for no registration answered %v", err)
	}
	blank := base
	blank.Reason = " "
	if _, err := h.reconciler.GrantException(context.Background(), blank, time.Hour); !errors.Is(err, ErrInvalid) {
		t.Errorf("an exception without a reason answered %v", err)
	}
	if err := h.reconciler.Resolve(context.Background(), Resolution{Findings: []id.UUID{nobody}, ResolvedBy: grantor,
		Reason: "x"}); !errors.Is(err, ErrNotResolvable) {
		t.Errorf("resolving a finding that does not exist answered %v", err)
	}
}

// An absent client is held as an open 'missing' finding, and one finding however many sweeps see
// it. Nothing recreates it without an operator, even with a recreator wired in: deleting a client
// is how a compromised one is contained while :suspend and :retire are not built.
func TestAnAbsentClientIsHeldNotRecreated(t *testing.T) {
	h := newHarness(t)
	recreations := 0
	h.reconciler.cfg.Recreate = func(context.Context, id.UUID) (keycloak.ClientUUID, error) {
		recreations++
		return "", errors.New("the sweep must not call this")
	}
	caller := h.caller()
	h.sweep()
	h.tick(time.Second)
	h.kernel.Remove(admin, caller.client)
	h.tick(time.Minute)
	run := h.sweep()
	if run.Outcome != Drift || run.Findings != 1 {
		t.Errorf("run = %+v, want drift with one finding", run)
	}
	h.tick(time.Minute)
	h.sweep()
	if _, ok := h.kernel.Client(caller.client); ok || recreations != 0 {
		t.Errorf("the absent client was recreated by a sweep (%d call(s))", recreations)
	}
	f := h.findings(caller.client)
	if len(f) != 1 || f[0].class != string(Missing) || f[0].field != "" || f[0].actor != admin || f[0].convergedAt != nil {
		t.Errorf("findings = %+v, want one open missing finding naming %s", f, admin)
	}
}

// The drift route reports the last run and every finding that has not converged.
func TestStatusReportsTheOpenFindings(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()
	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.RedirectURIs = []string{takeoverURI} })
	h.tick(time.Second)
	h.sweep()

	status, err := h.reconciler.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.LastRun == nil || status.LastRun.Outcome != Drift || status.LastRun.FinishedAt == nil {
		t.Errorf("last run = %+v", status.LastRun)
	}
	if len(status.Findings) != 1 {
		t.Fatalf("findings = %+v, want the one blocked finding", status.Findings)
	}
	f := status.Findings[0]
	if f.ClientKey != "identity-control-caller" || f.Class != Blocked || f.Actor != admin ||
		string(f.Observed) != `["`+takeoverURI+`"]` || string(f.Desired) != `["`+callbackURI+`"]` {
		t.Errorf("finding = %+v desired %s observed %s", f, f.Desired, f.Observed)
	}
}

// A client deleted in the console is recreated from desired state only by an operator's reconcile
// naming its finding, which then records the deletion's actor, the operator and the reason.
func TestADeletedClientIsRecreatedOnlyByAnOperator(t *testing.T) {
	h := newHarness(t)
	service, err := clientregistration.New(h.pool, h.kernel, clientregistration.Config{Realm: realm,
		CallTimeout: time.Second, PendingRecoveryAfter: time.Minute}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h.reconciler.cfg.Recreate = service.Recreate
	caller, _ := id.NewV7()
	key, _ := id.NewV7()
	registered, err := service.Register(context.Background(), clientregistration.Request{
		CallerScope: "principal:" + caller.String(), IdempotencyKey: key.String(), RegisteredBy: caller,
		ClientKey: "proof-b-client", Profile: clientregistration.ProfilePublic, AudienceClass: "internal",
		ApplicationRef: "proof-b", RedirectURIs: []string{callbackURI}})
	if err != nil {
		t.Fatal(err)
	}
	h.sweep()
	found, _ := h.kernel.FindClients(context.Background(), realm, "proof-b-client")
	original := found[0].ID

	h.tick(time.Second)
	h.kernel.Remove(admin, original)
	h.tick(time.Second)
	run := h.sweep()

	found, _ = h.kernel.FindClients(context.Background(), realm, "proof-b-client")
	if len(found) != 0 || run.Outcome != Drift || run.Findings != 1 {
		t.Fatalf("after the sweep: %d client(s), run %+v; want none recreated", len(found), run)
	}
	missing := h.findings(original)
	if len(missing) != 1 || missing[0].class != string(Missing) {
		t.Fatalf("findings = %+v, want one open missing finding", missing)
	}

	operator, _ := id.NewV7()
	if err := h.reconciler.Resolve(context.Background(), Resolution{Findings: []id.UUID{missing[0].id},
		ResolvedBy: operator, Reason: "the deletion was a mistake"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	found, _ = h.kernel.FindClients(context.Background(), realm, "proof-b-client")
	if len(found) != 1 || found[0].ID == original {
		t.Fatalf("after the operator's reconcile: %d client(s)", len(found))
	}
	f := h.findings(original)
	if len(f) != 1 || f[0].class != string(Recreated) || f[0].actor != admin || f[0].convergedAt == nil ||
		f[0].resolvedBy != operator.String() {
		t.Errorf("findings = %+v, want the finding recreated, naming %s and resolved by the operator", f, admin)
	}
	current, _ := service.Get(context.Background(), registered.ID)
	h.tick(time.Minute)
	if again := h.sweep(); again.Outcome != Converged || current.State != "active" {
		t.Errorf("the sweep after recreation reported %+v", again)
	}
}

// A repair converges inside the sweep that made it, so the open findings never show it. The last
// run's findings do, with the times its convergence is measured from.
func TestStatusReportsTheLastRunsConvergedRepair(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()
	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.AccessTokenLifespan = 3600 })
	h.tick(3 * time.Second)
	h.sweep()

	status, err := h.reconciler.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Findings) != 0 || len(status.LastRunFindings) != 1 {
		t.Fatalf("open %+v, last run %+v; want nothing open and the one repair", status.Findings, status.LastRunFindings)
	}
	history, err := h.reconciler.FindingsFor(context.Background(), caller.id)
	if err != nil || len(history) != 1 || history[0].ID != status.LastRunFindings[0].ID {
		t.Errorf("the registration's history is %+v (%v), want the one repair", history, err)
	}
	f := status.LastRunFindings[0]
	if f.Class != Repaired || f.Actor != admin || f.ChangedAt == nil || f.ConvergedAt == nil ||
		f.ConvergedAt.Sub(*f.ChangedAt) != 3*time.Second {
		t.Errorf("last run finding = %+v", f)
	}
}

// Without a recreator configured, an operator's reconcile of a missing client is refused rather
// than recorded as done.
func TestAMissingClientNeedsSomethingToRecreateIt(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()
	h.kernel.Remove(admin, caller.client)
	h.tick(time.Minute)
	h.sweep()
	missing := h.findings(caller.client)
	operator, _ := id.NewV7()
	err := h.reconciler.Resolve(context.Background(), Resolution{Findings: []id.UUID{missing[0].id},
		ResolvedBy: operator, Reason: "recreate it"})
	if !errors.Is(err, ErrNotResolvable) {
		t.Errorf("resolving without a recreator answered %v, want ErrNotResolvable", err)
	}
	if f := h.findings(caller.client); f[0].convergedAt != nil {
		t.Error("the refused resolution closed the finding")
	}
}

// A key added in the console lets whoever holds its private key authenticate as the client: it is
// blocked, not restored, and stays blocked until an operator lifts it, which puts back exactly the
// registered keys. A console fix does not lift it, as for a redirect URI.
func TestAKeyAddedInTheConsoleBlocksTheClient(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	h.sweep()

	intruder := keycloak.JWK{KID: "someone-elses", N: "n-intruder", E: "AQAB"}
	h.tick(time.Second)
	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) {
		c.Credential.Keys = append(c.Credential.Keys, intruder)
	})
	h.tick(time.Second)
	h.sweep()

	client := h.live(caller.client)
	if client.Enabled {
		t.Error("the client is still enabled after a key was added to it in the console")
	}
	if !slices.Contains(client.Credential.Keys, intruder) {
		t.Error("the added key was removed; it must be kept for whoever investigates")
	}
	findings := h.findings(caller.client)
	if len(findings) != 1 || findings[0].field != string(ClientKeys) || findings[0].class != string(Blocked) ||
		findings[0].actor != admin {
		t.Fatalf("findings = %+v, want one open blocked client_keys finding attributed to the administrator", findings)
	}

	h.kernel.ConsoleChange(admin, caller.client, func(c *keycloak.Client) { c.Credential.Keys = []keycloak.JWK{caller.key} })
	h.tick(time.Minute)
	h.sweep()
	if f := h.findings(caller.client); f[0].convergedAt != nil || h.live(caller.client).Enabled {
		t.Fatal("a console fix of the keys lifted the block without an operator")
	}

	operator, _ := id.NewV7()
	if err := h.reconciler.Resolve(context.Background(), Resolution{Findings: []id.UUID{findings[0].id},
		ResolvedBy: operator, Reason: "investigated: the key was added by mistake"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	client = h.live(caller.client)
	if !client.Enabled || !client.Credential.ByKeys([]keycloak.JWK{caller.key}) {
		t.Errorf("after the operator's reconcile the client is %+v, want enabled with its registered key only", client)
	}
	if f := h.findings(caller.client)[0]; f.convergedAt == nil || f.resolvedBy != operator.String() {
		t.Errorf("the finding is %+v, want converged and resolved by the operator", f)
	}
}

// Switching the client back to a secret, or to a key URL, is a takeover too, and so is a change
// nobody can be named for: blocking removes access and never grants it, so it needs no attribution.
func TestAnyOtherCredentialChangeBlocksTheClient(t *testing.T) {
	for name, c := range map[string]struct {
		actor  string
		change func(*keycloak.Client)
	}{
		"a client secret":     {admin, func(c *keycloak.Client) { c.Credential.Authenticator = "client-secret" }},
		"a JWKS URL":          {admin, func(c *keycloak.Client) { c.Credential.HeldJWKS = false }},
		"a swapped modulus":   {admin, func(c *keycloak.Client) { c.Credential.Keys[0].N = "n-swapped" }},
		"a JWKS nobody reads": {admin, func(c *keycloak.Client) { c.Credential.Unreadable = true }},
		"an unattributed key": {"", func(c *keycloak.Client) { c.Credential.Keys = nil }},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			caller := h.caller()
			h.sweep()
			h.tick(time.Second)
			h.kernel.ConsoleChange(c.actor, caller.client, c.change)
			h.tick(time.Second)
			h.sweep()
			if h.live(caller.client).Enabled {
				t.Error("the client is still enabled")
			}
			if f := h.findings(caller.client); len(f) != 1 || f[0].field != string(ClientKeys) || f[0].class != string(Blocked) {
				t.Errorf("findings = %+v, want one blocked client_keys finding", f)
			}
		})
	}
}

// This service's own rotation writes the kernel before it commits the rows a sweep reads. A sweep
// that read the rows first and the kernel after sees a difference nobody made, and confirms it
// under the registration's lock before blocking: by then the rotation has committed.
func TestARotationInFlightIsNotTakenForDrift(t *testing.T) {
	h := newHarness(t)
	caller := h.caller()
	stale := registration{id: caller.id, client: caller.client, clientKey: "identity-control-caller",
		profile: "confidential", keys: []keycloak.JWK{caller.key}}

	// The rotation, committed: the next key active, the previous one retiring, the kernel holding both.
	next := keycloak.JWK{KID: "kid-next", N: "n-next", E: "AQAB"}
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE identity.client_key SET state = 'retiring', retiring_at = now() + interval '7 days'
		    WHERE registration_id = $1`, caller.id.String()); err != nil {
			return err
		}
		keyID, _ := id.NewV7()
		_, err := tx.Exec(ctx, `INSERT INTO identity.client_key
		    (key_id, registration_id, kid, thumbprint, public_jwk, state, registered_by, expires_at)
		    VALUES ($1, $2, 'kid-next', $3, '{"kty":"RSA","kid":"kid-next","n":"n-next","e":"AQAB"}', 'active', $2,
		            now() + interval '90 days')`, keyID.String(), caller.id.String(), "tp-"+keyID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.kernel.ConsoleChange("", caller.client, func(c *keycloak.Client) {
		c.Credential.Keys = []keycloak.JWK{next, caller.key}
	})

	confirmed, _, differs, err := h.reconciler.confirmKeyDrift(context.Background(), stale)
	if err != nil {
		t.Fatal(err)
	}
	if differs || len(confirmed.keys) != 2 {
		t.Errorf("a committed rotation was confirmed as drift: differs %v, keys %v", differs, confirmed.keys)
	}
	h.sweep()
	if !h.live(caller.client).Enabled || len(h.findings(caller.client)) != 0 {
		t.Error("the sweep blocked a client whose keys match what was committed")
	}
}

// A public client and a resource hold no key, so they are never compared on it.
func TestAKeylessClientIsNotComparedOnKeys(t *testing.T) {
	h := newHarness(t)
	web := h.register("keyless-web", "public", "", nil, []string{callbackURI})
	h.kernel.Put(keycloak.Client{ID: web.client, ClientID: "keyless-web", Enabled: true,
		RedirectURIs: []string{callbackURI}, AccessTokenLifespan: 240})
	h.sweep()
	if !h.live(web.client).Enabled || len(h.findings(web.client)) != 0 {
		t.Error("a public client was compared on keys it does not hold")
	}
}

// A client no registration describes is recorded on every sweep, attributed, and left alone in
// report mode. The kernel's built-in clients are never recorded.
func TestAClientNoRegistrationDescribesIsRecorded(t *testing.T) {
	h := newHarness(t)
	h.caller()
	h.kernel.Put(keycloak.Client{ID: "kc-admin-cli", ClientID: "admin-cli", Enabled: true})
	h.kernel.Put(keycloak.Client{ID: "kc-stray", ClientID: "stray-app", Enabled: true})
	h.kernel.ConsoleChange(admin, "kc-stray", func(*keycloak.Client) {})
	h.tick(time.Second)
	run := h.sweep()

	if run.Outcome != Drift {
		t.Errorf("the run is %s, want drift", run.Outcome)
	}
	if !h.live("kc-stray").Enabled {
		t.Error("report mode disabled the unmanaged client")
	}
	findings := h.findings("kc-stray")
	if len(findings) != 1 || findings[0].class != string(Unmanaged) || findings[0].field != "" || findings[0].actor != admin {
		t.Fatalf("findings = %+v, want one open unmanaged finding attributed to the administrator", findings)
	}
	if n := len(h.findings("kc-admin-cli")); n != 0 {
		t.Errorf("a built-in client was recorded %d time(s)", n)
	}
	status, err := h.reconciler.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reported *Finding
	for i := range status.Findings {
		if status.Findings[i].Class == Unmanaged {
			reported = &status.Findings[i]
		}
	}
	if reported == nil || reported.ClientKey != "stray-app" || reported.Registration != nil {
		t.Errorf("the drift status reports %+v, want the unmanaged client by its clientId and no registration", reported)
	}

	h.tick(time.Minute)
	h.sweep()
	if len(h.findings("kc-stray")) != 1 {
		t.Error("a second sweep opened another finding")
	}
}

// In disable mode the unmanaged client is also disabled, once.
func TestAnUnmanagedClientIsDisabledWhenAsked(t *testing.T) {
	h := newHarness(t)
	h.caller()
	h.reconciler.cfg.DisableUnmanaged = true
	h.kernel.Put(keycloak.Client{ID: "kc-stray", ClientID: "stray-app", Enabled: true})
	h.sweep()
	if h.live("kc-stray").Enabled {
		t.Fatal("disable mode left the unmanaged client enabled")
	}
	patches := h.kernel.Patches
	h.tick(time.Minute)
	h.sweep()
	if h.kernel.Patches != patches {
		t.Error("a second sweep disabled the client again")
	}
}

// The finding converges once the client is registered, by adoption or otherwise.
func TestAnUnmanagedFindingConvergesOnceTheClientIsRegistered(t *testing.T) {
	h := newHarness(t)
	h.caller()
	h.kernel.Put(keycloak.Client{ID: "kc-stray-app", ClientID: "stray-app", Enabled: true})
	h.sweep()
	if f := h.findings("kc-stray-app"); len(f) != 1 || f[0].convergedAt != nil {
		t.Fatalf("findings = %+v", f)
	}
	h.register("stray-app", "resource", "L1", nil, nil)
	h.tick(time.Minute)
	h.sweep()
	if f := h.findings("kc-stray-app"); len(f) != 1 || f[0].convergedAt == nil {
		t.Errorf("after the client was registered its finding is %+v, want converged", f)
	}
}
