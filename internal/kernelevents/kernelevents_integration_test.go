package kernelevents

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

type nopTransactor struct{}

func (nopTransactor) InTx(context.Context, func(context.Context, db.Tx) error) error { return nil }

func openPool(t *testing.T) *db.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	p, err := db.Open(context.Background(), db.Config{Name: "kernelevents-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func newID(t *testing.T) id.UUID {
	t.Helper()
	value, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// harness is a sweep over its own realm, so a second run on the same database starts clean.
type harness struct {
	pool    *db.Pool
	store   *keycloakfake.Events
	sweeper *Sweeper
	realm   keycloak.Realm
	now     time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool := openPool(t)
	store := keycloakfake.NewEvents()
	realm := keycloak.Realm("events-" + newID(t).String())
	sweeper, err := NewSweeper(pool, store, realm, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{pool: pool, store: store, sweeper: sweeper, realm: realm,
		now: time.Now().UTC().Truncate(time.Millisecond)}
	sweeper.now = func() time.Time { return h.now }
	return h
}

func (h *harness) count(t *testing.T, statement string, args ...any) int {
	t.Helper()
	var n int
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, statement, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
	return n
}

func (h *harness) sweep(t *testing.T) map[string]KindResult {
	t.Helper()
	result, err := h.sweeper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	out := map[string]KindResult{}
	for _, kind := range result.Kinds {
		out[kind.Kind] = kind
	}
	return out
}

func login(id, user string, at time.Time) keycloak.KernelEvent {
	return keycloak.KernelEvent{Kind: keycloak.KindUserEvent, ID: id, Time: at, Type: "LOGIN", UserID: user,
		ClientID: "app", SessionID: "s-" + id, IPAddress: "203.0.113.10", Details: map[string]string{"auth_method": "openid-connect"}}
}

// An event read by two overlapping sweeps is recorded once; the first sweep reads the kernel's whole
// retention, and the next reads from the mark less one interval.
func TestOverlappingSweepsRecordEachEventOnce(t *testing.T) {
	h := newHarness(t)
	old := h.now.Add(-6 * 24 * time.Hour)
	h.store.Record(login("e1", "kc-1", old), login("e2", "kc-2", h.now.Add(-time.Minute)),
		keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, ID: "a1", Time: h.now.Add(-2 * time.Minute), Type: "CREATE",
			UserID: "kc-admin", ResourceType: "GROUP", ResourcePath: "groups/g1", Representation: `{"name":"g"}`})

	first := h.sweep(t)
	if first[keycloak.KindUserEvent].Recorded != 2 || first[keycloak.KindAdminEvent].Recorded != 1 {
		t.Fatalf("the first sweep recorded %+v; want both user events, the six-day-old one included, and the admin event", first)
	}
	if since := h.store.Since[keycloak.KindUserEvent][0]; !since.Equal(h.now.Add(-Retention)) {
		t.Errorf("the first sweep read from %s, want the start of the kernel's retention", since)
	}
	if !first[keycloak.KindUserEvent].ReadThrough.Equal(h.now.Add(-time.Minute)) {
		t.Errorf("the mark is %s, want the newest event read", first[keycloak.KindUserEvent].ReadThrough)
	}

	h.now = h.now.Add(time.Hour)
	h.store.Record(login("e3", "kc-1", h.now.Add(-time.Second)))
	second := h.sweep(t)
	if second[keycloak.KindUserEvent].Read != 2 || second[keycloak.KindUserEvent].Recorded != 1 {
		t.Errorf("the second sweep read %d and recorded %d; want e2 again, in the overlap, and e3 recorded",
			second[keycloak.KindUserEvent].Read, second[keycloak.KindUserEvent].Recorded)
	}
	if since := h.store.Since[keycloak.KindUserEvent][1]; !since.Equal(first[keycloak.KindUserEvent].ReadThrough.Add(-time.Hour)) {
		t.Errorf("the second sweep read from %s, want the mark less one interval", since)
	}
	if n := h.count(t, `SELECT count(*) FROM identity.kernel_event WHERE realm = $1`, string(h.realm)); n != 4 {
		t.Errorf("%d events recorded, want 4", n)
	}
}

// A truncated read records what it read and keeps the mark, so the next sweep reads the window again.
func TestATruncatedReadKeepsTheMark(t *testing.T) {
	h := newHarness(t)
	h.store.Record(login("t1", "kc-1", h.now.Add(-3*time.Minute)))
	h.sweep(t)
	h.store.Record(login("t2", "kc-1", h.now.Add(-2*time.Minute)), login("t3", "kc-1", h.now.Add(-time.Minute)))
	h.store.Bound = 1

	result := h.sweep(t)[keycloak.KindUserEvent]
	if !result.Truncated || result.Recorded != 1 {
		t.Fatalf("a bounded read answered %+v; want truncated with the newest event recorded", result)
	}
	if !result.ReadThrough.Equal(h.now.Add(-3 * time.Minute)) {
		t.Errorf("a truncated read moved the mark to %s; it must stay at the last complete read", result.ReadThrough)
	}
	h.store.Bound = 0
	result = h.sweep(t)[keycloak.KindUserEvent]
	if result.Truncated || result.Recorded != 1 || !result.ReadThrough.Equal(h.now.Add(-time.Minute)) {
		t.Errorf("the next sweep answered %+v; want the gap recorded and the mark moved", result)
	}
}

// A kernel user a mapping holds is recorded with its Principal; one no mapping holds, with none.
func TestAUserEventCarriesItsPrincipal(t *testing.T) {
	h := newHarness(t)
	principal := newID(t)
	kcUser := "kc-" + principal.String()
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
		    (principal_id, realm, username, subject_type, keycloak_user_id, state)
		    VALUES ($1, $2, $3, 'human', $4, 'active')`,
			principal.String(), string(h.realm), "events-"+principal.String(), kcUser)
		return err
	}); err != nil {
		t.Fatalf("map the Principal: %v", err)
	}
	h.store.Record(login("p1", kcUser, h.now.Add(-time.Minute)), login("p2", "kc-unmapped", h.now.Add(-time.Minute)))
	h.sweep(t)
	if n := h.count(t, `SELECT count(*) FROM identity.kernel_event WHERE realm = $1 AND kc_event_id = 'p1' AND principal_id = $2`,
		string(h.realm), principal.String()); n != 1 {
		t.Error("a mapped kernel user's event was recorded without its Principal")
	}
	if n := h.count(t, `SELECT count(*) FROM identity.kernel_event WHERE realm = $1 AND kc_event_id = 'p2' AND principal_id IS NULL`,
		string(h.realm)); n != 1 {
		t.Error("an unmapped kernel user's event was recorded with a Principal")
	}
}

// An event without the kernel's identifier cannot be keyed, so the sweep fails rather than drop it.
func TestAnEventWithoutAnIdentifierStopsTheSweep(t *testing.T) {
	h := newHarness(t)
	h.store.Record(login("", "kc-1", h.now.Add(-time.Minute)))
	if _, err := h.sweeper.Sweep(context.Background()); err == nil || !strings.Contains(err.Error(), "no id") {
		t.Errorf("an event without an id answered %v", err)
	}
}

// The recorded hook sees each event once, when it is first recorded, inside the sweep's transaction
// (TDD-identity-control-008 §Component Design): a second sweep that reads it again in the overlap does
// not call it, and a hook that fails rolls the sweep back with it.
func TestTheRecordedHookSeesEachEventOnce(t *testing.T) {
	h := newHarness(t)
	var seen []string
	h.sweeper.OnRecorded(func(_ context.Context, _ db.Tx, realm keycloak.Realm, e keycloak.KernelEvent) error {
		if realm != h.realm {
			t.Errorf("the hook was called for realm %s", realm)
		}
		seen = append(seen, e.ID)
		return nil
	})
	h.store.Record(login("h1", "kc-1", h.now.Add(-time.Minute)))
	h.sweep(t)
	h.now = h.now.Add(time.Hour)
	h.store.Record(login("h2", "kc-1", h.now.Add(-time.Second)))
	h.sweep(t)
	if len(seen) != 2 || seen[0] != "h1" || seen[1] != "h2" {
		t.Errorf("the hook saw %v; want h1 then h2, each once", seen)
	}

	h.now = h.now.Add(time.Hour)
	h.store.Record(login("h3", "kc-1", h.now.Add(-time.Second)))
	h.sweeper.OnRecorded(func(context.Context, db.Tx, keycloak.Realm, keycloak.KernelEvent) error {
		return errors.New("the request could not be recorded")
	})
	if _, err := h.sweeper.Sweep(context.Background()); err == nil {
		t.Fatal("a failing hook did not fail the sweep")
	}
	if n := h.count(t, `SELECT count(*) FROM identity.kernel_event WHERE realm = $1 AND kc_event_id = 'h3'`, string(h.realm)); n != 0 {
		t.Error("the event was recorded although its hook failed; the two must commit together")
	}
}
