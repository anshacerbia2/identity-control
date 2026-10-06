package providerauthority

// Applying provider grant events against the real engine (TDD-identity-control-006 §Applying an
// Event).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"
)

func pool(t *testing.T) *db.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	p, err := db.Open(context.Background(), db.Config{Name: "providerauthority-test", DSN: dsn, MaxConns: 4})
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

func envelope(t *testing.T, eventType event.Type, grant Grant) event.Envelope {
	t.Helper()
	built, err := event.New("/systems/organization-control", eventType, time.Now().UTC(), grant)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	built.StreamPosition = grant.GrantVersion * 10
	return built
}

type held struct {
	status, kind string
	version      int64
	activation   bool
}

func read(t *testing.T, p *db.Pool, grantID id.UUID) (held, bool) {
	t.Helper()
	var h held
	found := false
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT grant_status, kind, grant_version, activation_id IS NOT NULL
			FROM identity.provider_grant WHERE grant_id = $1`, grantID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			found = true
			return rows.Scan(&h.status, &h.kind, &h.version, &h.activation)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return h, found
}

func cleanup(t *testing.T, p *db.Pool, grantID id.UUID, events ...event.Envelope) {
	t.Cleanup(func() {
		_ = p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			_, _ = tx.Exec(ctx, `DELETE FROM identity.provider_emergency_use WHERE grant_id = $1`, grantID.String())
			_, _ = tx.Exec(ctx, `DELETE FROM identity.provider_grant WHERE grant_id = $1`, grantID.String())
			for _, e := range events {
				_, _ = tx.Exec(ctx, `DELETE FROM platform.processed_event WHERE event_id = $1`, e.ID.String())
			}
			return nil
		})
	})
}

// Each transition replaces the grant's state by version; a duplicate is applied already, and an
// older event is discarded whatever order it arrives in.
func TestEventsReplaceAGrantByVersion(t *testing.T) {
	p := pool(t)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "eligible", GrantStatus: "active", GrantVersion: 1}
	granted := envelope(t, EventGranted, grant)

	activated := grant
	activated.GrantVersion = 2
	activated.Activation = &Activation{ActivationID: newID(t), EndsAt: time.Now().Add(time.Hour)}
	activation := envelope(t, EventActivated, activated)

	revoked := grant
	revoked.GrantVersion, revoked.GrantStatus = 3, "revoked"
	revocation := envelope(t, EventRevoked, revoked)
	cleanup(t, p, grant.GrantID, granted, activation, revocation)

	ctx := context.Background()
	for _, step := range []struct {
		what       string
		envelope   event.Envelope
		duplicate  bool
		superseded bool
		want       held
	}{
		{"granted", granted, false, false, held{"active", "eligible", 1, false}},
		{"activated", activation, false, false, held{"active", "eligible", 2, true}},
		{"activated again", activation, true, false, held{"active", "eligible", 2, true}},
		{"revoked", revocation, false, false, held{"revoked", "eligible", 3, false}},
	} {
		outcome, err := projection.Apply(ctx, step.envelope)
		if err != nil {
			t.Fatalf("%s: %v", step.what, err)
		}
		if outcome.Duplicate != step.duplicate || outcome.Superseded != step.superseded {
			t.Errorf("%s: outcome %+v", step.what, outcome)
		}
		if got, _ := read(t, p, grant.GrantID); got != step.want {
			t.Errorf("%s: held %+v, want %+v", step.what, got, step.want)
		}
	}

	// An older event delivered late, as a new delivery: discarded, and the revocation stands.
	late := envelope(t, EventActivated, activated)
	cleanup(t, p, grant.GrantID, late)
	outcome, err := projection.Apply(ctx, late)
	if err != nil || !outcome.Superseded || outcome.Applied() {
		t.Fatalf("a late activation answered %+v, %v; want superseded and not applied", outcome, err)
	}
	if got, _ := read(t, p, grant.GrantID); got.status != "revoked" || got.activation {
		t.Errorf("a late activation revived a revoked grant: %+v", got)
	}
}

// Poison is refused before anything is written, so the dispatcher dead-letters it rather than
// retrying forever.
func TestAnEventThisProjectionCannotApplyIsRefused(t *testing.T) {
	p := pool(t)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "emergency", GrantStatus: "active", GrantVersion: 1}
	cleanup(t, p, grant.GrantID)

	other := grant
	other.Scope = "provider:organization-control"
	revokedWithActivation := grant
	revokedWithActivation.GrantStatus = "revoked"
	revokedWithActivation.Activation = &Activation{ActivationID: newID(t), EndsAt: time.Now()}

	for name, c := range map[string]struct {
		envelope event.Envelope
		want     error
	}{
		"another scope":                      {envelope(t, EventGranted, other), ErrMalformed},
		"a revoked grant with an activation": {envelope(t, EventRevoked, revokedWithActivation), ErrMalformed},
		"an unknown type":                    {envelope(t, "com.scnehaux.organization.membership.security.revoked", grant), ErrUnknownType},
	} {
		if _, err := projection.Apply(context.Background(), c.envelope); !errors.Is(err, c.want) {
			t.Errorf("%s answered %v, want %v", name, err, c.want)
		}
	}
	if _, found := read(t, p, grant.GrantID); found {
		t.Error("a refused event wrote the grant")
	}

	malformed := envelope(t, EventGranted, grant)
	malformed.Data = json.RawMessage(`{"grant_id": 7}`)
	if _, err := projection.Apply(context.Background(), malformed); !errors.Is(err, ErrMalformed) {
		t.Errorf("an unreadable payload answered %v", err)
	}
}
