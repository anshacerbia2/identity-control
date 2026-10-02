package providerauthority

// The provider decision against the real engine (TDD-identity-control-006 §The Provider Decision,
// §The Ceremony's Grant): an emergency grant authorizes while stale, an activation does not, an
// ended or expired activation does not, a revoked grant does not, and the ceremony grant authorizes
// until an emergency grant is projected and never after.

import (
	"context"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// held freshness, as a test states it.
type stated struct {
	fresh  bool
	reason string
}

func (s *stated) Fresh() (bool, string) { return s.fresh, s.reason }

func decider(t *testing.T, p *db.Pool, freshness FreshnessReader, now time.Time) *Decider {
	t.Helper()
	d, err := NewDecider(p, freshness)
	if err != nil {
		t.Fatal(err)
	}
	d.now = func() time.Time { return now }
	return d
}

func decide(t *testing.T, d *Decider, principal id.UUID) Decision {
	t.Helper()
	decision, err := d.Decide(context.Background(), principal)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return decision
}

func TestTheDecisionReadsGrantsAndFreshness(t *testing.T) {
	p := pool(t)
	now := time.Now().UTC()
	freshness := &stated{fresh: true}
	d := decider(t, p, freshness, now)

	grant := func(kind, status string, endsIn *time.Duration) Grant {
		g := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: kind, GrantStatus: status, GrantVersion: 1}
		if endsIn != nil {
			g.Activation = &Activation{ActivationID: newID(t), EndsAt: now.Add(*endsIn)}
		}
		hold(t, p, g)
		return g
	}
	hour, ago := time.Hour, -time.Minute

	activated := grant("eligible", "active", &hour)
	expired := grant("eligible", "active", &ago)
	unactivated := grant("eligible", "active", nil)
	revoked := grant("eligible", "revoked", nil)
	emergency := grant("emergency", "active", nil)
	revokedEmergency := grant("emergency", "revoked", nil)

	for _, c := range []struct {
		what      string
		principal id.UUID
		fresh     bool
		want      Decision
	}{
		{"an activation in force, fresh", activated.PrincipalID, true, Decision{Provider: true, Basis: BasisActivation}},
		{"an activation in force, stale", activated.PrincipalID, false, Decision{Stale: true, StaleReason: StaleAge}},
		{"an expired activation", expired.PrincipalID, true, Decision{}},
		{"an eligible grant not activated", unactivated.PrincipalID, true, Decision{}},
		{"a revoked grant", revoked.PrincipalID, true, Decision{}},
		{"an emergency grant, fresh", emergency.PrincipalID, true, Decision{Provider: true, Basis: BasisEmergency, Emergency: true}},
		{"an emergency grant, stale", emergency.PrincipalID, false, Decision{Provider: true, Basis: BasisEmergency, Emergency: true}},
		{"a revoked emergency grant", revokedEmergency.PrincipalID, false, Decision{}},
		{"a Principal with no grant", newID(t), true, Decision{}},
		{"no Principal", id.UUID{}, true, Decision{}},
	} {
		freshness.fresh, freshness.reason = c.fresh, ""
		if !c.fresh {
			freshness.reason = StaleAge
		}
		if got := decide(t, d, c.principal); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.what, got, c.want)
		}
	}

	// An activation ends on its recorded end, on this process's clock, with no event.
	later := decider(t, p, &stated{fresh: true}, now.Add(2*time.Hour))
	if got := decide(t, later, activated.PrincipalID); got.Provider {
		t.Errorf("an activation past its end authorized: %+v", got)
	}

	// A process reading no frontier is never fresh: activations stop, emergency grants do not.
	unread := decider(t, p, nil, now)
	if got := decide(t, unread, activated.PrincipalID); got.Provider || got.StaleReason != StaleUnobserved {
		t.Errorf("with no frontier an activation decided %+v", got)
	}
	if got := decide(t, unread, emergency.PrincipalID); !got.Provider {
		t.Errorf("with no frontier an emergency grant decided %+v", got)
	}
}

// keepCeremonyRows restores the ceremony row and its retirement as the test found them: both are
// single-row and shared with whatever else ran against this database.
func keepCeremonyRows(t *testing.T, p *db.Pool) {
	t.Helper()
	ctx := context.Background()
	var (
		ceremony   []any
		retirement []any
		found      [2]bool
	)
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT operator, reason, idempotency_key, requested_at, principal_id::text
			FROM identity.bootstrap_ceremony WHERE id = 1`)
		if err != nil {
			return err
		}
		if rows.Next() {
			var operator, reason, key string
			var requested time.Time
			var principal *string
			if err := rows.Scan(&operator, &reason, &key, &requested, &principal); err != nil {
				rows.Close()
				return err
			}
			ceremony, found[0] = []any{operator, reason, key, requested, principal}, true
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT retired_at, by_grant_id::text FROM identity.ceremony_grant_retirement WHERE id = 1`)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			var retired time.Time
			var by string
			if err := rows.Scan(&retired, &by); err != nil {
				return err
			}
			retirement, found[1] = []any{retired, by}, true
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	clear := func() error {
		return p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			for _, statement := range []string{
				`DELETE FROM identity.ceremony_grant_retirement`,
				`DELETE FROM identity.bootstrap_ceremony`,
			} {
				if _, err := tx.Exec(ctx, statement); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if err := clear(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clear()
		_ = p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			if found[0] {
				if _, err := tx.Exec(ctx, `INSERT INTO identity.bootstrap_ceremony
					(id, operator, reason, idempotency_key, requested_at, principal_id)
					VALUES (1, $1, $2, $3, $4, $5::uuid)`, ceremony...); err != nil {
					return err
				}
			}
			if found[1] {
				if _, err := tx.Exec(ctx, `INSERT INTO identity.ceremony_grant_retirement (id, retired_at, by_grant_id)
					VALUES (1, $1, $2::uuid)`, retirement...); err != nil {
					return err
				}
			}
			return nil
		})
	})
}

func recordCeremony(t *testing.T, p *db.Pool, principal id.UUID) {
	t.Helper()
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.bootstrap_ceremony (id, operator, reason, idempotency_key, principal_id)
			VALUES (1, 'suite', 'suite', 'bootstrap:suite', $1)`, principal.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func retiredBy(t *testing.T, p *db.Pool) (string, bool) {
	t.Helper()
	var by string
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce((SELECT by_grant_id::text FROM identity.ceremony_grant_retirement WHERE id = 1), '')`).Scan(&by)
	}); err != nil {
		t.Fatal(err)
	}
	return by, by != ""
}

// The ceremony's Principal is a provider until the first emergency grant is projected, and never
// after: the retirement is written in that grant's transaction, once.
func TestTheCeremonyGrantEndsAtTheFirstProjectedEmergencyGrant(t *testing.T) {
	p := pool(t)
	keepCeremonyRows(t, p)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	d := decider(t, p, &stated{}, time.Now().UTC())
	ctx := context.Background()

	first := newID(t)
	recordCeremony(t, p, first)
	if got := decide(t, d, first); got != (Decision{Provider: true, Basis: BasisCeremony, Emergency: true}) {
		t.Fatalf("the ceremony's Principal decided %+v", got)
	}

	// An eligible grant, even activated, retires nothing.
	eligible := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "eligible", GrantStatus: "active", GrantVersion: 1,
		Activation: &Activation{ActivationID: newID(t), EndsAt: time.Now().Add(time.Hour)}}
	granted := envelope(t, EventActivated, eligible)
	cleanup(t, p, eligible.GrantID, granted)
	if _, err := projection.Apply(ctx, granted); err != nil {
		t.Fatal(err)
	}
	if _, retired := retiredBy(t, p); retired {
		t.Fatal("an eligible grant retired the ceremony grant")
	}

	emergency := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "emergency", GrantStatus: "active", GrantVersion: 1}
	emergencyGranted := envelope(t, EventGranted, emergency)
	cleanup(t, p, emergency.GrantID, emergencyGranted)
	if _, err := projection.Apply(ctx, emergencyGranted); err != nil {
		t.Fatal(err)
	}
	if by, retired := retiredBy(t, p); !retired || by != emergency.GrantID.String() {
		t.Fatalf("the ceremony grant was retired by %q (%v); want %s", by, retired, emergency.GrantID)
	}
	if got := decide(t, d, first); got.Provider {
		t.Errorf("the ceremony's Principal is still a provider after retirement: %+v", got)
	}
	if got := decide(t, d, emergency.PrincipalID); got.Basis != BasisEmergency {
		t.Errorf("the emergency grant decided %+v", got)
	}

	// Revoking the emergency grant does not revive the ceremony grant, and a second one records
	// nothing: the end is single.
	revoked := emergency
	revoked.GrantVersion, revoked.GrantStatus = 2, "revoked"
	revocation := envelope(t, EventRevoked, revoked)
	second := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "emergency", GrantStatus: "active", GrantVersion: 1}
	secondGranted := envelope(t, EventGranted, second)
	cleanup(t, p, emergency.GrantID, revocation)
	cleanup(t, p, second.GrantID, secondGranted)
	if _, err := projection.Apply(ctx, revocation); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Apply(ctx, secondGranted); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, d, first); got.Provider {
		t.Errorf("the ceremony grant was revived: %+v", got)
	}
	if by, _ := retiredBy(t, p); by != emergency.GrantID.String() {
		t.Errorf("the retirement was rewritten to %s", by)
	}
}

// A snapshot carrying an emergency grant retires the ceremony grant too.
func TestASnapshotWithAnEmergencyGrantRetiresTheCeremonyGrant(t *testing.T) {
	p := pool(t)
	keepCeremonyRows(t, p)
	keepProjectionRow(t, p)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	first := newID(t)
	recordCeremony(t, p, first)

	emergency := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "emergency", GrantStatus: "active", GrantVersion: 3}
	cleanup(t, p, emergency.GrantID)
	if err := projection.ReplaceFromSnapshot(context.Background(), 7, []Grant{emergency}); err != nil {
		t.Fatal(err)
	}
	if by, retired := retiredBy(t, p); !retired || by != emergency.GrantID.String() {
		t.Errorf("the snapshot retired the ceremony grant by %q (%v)", by, retired)
	}
	if got := decide(t, decider(t, p, nil, time.Now()), first); got.Provider {
		t.Errorf("the ceremony's Principal decided %+v after the snapshot", got)
	}
}
