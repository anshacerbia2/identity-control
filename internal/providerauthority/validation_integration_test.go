package providerauthority

// Emergency grant validation against the real engine (ADR-ORG-002 §5.2,
// TDD-identity-control-006 §Emergency Grant Validation): each use is recorded on the projected
// grant, a later version keeps when the grant was first held, and one unused for 90 days is overdue.

import (
	"context"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

func TestAProjectedEmergencyGrantIsValidatedByItsUse(t *testing.T) {
	p := pool(t)
	ctx := context.Background()
	d := decider(t, p, &stated{fresh: true}, time.Now().UTC())

	emergency := func() Grant {
		g := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "emergency", GrantStatus: "active", GrantVersion: 1}
		hold(t, p, g)
		return g
	}
	stale, used := emergency(), emergency()
	eligible := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "eligible", GrantStatus: "active", GrantVersion: 1}
	hold(t, p, eligible)
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.provider_grant SET first_applied_at = now() - interval '100 days'
		    WHERE grant_id = $1`, stale.GrantID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := d.RecordEmergencyUse(ctx, used.PrincipalID); err != nil {
			t.Fatalf("recording a use: %v", err)
		}
	}
	// An eligible grant's holder records nothing, and is no error.
	if err := d.RecordEmergencyUse(ctx, eligible.PrincipalID); err != nil {
		t.Errorf("an eligible holder: %v", err)
	}
	// A later version of the stale grant does not restart its 90 days.
	again := stale
	again.GrantVersion = 2
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := upsert(ctx, tx, again)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	read := func(at time.Time) map[id.UUID]EmergencyValidation {
		t.Helper()
		report, err := d.EmergencyValidation(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		out := map[id.UUID]EmergencyValidation{}
		for _, v := range report {
			out[v.GrantID] = v
		}
		return out
	}
	report := read(now)
	if _, listed := report[eligible.GrantID]; listed {
		t.Error("the report lists an eligible grant")
	}
	if v := report[stale.GrantID]; v.LastUsedAt != nil || v.Uses != 0 || !v.Overdue || now.Sub(v.HeldSince) < 99*24*time.Hour {
		t.Errorf("the grant held 100 days and never used reads %+v, want overdue", v)
	}
	if v := report[used.GrantID]; v.LastUsedAt == nil || v.Uses != 2 || v.Overdue {
		t.Errorf("the used grant reads %+v, want two uses and not overdue", v)
	}
	if v := read(now.Add(ValidationPeriod + time.Hour))[used.GrantID]; !v.Overdue {
		t.Errorf("ninety days after its last use the grant reads %+v, want overdue", v)
	}
}
