package providerauthority

// A restore to an older point raises every grant_version by 10^9 before Organization Control serves
// again, and publishes each revoked or ended grant at its new version (ADR-ORG-003 §5.5). This
// projection applies only a higher version and checks no gap, so the jump needs nothing of it. These
// prove that, against the real engine (TDD-identity-control-006 1.4.0).

import (
	"context"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
)

// restoreBump is ADR-ORG-003 §5.5's margin, M = 10^9.
const restoreBump = 1_000_000_000

// A grant the consumer holds at version 5, a restore that brings authority back to version 3 and
// bumps it to 3 + 10^9, and the withdrawal published at that version: applied. The next version after
// it is applied, and the pre-restore version 4, delivered late, is discarded.
func TestAGrantVersionBumpedByTheRestoreIsApplied(t *testing.T) {
	p := pool(t)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "eligible", GrantStatus: "active",
		GrantVersion: 5}
	granted := envelope(t, EventGranted, grant)

	withdrawn := grant
	withdrawn.GrantVersion, withdrawn.GrantStatus = 3+restoreBump, "revoked"
	withdrawal := envelope(t, EventRevoked, withdrawn)

	regranted := grant
	regranted.GrantVersion = 4 + restoreBump
	after := envelope(t, EventGranted, regranted)

	stale := grant
	stale.GrantVersion, stale.GrantStatus = 4, "revoked"
	late := envelope(t, EventRevoked, stale)
	cleanup(t, p, grant.GrantID, granted, withdrawal, after, late)

	ctx := context.Background()
	for _, step := range []struct {
		what       string
		envelope   event.Envelope
		superseded bool
		want       held
	}{
		{"held before the restore", granted, false, held{"active", "eligible", 5, false}},
		{"the withdrawal at the bumped version", withdrawal, false, held{"revoked", "eligible", 3 + restoreBump, false}},
		{"the next version after it", after, false, held{"active", "eligible", 4 + restoreBump, false}},
		{"a pre-restore version, late", late, true, held{"active", "eligible", 4 + restoreBump, false}},
	} {
		outcome, err := projection.Apply(ctx, step.envelope)
		if err != nil {
			t.Fatalf("%s: %v", step.what, err)
		}
		if outcome.Superseded != step.superseded || outcome.Duplicate {
			t.Errorf("%s: outcome %+v, want superseded=%v", step.what, outcome, step.superseded)
		}
		if got, _ := read(t, p, grant.GrantID); got != step.want {
			t.Errorf("%s: held %+v, want %+v", step.what, got, step.want)
		}
	}
}

// The snapshot path applies the same rule: a snapshot read after the restore carries the bumped
// version, and replaces the state held at the lower one.
func TestASnapshotAtTheBumpedVersionReplacesTheHeldGrant(t *testing.T) {
	p := pool(t)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "emergency", GrantStatus: "active",
		GrantVersion: 7}
	granted := envelope(t, EventGranted, grant)
	cleanup(t, p, grant.GrantID, granted)
	ctx := context.Background()
	if _, err := projection.Apply(ctx, granted); err != nil {
		t.Fatal(err)
	}
	status, err := projection.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bumped := grant
	bumped.GrantVersion = 2 + restoreBump
	if err := projection.ReplaceFromSnapshot(ctx, status.AppliedMark, []Grant{bumped}); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(t, p, grant.GrantID); got.version != 2+restoreBump || got.status != "active" {
		t.Errorf("after a snapshot at the bumped version the grant is %+v", got)
	}
}

// Every version this projection orders by is a bigint, so 10^9 added to any version held cannot
// overflow (ADR-ORG-003 §5.5: "The versions are bigint").
func TestEveryProjectedVersionIsABigint(t *testing.T) {
	p := pool(t)
	columns := [][2]string{
		{"provider_grant", "grant_version"},
		{"tenant_desired", "tenant_version"},
		{"tenant_desired", "tenant_security_version"},
		{"membership_desired", "membership_version"},
	}
	check := func(table, column string) {
		var dataType string
		if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx, `SELECT data_type FROM information_schema.columns
				WHERE table_schema = 'identity' AND table_name = $1 AND column_name = $2`, table, column).Scan(&dataType)
		}); err != nil {
			t.Fatalf("%s.%s: %v", table, column, err)
		}
		if dataType != "bigint" {
			t.Errorf("identity.%s.%s is %s; a restore's 10^9 margin needs bigint", table, column, dataType)
		}
	}
	for _, c := range columns {
		check(c[0], c[1])
	}
}
