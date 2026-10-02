package providerauthority

// Bootstrapping from the provider authority snapshot against the real engine
// (TDD-identity-control-006 §Bootstrap).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
)

// hold writes a grant as already projected.
func hold(t *testing.T, p *db.Pool, grant Grant) {
	t.Helper()
	cleanup(t, p, grant.GrantID)
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := upsert(ctx, tx, grant)
		return err
	}); err != nil {
		t.Fatalf("hold %s: %v", grant.GrantID, err)
	}
}

// keepProjectionRow restores the projection's one row as the test found it, since it is shared by
// every test that bootstraps.
func keepProjectionRow(t *testing.T, p *db.Pool) {
	t.Helper()
	ctx := context.Background()
	var (
		found                 bool
		snapshotMark, applied int64
		bootstrappedAt        time.Time
	)
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT snapshot_mark, applied_mark, bootstrapped_at
			FROM identity.provider_projection WHERE id = 1`)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			found = true
			return rows.Scan(&snapshotMark, &applied, &bootstrappedAt)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			if _, err := tx.Exec(ctx, `DELETE FROM identity.provider_projection WHERE id = 1`); err != nil || !found {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO identity.provider_projection (id, snapshot_mark, applied_mark, bootstrapped_at)
				VALUES (1, $1, $2, $3)`, snapshotMark, applied, bootstrappedAt)
			return err
		})
	})
}

func clearProjectionRow(t *testing.T, p *db.Pool) {
	t.Helper()
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM identity.provider_projection WHERE id = 1`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A snapshot applies each row by version, marks a grant it omits revoked, and records its mark.
func TestASnapshotReplacesTheProjectionByVersion(t *testing.T) {
	p := pool(t)
	keepProjectionRow(t, p)
	clearProjectionRow(t, p)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if status, err := projection.Status(ctx); err != nil || status.Bootstrapped {
		t.Fatalf("before a snapshot the status is %+v, %v; want not bootstrapped", status, err)
	}

	base := func(version int64) Grant {
		return Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "eligible",
			GrantStatus: "active", GrantVersion: version}
	}
	older := base(2)
	hold(t, p, older)
	newer := base(5)
	hold(t, p, newer)
	omitted := base(2)
	hold(t, p, omitted)
	added := base(1)
	cleanup(t, p, added.GrantID)

	advanced := older
	advanced.GrantVersion = 3
	advanced.Activation = &Activation{ActivationID: newID(t), EndsAt: time.Now().Add(time.Hour)}
	stale := newer
	stale.GrantVersion, stale.Kind = 4, "emergency"

	if err := projection.ReplaceFromSnapshot(ctx, 40, []Grant{advanced, stale, added}); err != nil {
		t.Fatalf("ReplaceFromSnapshot: %v", err)
	}
	for _, check := range []struct {
		what  string
		grant Grant
		want  held
	}{
		{"a grant the snapshot carries newer", older, held{"active", "eligible", 3, true}},
		{"a grant held newer than the snapshot", newer, held{"active", "eligible", 5, false}},
		{"a grant the snapshot omits", omitted, held{"revoked", "eligible", 2, false}},
		{"a grant first seen in the snapshot", added, held{"active", "eligible", 1, false}},
	} {
		if got, found := read(t, p, check.grant.GrantID); !found || got != check.want {
			t.Errorf("%s: held %+v (found %v), want %+v", check.what, got, found, check.want)
		}
	}

	status, err := projection.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Bootstrapped || status.SnapshotMark != 40 || status.AppliedMark != 40 {
		t.Errorf("after the snapshot the status is %+v; want bootstrapped at 40", status)
	}

	// Progress past the mark survives a rerun from an older snapshot.
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, advanceAppliedStatement, int64(70))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := projection.ReplaceFromSnapshot(ctx, 50, []Grant{advanced, stale, added}); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if status, _ := projection.Status(ctx); status.SnapshotMark != 50 || status.AppliedMark != 70 {
		t.Errorf("after a rerun the status is %+v; want snapshot 50, applied 70", status)
	}
}

// A snapshot that is not one is refused whole, and nothing is written.
func TestAMalformedSnapshotIsRefused(t *testing.T) {
	p := pool(t)
	keepProjectionRow(t, p)
	clearProjectionRow(t, p)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	held := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "eligible", GrantStatus: "active", GrantVersion: 1}
	hold(t, p, held)
	revoked := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: Scope, Kind: "eligible", GrantStatus: "revoked", GrantVersion: 2}
	other := Grant{GrantID: newID(t), PrincipalID: newID(t), Scope: "provider:organization-control", Kind: "eligible", GrantStatus: "active", GrantVersion: 1}

	for _, bad := range []struct {
		what   string
		mark   int64
		grants []Grant
	}{
		{"a revoked row", 10, []Grant{revoked}},
		{"another scope", 10, []Grant{other}},
		{"a negative mark", -1, nil},
	} {
		err := projection.ReplaceFromSnapshot(ctx, bad.mark, bad.grants)
		if err == nil {
			t.Errorf("%s was accepted", bad.what)
			continue
		}
		if bad.mark >= 0 && !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v; want ErrMalformed", bad.what, err)
		}
	}
	if got, _ := read(t, p, held.GrantID); got.status != "active" {
		t.Errorf("a refused snapshot revoked a held grant: %+v", got)
	}
	if status, _ := projection.Status(ctx); status.Bootstrapped {
		t.Error("a refused snapshot recorded a bootstrap")
	}
}
