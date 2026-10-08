package httpapi

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"
)

// The key a command route claims, against platform.idempotency_key as the runtime role holds it:
// claimed, in progress for a concurrent retry, released after a refusal, and replayed once complete.
func TestThePoolLedgerClaimsReleasesAndReplays(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{Name: "command-keys-test", DSN: dsn, MaxConns: 2})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ledger := poolLedger{store: pool}
	caller, _ := id.NewV7()
	claim := keyClaim{scope: "route:principal:" + caller.String(), key: "grant-owner-1", digest: "digest-1"}

	if stored, err := ledger.take(ctx, claim); err != nil || stored != nil {
		t.Fatalf("the first take = %v, %v; want a fresh claim", stored, err)
	}
	if _, err := ledger.take(ctx, claim); !errors.Is(err, idempotency.ErrInProgress) {
		t.Fatalf("a concurrent retry = %v, want in progress", err)
	}
	if err := ledger.release(ctx, claim); err != nil {
		t.Fatalf("release: %v", err)
	}
	if stored, err := ledger.take(ctx, claim); err != nil || stored != nil {
		t.Fatalf("a take after the release = %v, %v; want a fresh claim", stored, err)
	}
	if err := ledger.complete(ctx, claim, 201, []byte(`{"owner":"granted"}`)); err != nil {
		t.Fatalf("complete: %v", err)
	}
	stored, err := ledger.take(ctx, claim)
	if err != nil || stored == nil || stored.status != 201 || string(stored.body) != `{"owner": "granted"}` && string(stored.body) != `{"owner":"granted"}` {
		t.Fatalf("a retry after completion = %+v, %v; want the recorded 201", stored, err)
	}
	other := claim
	other.digest = "digest-2"
	if _, err := ledger.take(ctx, other); !errors.Is(err, idempotency.ErrConflict) {
		t.Errorf("the key on another request = %v, want a conflict", err)
	}

	empty := keyClaim{scope: claim.scope, key: "revoke-1", digest: "digest-3"}
	if _, err := ledger.take(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if err := ledger.complete(ctx, empty, 204, nil); err != nil {
		t.Fatalf("complete with no body: %v", err)
	}
	if stored, err := ledger.take(ctx, empty); err != nil || stored == nil || stored.status != 204 {
		t.Errorf("a retry of a 204 = %+v, %v", stored, err)
	}
}
