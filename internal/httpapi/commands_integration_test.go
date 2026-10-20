package httpapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

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

// The published window (TDD-identity-control-003 1.39.0 §Key Retention): a completed key older than 7
// days is purged, a younger one and an uncompleted one of any age are kept, and the runtime role the
// service runs as may do it.
func TestCompletedKeysArePurgedAfterTheirWindow(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{Name: "key-purge-test", DSN: dsn, MaxConns: 2})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	scope := "route:purge-test"
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM platform.idempotency_key WHERE scope = $1`, scope); err != nil {
			return err
		}
		for _, row := range []struct {
			key, age  string
			completed bool
		}{{"old", "8 days", true}, {"young", "6 days", true}, {"old-uncompleted", "30 days", false}} {
			completed := "NULL"
			if row.completed {
				completed = "now() - interval '" + row.age + "'"
			}
			if _, err := tx.Exec(ctx, `INSERT INTO platform.idempotency_key
			    (scope, key, request_digest, claimed_at, completed_at, response_status, response_body)
			    VALUES ($1, $2, 'd', now() - interval '`+row.age+`', `+completed+`, 200, 'null')`, scope, row.key); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeKeys(ctx, pool); err != nil {
		t.Fatalf("PurgeKeys: %v", err)
	}
	var left []string
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key FROM platform.idempotency_key WHERE scope = $1 ORDER BY key`, scope)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				return err
			}
			left = append(left, key)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(left, ",") != "old-uncompleted,young" {
		t.Errorf("keys left %v; want the young and the uncompleted kept", left)
	}
	if KeyRetention != 7*24*time.Hour {
		t.Errorf("the published window is 7 days, not %s", KeyRetention)
	}
	var executes, otherFunctions bool
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT has_function_privilege('identity_runtime',
		    'platform.purge_idempotency_keys(interval)', 'EXECUTE')`).Scan(&executes); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT bool_or(has_function_privilege('identity_runtime', p.oid, 'EXECUTE'))
		    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		    WHERE n.nspname = 'platform' AND p.proname <> 'purge_idempotency_keys'`).Scan(&otherFunctions)
	}); err != nil {
		t.Fatal(err)
	}
	if !executes || otherFunctions {
		t.Errorf("the runtime executes the purge %v and another platform function %v; want only the purge", executes, otherFunctions)
	}
}
