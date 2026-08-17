package controldb_test

// The Week 1 exit criterion is a property of the database, not of the SQL that built it:
//
//	the runtime role owns no table, holds no SUPERUSER, no BYPASSRLS, and no DDL
//	privilege, proven by assertion rather than by review.
//
// Every assertion below reads the PostgreSQL catalog. A test that re-read roles.sql and
// grants.sql would only assert that the files say what they say, and the failure this
// criterion guards against is a privilege arriving from somewhere else — a restored dump,
// a hand-run GRANT, a role that predates these files.
//
// The suite skips without TEST_DATABASE_URL and fails on a skip when REQUIRE_INTEGRATION
// is set. CI sets both, because a service container that never came up would otherwise
// leave every assertion skipped and the run green, which is indistinguishable from having
// checked something.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
)

const (
	migratorRole = "identity_migrator"
	runtimeRole  = "identity_runtime"
)

func openPool(t *testing.T) (*db.Pool, context.Context) {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty: the database this suite asserts against never came up")
		}
		t.Skip("TEST_DATABASE_URL is unset; set it to run privilege assertions against a real server")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	pool, err := db.Open(ctx, db.Config{Name: "controldb-test", DSN: dsn, MaxConns: 2})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool, ctx
}

func queryBool(t *testing.T, pool *db.Pool, ctx context.Context, statement string, args ...any) bool {
	t.Helper()
	var result bool
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, statement, args...).Scan(&result)
	}); err != nil {
		t.Fatalf("query %q: %v", statement, err)
	}
	return result
}

func queryInt(t *testing.T, pool *db.Pool, ctx context.Context, statement string, args ...any) int {
	t.Helper()
	var result int
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, statement, args...).Scan(&result)
	}); err != nil {
		t.Fatalf("query %q: %v", statement, err)
	}
	return result
}

// TestRolesExist establishes the precondition for every assertion after it. Without this,
// a missing role would make each privilege check below pass for the wrong reason: a role
// that does not exist holds no privileges either.
func TestRolesExist(t *testing.T) {
	pool, ctx := openPool(t)

	for _, role := range []string{migratorRole, runtimeRole} {
		if !queryBool(t, pool, ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role) {
			t.Errorf("role %s does not exist; identity-migrate -stage=pre has not run", role)
		}
	}
}

// TestRuntimeRoleAttributes asserts the four cluster attributes named by the exit
// criterion, plus the two that would let the role create its way around the others.
//
// BYPASSRLS is the one worth stating separately: a role holding it reads every tenant's
// rows while every Row-Level Security policy in the estate still reports as enabled, so
// the control fails silently rather than loudly.
func TestRuntimeRoleAttributes(t *testing.T) {
	pool, ctx := openPool(t)

	attributes := map[string]string{
		"rolsuper":       "SUPERUSER",
		"rolbypassrls":   "BYPASSRLS",
		"rolcreatedb":    "CREATEDB",
		"rolcreaterole":  "CREATEROLE",
		"rolreplication": "REPLICATION",
	}

	for column, name := range attributes {
		held := queryBool(t, pool, ctx,
			`SELECT `+column+` FROM pg_roles WHERE rolname = $1`, runtimeRole)
		if held {
			t.Errorf("%s holds %s; the exit criterion forbids it", runtimeRole, name)
		}
	}
}

// TestRuntimeRoleOwnsNothing asserts the ownership half of the criterion. Ownership is
// what makes the DML grants sufficient: an owner can ALTER and DROP its own tables
// regardless of which privileges were granted to it.
func TestRuntimeRoleOwnsNothing(t *testing.T) {
	pool, ctx := openPool(t)

	tables := queryInt(t, pool, ctx,
		`SELECT count(*) FROM pg_tables WHERE tableowner = $1`, runtimeRole)
	if tables != 0 {
		t.Errorf("%s owns %d table(s); it must own none", runtimeRole, tables)
	}

	schemas := queryInt(t, pool, ctx,
		`SELECT count(*) FROM information_schema.schemata WHERE schema_owner = $1`, runtimeRole)
	if schemas != 0 {
		t.Errorf("%s owns %d schema(s); it must own none", runtimeRole, schemas)
	}

	sequences := queryInt(t, pool, ctx,
		`SELECT count(*) FROM pg_class c
		 JOIN pg_roles r ON r.oid = c.relowner
		 WHERE c.relkind = 'S' AND r.rolname = $1`, runtimeRole)
	if sequences != 0 {
		t.Errorf("%s owns %d sequence(s); it must own none", runtimeRole, sequences)
	}
}

// TestRuntimeRoleHoldsNoDDL asserts the DDL half. CREATE on a schema is the DDL privilege
// that matters here: a role holding it can add a table it then owns, which would defeat
// the ownership assertion above on the next deploy rather than on this one.
func TestRuntimeRoleHoldsNoDDL(t *testing.T) {
	pool, ctx := openPool(t)

	for _, schema := range []string{"identity", "platform"} {
		if queryBool(t, pool, ctx,
			`SELECT has_schema_privilege($1, $2, 'CREATE')`, runtimeRole, schema) {
			t.Errorf("%s holds CREATE on schema %s; it must hold none", runtimeRole, schema)
		}
	}

	// TRUNCATE on the outbox would let the runtime discard undelivered security events in
	// one statement. Partition retention is the migration role's job precisely so that
	// capability lives outside the request path.
	if queryBool(t, pool, ctx,
		`SELECT has_table_privilege($1, 'platform.outbox', 'TRUNCATE')`, runtimeRole) {
		t.Errorf("%s holds TRUNCATE on platform.outbox; retention belongs to the migration role", runtimeRole)
	}
}

// TestMigratorRoleOwnsTheSchemas is the other side of the same property. If the migration
// role owns nothing either, the objects belong to whichever superuser ran the migration,
// and the separation the criterion describes exists only on paper.
func TestMigratorRoleOwnsTheSchemas(t *testing.T) {
	pool, ctx := openPool(t)

	for _, schema := range []string{"identity", "platform"} {
		owner := ""
		if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT schema_owner FROM information_schema.schemata WHERE schema_name = $1`,
				schema).Scan(&owner)
		}); err != nil {
			t.Fatalf("read owner of %s: %v", schema, err)
		}
		if owner != migratorRole {
			t.Errorf("schema %s is owned by %q, want %q", schema, owner, migratorRole)
		}
	}
}

// TestRuntimeRoleCanPerformDML is the assertion that stops the four above from being
// satisfiable by granting nothing at all. A runtime that cannot read its own mapping table
// or append to its own outbox passes every restriction and serves no request.
func TestRuntimeRoleCanPerformDML(t *testing.T) {
	pool, ctx := openPool(t)

	required := []struct {
		object    string
		privilege string
	}{
		{"identity.principal_mapping", "SELECT"},
		{"identity.principal_mapping", "INSERT"},
		{"identity.principal_mapping", "UPDATE"},
		{"identity.projection_cursor", "SELECT"},
		{"identity.projection_cursor", "UPDATE"},
		{"platform.outbox", "INSERT"},
		{"platform.outbox", "SELECT"},
		{"platform.outbox", "UPDATE"},
		{"platform.processed_event", "INSERT"},
		{"platform.dead_letter", "INSERT"},
		{"platform.idempotency_key", "INSERT"},
	}

	for _, want := range required {
		if !queryBool(t, pool, ctx,
			`SELECT has_table_privilege($1, $2, $3)`, runtimeRole, want.object, want.privilege) {
			t.Errorf("%s lacks %s on %s; the runtime cannot serve without it",
				runtimeRole, want.privilege, want.object)
		}
	}

	// platform.outbox_sequence is read by every append. Without USAGE the outbox write
	// fails inside the caller's domain transaction, so a domain mutation rolls back.
	if !queryBool(t, pool, ctx,
		`SELECT has_sequence_privilege($1, 'platform.outbox_sequence', 'USAGE')`, runtimeRole) {
		t.Errorf("%s lacks USAGE on platform.outbox_sequence; every outbox append would fail", runtimeRole)
	}

	for _, schema := range []string{"identity", "platform"} {
		if !queryBool(t, pool, ctx,
			`SELECT has_schema_privilege($1, $2, 'USAGE')`, runtimeRole, schema) {
			t.Errorf("%s lacks USAGE on schema %s", runtimeRole, schema)
		}
	}
}

// TestWeek1SchemaShape asserts that the two tables named by the Week 1 checklist exist
// with the state machine and the partial unique index it calls out. Atlas applied them, so
// this is a check that the applied state matches what schema.hcl declares rather than a
// restatement of the DDL.
func TestWeek1SchemaShape(t *testing.T) {
	pool, ctx := openPool(t)

	for _, table := range []string{"principal_mapping", "projection_cursor"} {
		if !queryBool(t, pool, ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'identity' AND tablename = $1)`,
			table) {
			t.Errorf("identity.%s does not exist; Atlas has not applied schema.hcl", table)
		}
	}

	// The state machine is a CHECK constraint rather than application validation, so a
	// repair script cannot write a state the transition diagram does not contain.
	for _, constraint := range []string{
		"principal_mapping_state_check",
		"principal_mapping_subject_check",
		"principal_mapping_owner_check",
	} {
		if !queryBool(t, pool, ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM pg_constraint c
			   JOIN pg_class t ON t.oid = c.conrelid
			   JOIN pg_namespace n ON n.oid = t.relnamespace
			   WHERE n.nspname = 'identity' AND t.relname = 'principal_mapping'
			     AND c.conname = $1 AND c.contype = 'c')`, constraint) {
			t.Errorf("check constraint %s is absent from identity.principal_mapping", constraint)
		}
	}

	if !queryBool(t, pool, ctx,
		`SELECT indpred IS NOT NULL AND indisunique
		   FROM pg_index i
		   JOIN pg_class c ON c.oid = i.indexrelid
		   JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'identity' AND c.relname = 'principal_mapping_realm_user'`) {
		t.Error("identity.principal_mapping_realm_user is not a partial unique index")
	}
}
