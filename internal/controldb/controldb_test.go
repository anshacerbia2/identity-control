package controldb_test

// These tests need no database. They assert that the embedded statements exist and that an
// unknown stage is refused, which is what stops a typo in a stage name from producing a
// migration run that applies nothing and reports success.

import (
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/controldb"
)

func TestSQLReturnsEveryStage(t *testing.T) {
	for _, stage := range []controldb.Stage{controldb.StageRoles, controldb.StageGrants} {
		body, err := controldb.SQL(stage)
		if err != nil {
			t.Fatalf("SQL(%s): %v", stage, err)
		}
		if strings.TrimSpace(body) == "" {
			t.Fatalf("SQL(%s) returned no statements", stage)
		}
	}
}

func TestSQLRejectsUnknownStage(t *testing.T) {
	if _, err := controldb.SQL(controldb.Stage("nope.sql")); err == nil {
		t.Fatal("SQL accepted an unknown stage; a typo would apply nothing and report success")
	}
}

// TestRolesStageCreatesBothRoles is a content assertion rather than a behaviour one, and it
// earns its place: the Week 1 exit criterion names two roles, and a stage that silently
// stopped creating one would leave the privilege suite asserting against a role that does
// not exist, where every restriction passes for the wrong reason.
func TestRolesStageCreatesBothRoles(t *testing.T) {
	body, err := controldb.SQL(controldb.StageRoles)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}

	for _, role := range []string{"identity_migrator", "identity_runtime"} {
		if !strings.Contains(body, "CREATE ROLE "+role) {
			t.Errorf("roles.sql does not create %s", role)
		}
		if !strings.Contains(body, "ALTER ROLE "+role) {
			t.Errorf("roles.sql does not re-assert attributes on %s; a role restored from a dump would keep privileges this file never granted", role)
		}
	}

	if !strings.Contains(body, "NOBYPASSRLS") {
		t.Error("roles.sql does not state NOBYPASSRLS; a role holding it reads every tenant's rows while every policy still reports as enabled")
	}

	// The schema container is created here rather than by Atlas, because a schema-scoped
	// Atlas plan may not modify the schema it is scoped to.
	if !strings.Contains(body, "CREATE SCHEMA IF NOT EXISTS identity") {
		t.Error("roles.sql does not create the identity schema; Atlas cannot create it in schema scope")
	}
}

// TestGrantsStageGuardsItsOrdering asserts the guard exists. A grant over an empty schema
// is a no-op rather than an error, so without this the stage reports success and grants
// nothing — which is how the first end-to-end run of this pipeline failed.
func TestGrantsStageGuardsItsOrdering(t *testing.T) {
	body, err := controldb.SQL(controldb.StageGrants)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}

	if !strings.Contains(body, "RAISE EXCEPTION") {
		t.Error("grants.sql has no ordering guard; run before Atlas it would grant nothing and report success")
	}

	for _, object := range []string{
		"identity.principal_mapping",
		"identity.projection_cursor",
		"platform.outbox",
	} {
		if !strings.Contains(body, object) {
			t.Errorf("grants.sql does not mention %s", object)
		}
	}

	// foundation-platform ships the platform schema with no GRANT of its own, so granting
	// on it is this repository's obligation. Forgetting it produces a runtime that cannot
	// reach its own outbox.
	if !strings.Contains(body, "GRANT USAGE ON SCHEMA platform") {
		t.Error("grants.sql does not grant USAGE on the platform schema")
	}
}
