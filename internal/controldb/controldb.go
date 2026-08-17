// Package controldb carries the Control Database statements that Atlas does not own,
// embedded so the migration binary needs no files beside it.
//
// Two things live here and neither belongs in schema.hcl:
//
//   - Roles are cluster objects rather than schema objects, and Atlas Community manages
//     schemas, tables, indexes, and constraints. Declaring the role graph as explicit SQL
//     is the honest boundary, not a workaround.
//   - Privileges must be granted after every object exists, including the `platform`
//     tables that foundation-platform ships. A declarative desired state cannot express
//     "after the other owner's migration ran".
//
// ci.yml asserts the resulting privileges against the PostgreSQL catalog, so neither file
// is trusted to be complete on the strength of having been written.
package controldb

import (
	"embed"
	"fmt"
)

//go:embed roles.sql grants.sql
var statements embed.FS

// Stage names one ordered step of a Control Database migration run.
type Stage string

const (
	// StageRoles creates the cluster roles. It runs before any schema exists.
	StageRoles Stage = "roles.sql"

	// StageGrants gives the runtime role its privileges. It runs after the platform
	// migrations and after Atlas has applied the identity schema, because a GRANT names
	// objects and an object that does not exist yet cannot be granted on.
	StageGrants Stage = "grants.sql"
)

// SQL returns the statements for one stage.
func SQL(stage Stage) (string, error) {
	body, err := statements.ReadFile(string(stage))
	if err != nil {
		return "", fmt.Errorf("controldb: read %s: %w", stage, err)
	}
	if len(body) == 0 {
		return "", fmt.Errorf("controldb: %s is empty", stage)
	}
	return string(body), nil
}
