package controldb_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/controldb"
)

// purgeSource is the one production file allowed to delete an audit record: the scheduled purge,
// which deletes only records older than 7 years (STD-GLB-007 1.2.1, TDD-identity-control-001 1.24.0
// §Audit Retention).
var purgeSource = filepath.Join("internal", "controldb", "retention.go")

// TestNoSourceDeletesAnAuditRecord reads every migration and every production Go file for a DELETE
// or TRUNCATE naming an audit table (STD-GLB-007 1.2.1 §Data Retention: a record younger than 7
// years is never purged). Only the purge may, and every statement it holds compares with the 7-year
// boundary. The tables' retention triggers refuse any other delete at run time; this keeps one from
// being written, in a migration as much as in the service.
func TestNoSourceDeletesAnAuditRecord(t *testing.T) {
	root := filepath.Join("..", "..")
	var names []string
	for _, table := range auditTables {
		names = append(names, regexp.QuoteMeta(strings.TrimPrefix(table, "identity.")))
	}
	purge := regexp.MustCompile(`(?i)(DELETE\s+FROM|TRUNCATE(\s+TABLE)?)\s+("?identity"?\.)?"?(` +
		strings.Join(names, "|") + `)"?\b`)
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Dot directories hold no source: .git, and local caches such as .image-scan.
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		production := strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
		if !production && !strings.HasSuffix(path, ".sql") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		if rel, _ := filepath.Rel(root, path); rel == purgeSource {
			return nil
		}
		if match := purge.Find(source); match != nil {
			t.Errorf("%s purges an audit record: %q", path, match)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the repository: %v", err)
	}
	if checked < 50 {
		t.Fatalf("read %d files; the walk is not reaching the sources", checked)
	}
}

// TestThePurgeComparesEveryDeleteWithSevenYears reads the purge's own source: each DELETE it holds is
// in a statement that compares with the boundary, and the floor is 7.
func TestThePurgeComparesEveryDeleteWithSevenYears(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", purgeSource))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	deletes := strings.Count(text, "DELETE FROM identity.")
	bounded := strings.Count(text, "` + expired")
	if deletes == 0 || bounded < deletes {
		t.Errorf("%s holds %d deletes and %d comparisons with the boundary; each delete needs one", purgeSource, deletes, bounded)
	}
	if !strings.Contains(text, "const expired = `< now() - make_interval(years => $1)`") {
		t.Error("the purge's boundary is not now() - make_interval(years => $1)")
	}
	if controldb.AuditRetentionFloor != 7 {
		t.Errorf("AuditRetentionFloor is %d; STD-GLB-007 keeps an audit record 7 years", controldb.AuditRetentionFloor)
	}
}

// TestTheAuditTableListsAgree holds the catalog test's list and the purge's together, and the purge's
// columns: a table added to one and not the other would carry triggers nothing checks, or none.
func TestTheAuditTableListsAgree(t *testing.T) {
	if len(controldb.AuditTables) != len(auditTables) {
		t.Fatalf("controldb.AuditTables names %d tables, auditTables %d", len(controldb.AuditTables), len(auditTables))
	}
	for i, table := range controldb.AuditTables {
		if table.Name != auditTables[i] {
			t.Errorf("table %d: controldb.AuditTables names %s, auditTables %s", i, table.Name, auditTables[i])
		}
		if len(table.Columns) == 0 {
			t.Errorf("%s names no column to read its age from", table.Name)
		}
	}
}
