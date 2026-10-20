package controldb_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoSourceDeletesAnAuditRecord reads every migration and every production Go file for a DELETE
// or TRUNCATE naming an audit table (STD-GLB-007 1.1.0 §Data Retention: a record younger than 7
// years is never purged). The catalog assertion in TestNoAuditRecordIsPurgedBeforeSevenYears covers
// the runtime role; this covers the migration role, which owns the tables and could purge them from
// a migration.
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
			if name := d.Name(); name == ".git" || name == "node_modules" || name == ".image-scan" {
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
