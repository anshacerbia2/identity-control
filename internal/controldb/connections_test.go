package controldb_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestOnlyTheControlDatabaseIsOpened is the Week 3 exit (ROADMAP §Week 3): no code path in this
// service constructs an Organization Database connection.
//
// archcheck's deniedImports (arch.json) keep pgx and database/sql out of every package, so the only
// way to open a connection is foundation-platform's db.Open. This test holds what archcheck cannot
// see: every db.Open is in a cmd/ composition root, its DSN is the Control Database's, and the only
// database URLs this service reads from its environment are its own two.
func TestOnlyTheControlDatabaseIsOpened(t *testing.T) {
	root := moduleRoot(t)
	allowedDSN := []string{"cfg.RuntimeDSN", "dsn"}
	allowedEnv := []string{"IDENTITY_DATABASE_URL", "IDENTITY_MIGRATION_DATABASE_URL"}
	databaseEnv := regexp.MustCompile(`^[A-Z][A-Z0-9_]*_(DATABASE_URL|DSN)$`)

	opens := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		dbName := ""
		for _, spec := range file.Imports {
			importPath, _ := strconv.Unquote(spec.Path.Value)
			if strings.Contains(importPath, "foundation-platform") && strings.HasSuffix(importPath, "/db") {
				dbName = "db"
				if spec.Name != nil {
					dbName = spec.Name.Name
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					value, _ := strconv.Unquote(n.Value)
					if databaseEnv.MatchString(value) && !slices.Contains(allowedEnv, value) {
						t.Errorf("%s reads %s: this service reads no database URL but the Control Database's",
							rel, value)
					}
				}
			case *ast.CallExpr:
				selector, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || dbName == "" || selector.Sel.Name != "Open" {
					return true
				}
				if pkg, ok := selector.X.(*ast.Ident); !ok || pkg.Name != dbName {
					return true
				}
				opens++
				if !strings.HasPrefix(filepath.ToSlash(rel), "cmd/") {
					t.Errorf("%s opens a database pool; only a cmd/ composition root opens one", rel)
				}
				dsn := dsnOf(n)
				if !slices.Contains(allowedDSN, dsn) {
					t.Errorf("%s opens a pool with DSN %q; only the Control Database's (%v) is opened", rel, dsn, allowedDSN)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if opens == 0 {
		t.Fatal("no db.Open call was found; the test no longer sees how this service connects")
	}
}

// dsnOf is the DSN field of the db.Config literal a db.Open call is given, as source text.
func dsnOf(call *ast.CallExpr) string {
	for _, arg := range call.Args {
		literal, ok := arg.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := field.Key.(*ast.Ident); ok && key.Name == "DSN" {
				return exprText(field.Value)
			}
		}
	}
	return ""
}

func exprText(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprText(e.X) + "." + e.Sel.Name
	}
	return "<expression>"
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test's directory")
		}
		dir = parent
	}
}
