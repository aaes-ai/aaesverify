package verifier

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The verifier may import only the standard library, internal/hash and
// internal/types. Anything else in its transitive closure defeats the point of
// the package: an auditor must be able to read it, compile it and run it
// against a JSONL export on a machine that has never talked to AAES.
var allowedVerifierImports = map[string]bool{
	"github.com/aaes-ai/aaesverify/internal/hash":  true,
	"github.com/aaes-ai/aaesverify/internal/types": true,
}

var forbiddenImportFragments = []string{
	"internal/gateway",
	"internal/journal",
	"internal/policy",
	"internal/credentials",
	"internal/directory",
	"internal/audit",
	"internal/connectors",
	"internal/ids",
}

// TestNoForbiddenImports is the mechanical form of this package's central
// promise. It checks every file in the package, test files included, so a
// direct import of the gateway, the journal, policy, credentials, the
// directory, the audit producer or a connector fails the build. The transitive
// form is TestNoForbiddenImportsInTheClosure below; this one stays because it
// also governs the tests, which the closure walk deliberately skips.
func TestNoForbiddenImports(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate the package directory")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", ent.Name(), err)
		}
		checked++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, "\"")
			first := strings.SplitN(p, "/", 2)[0]
			if !strings.Contains(first, ".") {
				continue // standard library
			}
			if allowedVerifierImports[p] {
				continue
			}
			t.Errorf("%s imports %q; the verifier may import only the standard library, internal/hash and internal/types", ent.Name(), p)
			for _, bad := range forbiddenImportFragments {
				if strings.Contains(p, bad) {
					t.Errorf("%s imports forbidden package %q", ent.Name(), p)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files were checked; the walk is broken")
	}
}

// TestNoForbiddenImportsInTheClosure is the audit's O15. The direct check above
// cannot see a forbidden package that arrives through an intermediate one: if
// internal/hash ever gained a dependency on internal/journal, the verifier's own
// imports would still be clean while every claim this package makes about
// running offline would be false. This test walks the transitive dependency
// closure — the same thing tools/checkisolation does with go list -deps, done
// here by parsing so it also works on a scratch tree with no build artifacts —
// and requires every non-standard-library package in it to be one of the two
// allowed internal packages.
func TestNoForbiddenImportsInTheClosure(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate the package directory")
	}
	dir := filepath.Dir(thisFile)
	root, modulePath := moduleRoot(t, dir)

	violations, visited := closureCheck(t, root, modulePath, dir, allowedVerifierImports)
	if len(violations) > 0 {
		t.Errorf("the verifier's transitive import closure is not isolated:")
		for _, v := range violations {
			t.Errorf("  - %s", v)
		}
	}
	// A walk that silently visits nothing would pass the check above, so the
	// packages that MUST be in the closure are asserted by name.
	for _, want := range []string{
		"github.com/aaes-ai/aaesverify/internal/hash",
		"github.com/aaes-ai/aaesverify/internal/types",
	} {
		if !sortedContains(visited, want) {
			t.Errorf("the closure walk never reached %s; the check is not closing over the package (visited %v)", want, visited)
		}
	}
}

// TestTheClosureGuardCatchesATransitiveDependency proves the closure check is
// load-bearing, which a green run against the real tree cannot do on its own.
// It builds a scratch module in which the verifier's DIRECT imports are exactly
// the allowed two, while internal/hash imports a package that imports the
// forbidden journal. The direct check passes; the closure check must fail and
// name the transitive path.
func TestTheClosureGuardCatchesATransitiveDependency(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write("go.mod", "module github.com/aaes-ai/aaesverify\n\ngo 1.27\n")
	write("internal/hash/hash.go", "package hash\n\nimport _ \"github.com/aaes-ai/aaesverify/internal/scratchdep\"\n")
	write("internal/types/types.go", "package types\n")
	write("internal/scratchdep/dep.go", "package scratchdep\n\nimport _ \"github.com/aaes-ai/aaesverify/internal/journal\"\n")
	write("internal/journal/journal.go", "package journal\n")
	write("internal/verifier/verifier.go", "package verifier\n\nimport (\n\t_ \"github.com/aaes-ai/aaesverify/internal/hash\"\n\t_ \"github.com/aaes-ai/aaesverify/internal/types\"\n)\n")

	startDir := filepath.Join(root, "internal", "verifier")
	for _, imp := range packageImports(t, startDir) {
		if !allowedVerifierImports[imp] {
			t.Fatalf("the scratch verifier imports %s directly, so it does not model a transitive-only dependency", imp)
		}
	}

	violations, visited := closureCheck(t, root, "github.com/aaes-ai/aaesverify", startDir, allowedVerifierImports)
	if len(violations) == 0 {
		t.Fatal("the closure walk accepted a transitive dependency on internal/journal through internal/hash")
	}
	joined := strings.Join(violations, "; ")
	for _, want := range []string{"internal/scratchdep", "internal/journal"} {
		if !strings.Contains(joined, want) {
			t.Errorf("violations %q do not name %s", joined, want)
		}
	}
	if !sortedContains(visited, "github.com/aaes-ai/aaesverify/internal/scratchdep") {
		t.Errorf("the walk never reached the intermediate package; visited %v", visited)
	}
}

// closureCheck walks the transitive import closure of the package in startDir
// and returns the violations it found plus every package path it visited.
//
// Every non-standard-library import must resolve inside the module and be in
// allowed; a package that is allowed is still walked, because the whole point
// is to see what IT imports. An import that does not resolve to a directory is
// a violation rather than a skip: a dependency the walk cannot follow is a
// dependency the check cannot clear.
func closureCheck(t *testing.T, root, modulePath, startDir string, allowed map[string]bool) ([]string, []string) {
	t.Helper()
	var violations []string
	visited := map[string]bool{}
	seenDir := map[string]bool{}
	queue := []string{startDir}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if seenDir[dir] {
			continue
		}
		seenDir[dir] = true
		visited[importPathOf(t, root, modulePath, dir)] = true
		for _, imp := range packageImports(t, dir) {
			if !strings.Contains(strings.SplitN(imp, "/", 2)[0], ".") {
				continue // standard library
			}
			from := relativeTo(root, dir)
			next, local := localDir(root, modulePath, imp)
			if !local {
				violations = append(violations, fmt.Sprintf("%s imports %s, which is not a package in this module", from, imp))
				continue
			}
			if !allowed[imp] {
				violations = append(violations, fmt.Sprintf("%s imports %s, which the verifier's closure may not contain", from, imp))
			}
			if info, err := os.Stat(next); err != nil || !info.IsDir() {
				violations = append(violations, fmt.Sprintf("%s imports %s, which does not resolve to a directory under %s", from, imp, root))
				continue
			}
			queue = append(queue, next)
		}
	}
	sort.Strings(violations)
	out := make([]string, 0, len(visited))
	for p := range visited {
		out = append(out, p)
	}
	sort.Strings(out)
	return violations, out
}

// packageImports parses the non-test Go files in dir and returns their import
// paths. Test files are skipped: a dependency of a test is not a dependency of
// the package an auditor compiles, and TestNoForbiddenImports already covers
// them directly.
func packageImports(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	var out []string
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, ent.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", ent.Name(), err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, "\"")
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// moduleRoot walks up from dir to the directory holding go.mod and returns that
// directory and the module path declared in the file.
func moduleRoot(t *testing.T, dir string) (string, string) {
	t.Helper()
	for d := dir; ; {
		data, err := os.ReadFile(filepath.Join(d, "go.mod"))
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if rest, ok := strings.CutPrefix(line, "module "); ok {
					return d, strings.TrimSpace(rest)
				}
			}
			t.Fatalf("%s/go.mod declares no module path", d)
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatalf("no go.mod above %s", dir)
		}
		d = parent
	}
}

// localDir maps an import path to the directory that holds it, when the path
// belongs to the module rooted at root.
func localDir(root, modulePath, imp string) (string, bool) {
	if imp == modulePath {
		return root, true
	}
	if rest, ok := strings.CutPrefix(imp, modulePath+"/"); ok {
		return filepath.Join(root, filepath.FromSlash(rest)), true
	}
	return "", false
}

// importPathOf is the inverse of localDir for a directory inside the module.
func importPathOf(t *testing.T, root, modulePath, dir string) string {
	t.Helper()
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		t.Fatalf("relativise %s against %s: %v", dir, root, err)
	}
	if rel == "." {
		return modulePath
	}
	return modulePath + "/" + filepath.ToSlash(rel)
}

func relativeTo(root, dir string) string {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return dir
	}
	return filepath.ToSlash(rel)
}

func sortedContains(list []string, want string) bool {
	i := sort.SearchStrings(list, want)
	return i < len(list) && list[i] == want
}
