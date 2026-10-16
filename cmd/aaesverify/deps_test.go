package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestImportGraphExcludesOperatorPackages(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".")
	cmd.Dir = moduleDir(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	forbidden := []string{
		"internal/gateway",
		"internal/journal",
		"internal/policy",
		"internal/credentials",
		"internal/aaesctl",
		"internal/evidencepack",
		"internal/audit",
		"internal/connectors",
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, frag := range forbidden {
			if strings.Contains(line, frag) {
				t.Errorf("aaesverify depends on %s via %s", frag, line)
			}
		}
	}
}

func TestCandidateEvidenceFlags(t *testing.T) {
	out, code := captureRun(t, []string{"-h"})
	if code != 0 {
		t.Fatalf("aaesverify -h exited %d:\n%s", code, out)
	}
	for _, name := range []string{"-records", "-evaluation", "-export"} {
		if !strings.Contains(out, name) {
			t.Fatalf("candidate missing %s: %s", name, out)
		}
	}
}

func TestVerifyCurrentExportFixture(t *testing.T) {
	export := filepath.Join(moduleDir(t), "testdata", "export_v2.jsonl")
	pub := filepath.Join(moduleDir(t), "testdata", "public_key.hex")
	out, code := captureRun(t, []string{"--export", export, "--pubkey", pub, "--allow-pre-anchor"})
	if code != 0 {
		t.Fatalf("aaesverify fixture exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "CONSISTENT") {
		t.Fatalf("want CONSISTENT, got:\n%s", out)
	}
}

func captureRun(t *testing.T, args []string) (string, int) {
	t.Helper()
	return captureWith(t, args, run)
}

// captureWith runs entry with stdout and stderr captured together.
func captureWith(t *testing.T, args []string, entry func([]string) int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	code := entry(args)
	_ = w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), code
}

func moduleDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Dir(file)
}

// exportFixturePath is a v2 export with its ledger key embedded.
func exportFixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(moduleDir(t), "testdata", "export_v2.jsonl")
}
