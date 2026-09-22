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

func TestNoRecordsFlag(t *testing.T) {
	out, code := captureRun(t, []string{"-h"})
	if code != 0 {
		t.Fatalf("aaesverify -h exited %d:\n%s", code, out)
	}
	if strings.Contains(out, "--records") {
		t.Fatalf("slim verifier must not take --records:\n%s", out)
	}
}

func TestVerifyExportV1Fixture(t *testing.T) {
	export := filepath.Join(moduleDir(t), "testdata", "export_v1.jsonl")
	pub := filepath.Join(moduleDir(t), "testdata", "public_key.hex")
	out, code := captureRun(t, []string{"--export", export, "--pubkey", pub})
	if code != 0 {
		t.Fatalf("aaesverify fixture exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Fatalf("want PASS, got:\n%s", out)
	}
}

func captureRun(t *testing.T, args []string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	code := run(args)
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
