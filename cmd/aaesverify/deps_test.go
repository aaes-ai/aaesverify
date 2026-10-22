package main

import (
	"os/exec"
	"path/filepath"
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
