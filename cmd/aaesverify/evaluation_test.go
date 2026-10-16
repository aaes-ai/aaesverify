// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluationModeRefusesConflictingInputsAndMissingDisclosure(t *testing.T) {
	_, code := captureRun(t, []string{"--evaluation", "missing", "--export", "missing"})
	if code != 2 {
		t.Fatalf("conflicting modes: %d", code)
	}
	out, code := captureRun(t, []string{"--evaluation", t.TempDir(), "--json"})
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if code != 1 || result["ok"] != false || result["verdict"] != "FAIL" {
		t.Fatalf("missing evaluation: %d %s", code, out)
	}
}

func TestRecordsModeRequiresExportAndCannotBypassExportFailure(t *testing.T) {
	for _, args := range [][]string{{"--records", "missing"}, {"--evaluation", "missing", "--records", "missing"}} {
		_, code := captureRun(t, args)
		if code != 2 {
			t.Fatalf("conflict: %v: %d", args, code)
		}
	}
	// A readable but cryptographically invalid export must fail before binding.
	dir := t.TempDir()
	path := filepath.Join(dir, "export.jsonl")
	raw, err := os.ReadFile("testdata/sample-export.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"record_hash":"`), []byte(`"record_hash":"0`), 1)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"--export", path, "--records", "missing", "--json"})
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if code != 1 || result["ok"] != false || result["sealed_records_resealed"] == true || result["sealed_sidecar_binding_verified"] == true {
		t.Fatalf("invalid export accepted: %d %s", code, out)
	}
}
