package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Check the current wire shape through the CLI boundary: passing a clean
// file must not also permit modified fields, a wrong key or unsupported trust.
func TestCLIReleaseCompatibilityRefusals(t *testing.T) {
	for _, schema := range []string{"v2"} {
		t.Run(schema, func(t *testing.T) {
			path := filepath.Join(moduleDir(t), "testdata", "export_"+schema+".jsonl")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			base := []string{"--export", path, "--pubkey", fixturePubKeyPath(t), "--allow-pre-anchor", "--json"}
			if out, code := captureRun(t, base); code != 0 || !strings.Contains(out, `"ok": true`) {
				t.Fatalf("clean %s: %d %s", schema, code, out)
			}
			cases := map[string]string{
				"retired-schema":     strings.Replace(string(raw), "aaes.export/"+schema, "aaes.export/v1", 1),
				"unsupported-schema": strings.Replace(string(raw), "aaes.export/"+schema, "aaes.export/v999", 1),
				"changed-actor":      strings.Replace(string(raw), `"actor_id":"`, `"actor_id":"modified-`, 1),
			}
			for name, altered := range cases {
				if altered == string(raw) {
					t.Fatalf("mutation %s did not change fixture", name)
				}
				mutated := filepath.Join(t.TempDir(), name+".jsonl")
				if err := os.WriteFile(mutated, []byte(altered), 0600); err != nil {
					t.Fatal(err)
				}
				args := append([]string(nil), base...)
				args[1] = mutated
				if out, code := captureRun(t, args); code != 1 || !strings.Contains(out, `"ok": false`) {
					t.Fatalf("%s accepted: %d %s", name, code, out)
				}
			}
			wrong := filepath.Join(t.TempDir(), "wrong-key.hex")
			if err := os.WriteFile(wrong, []byte(strings.Repeat("00", 32)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			args := append([]string(nil), base...)
			args[3] = wrong
			if out, code := captureRun(t, args); code != 1 || !strings.Contains(out, `"signature_ok": false`) {
				t.Fatalf("wrong key: %d %s", code, out)
			}
			if out, code := captureRun(t, append(base, "--require-independent")); code != 1 || !strings.Contains(out, `"ok": false`) {
				t.Fatalf("unsupported independence: %d %s", code, out)
			}
		})
	}
}

func TestPublicSampleCompatibility(t *testing.T) {
	path := filepath.Join(moduleDir(t), "testdata", "sample-export.jsonl")
	key := filepath.Join(moduleDir(t), "testdata", "sample-pubkey.txt")
	out, code := captureRun(t, []string{"--export", path, "--pubkey", key, "--json"})
	if code != 0 || !strings.Contains(out, `"entry_count": 16`) {
		t.Fatalf("public sample: %d %s", code, out)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{"aaes.export/v0", "aaes.export/v1"} {
		retired := filepath.Join(t.TempDir(), "retired.jsonl")
		if err := os.WriteFile(retired, []byte(strings.Replace(string(raw), "aaes.export/v2", schema, 1)), 0600); err != nil {
			t.Fatal(err)
		}
		out, code := captureRun(t, []string{"--export", retired, "--pubkey", key, "--json"})
		if code != 1 || !strings.Contains(out, "unsupported export schema") {
			t.Fatalf("retired %s: %d %s", schema, code, out)
		}
	}
}
