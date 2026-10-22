package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunExportWithAMalformedBodyLineFails: the header normalizes, so the
// file is read as an export, but a body line without a type discriminator
// fails the load. The failure is printed as a result and exits 1.
func TestRunExportWithAMalformedBodyLineFails(t *testing.T) {
	raw, err := os.ReadFile(fixtureExport(t))
	if err != nil {
		t.Fatal(err)
	}
	header, _, ok := strings.Cut(string(raw), "\n")
	if !ok {
		t.Fatal("fixture has no body")
	}
	broken := filepath.Join(t.TempDir(), "broken.jsonl")
	if err := os.WriteFile(broken, []byte(header+"\n{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"--export", broken, "--pubkey", fixturePubKeyPath(t)})
	if code != 1 {
		t.Fatalf("malformed body exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, `"ok": false`) || !strings.Contains(out, "missing type discriminator") {
		t.Fatalf("the load failure was not reported:\n%s", out)
	}
}
