package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTrustFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --keyring and --expected-final are the v4 trust inputs. They are loaded
// strictly, refused with --receipt, and a v4 freshness pin on a v2/v3 export
// is a downgrade refusal rather than a silently ignored flag.
func TestRunV4TrustFlags(t *testing.T) {
	keyring := writeTrustFile(t, "keyring.json", `{"ledger-k1":"`+fixturePubKeyHex(t)+`"}`)
	pin := writeTrustFile(t, "final.json", `{"log_id":"l","index":1,"root_hash":"aa","tree_size":1}`)
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"unreadable keyring", []string{"--export", fixtureExport(t), "--keyring", filepath.Join(t.TempDir(), "missing.json")}, 2, "read keyring"},
		{"empty keyring", []string{"--export", fixtureExport(t), "--keyring", writeTrustFile(t, "empty.json", `{}`)}, 2, "names no keys"},
		{"repeated keyring id", []string{"--export", fixtureExport(t), "--keyring", writeTrustFile(t, "dup.json", `{"k":"`+fixturePubKeyHex(t)+`","k":"`+fixturePubKeyHex(t)+`"}`)}, 2, "duplicate object key"},
		{"incomplete pin", []string{"--export", fixtureExport(t), "--expected-final", writeTrustFile(t, "short.json", `{"log_id":"l"}`)}, 2, "lacks"},
		{"keyring with receipt", []string{"--receipt", "r.json", "--pubkey", fixturePubKeyPath(t), "--keyring", keyring}, 2, "apply only to --export"},
		{"pin on a v2 export", []string{"--export", fixtureExport(t), "--pubkey", fixturePubKeyPath(t), "--expected-final", pin}, 1, "v4 freshness modes require"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := captureRun(t, tc.args)
			if code != tc.code || !strings.Contains(out, tc.want) {
				t.Fatalf("exited %d, want %d with %q:\n%s", code, tc.code, tc.want, out)
			}
		})
	}
	out, code := captureRun(t, []string{"-h"})
	if code != 0 || !strings.Contains(out, "-keyring") || !strings.Contains(out, "-expected-final") {
		t.Fatalf("help lacks the v4 trust flags (%d):\n%s", code, out)
	}
}
