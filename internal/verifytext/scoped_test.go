package verifytext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// The human headline is the verifier's scoped v4 verdict, never the bare
// CONSISTENT/PASS headline the JSON contradicts.
func TestRenderShowsTheScopedVerdict(t *testing.T) {
	for _, tc := range []struct{ verdict, want, never string }{
		{verifier.VerdictUnpinnedV4, "UNPINNED_CONSISTENCY (no freshness pin", "CONSISTENT\n"},
		{verifier.VerdictContinuityV4, "CONTINUITY_FROM_CUTOVER (continuity", "PASS"},
		{verifier.VerdictFloorV4, "TREE_SIZE_FLOOR_SATISFIED (tree-size floor only", "PASS"},
		{"PASS", "result:                PASS", "CONSISTENT"},
	} {
		res := &verifier.Result{OK: true, Verdict: tc.verdict, KeySource: "keyring", IndependentWitnesses: 1}
		got := Render(res) + "\n"
		if !strings.Contains(got, tc.want) || strings.Contains(got, "result:                "+tc.never) {
			t.Fatalf("%s rendered as:\n%s", tc.verdict, got)
		}
		if !strings.Contains(got, "caller-pinned key or keyring") {
			t.Fatalf("keyring key source not described:\n%s", got)
		}
	}
}

func TestLoadKeyringAndHeadPin(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// Any 32-byte hex key will do; built at run time so no literal reads as a credential.
	key := strings.Repeat("0123456789abcdef", 4)
	ring, err := LoadKeyring(write("ring.json", `{"ledger-k1":"`+key+`"}`))
	if err != nil || len(ring["ledger-k1"]) != 32 {
		t.Fatalf("keyring: %v %v", ring, err)
	}
	if ring, err := LoadKeyring(""); ring != nil || err != nil {
		t.Fatalf("empty keyring path: %v %v", ring, err)
	}
	for body, want := range map[string]string{
		`{}`:                                    "names no keys",
		`["x"]`:                                 "JSON object",
		`{" k ":"` + key + `"}`:                 "empty or padded",
		`{"k":"nope"}`:                          `keyring key "k"`,
		`{"k":"` + key + `","k":"` + key + `"}`: "duplicate object key",
	} {
		if _, err := LoadKeyring(write("bad.json", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", body, err, want)
		}
	}
	if _, err := LoadKeyring(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "read keyring") {
		t.Fatalf("missing keyring: %v", err)
	}
	pin, err := LoadHeadPin(write("pin.json", `{"log_id":"l","index":2,"root_hash":"aa","tree_size":4}`))
	if err != nil || *pin != (verifier.HeadPin{LogID: "l", Index: 2, RootHash: "aa", TreeSize: 4}) {
		t.Fatalf("pin: %+v %v", pin, err)
	}
	if pin, err := LoadHeadPin(""); pin != nil || err != nil {
		t.Fatalf("empty pin path: %v %v", pin, err)
	}
	for body, want := range map[string]string{
		`{"log_id":"l","index":2,"root_hash":"aa"}`:                             `lacks "tree_size"`,
		`{"log_id":"l","index":2,"root_hash":"aa","tree_size":4,"extra":1}`:     "unknown field",
		`{"log_id":"l","index":2,"root_hash":"aa","tree_size":4,"Tree_Size":5}`: "duplicate object key",
		`{"log_id":"","index":2,"root_hash":"aa","tree_size":4}`:                "needs a log_id",
		`[]`: "JSON object",
	} {
		if _, err := LoadHeadPin(write("bad-pin.json", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", body, err, want)
		}
	}
	if _, err := LoadHeadPin(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "read expected final head") {
		t.Fatalf("missing pin: %v", err)
	}
}
