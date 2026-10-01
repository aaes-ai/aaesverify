package verifier

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// TestPreimageGoldenMatchesOpenVerifier recomputes every committed golden
// entry with this (open) verifier and refuses a one-byte drift in the sealed
// preimage layout.
func TestPreimageGoldenMatchesOpenVerifier(t *testing.T) {
	path := filepath.Join("testdata", "preimage-golden.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	var names []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var g struct {
			Name      string          `json:"name"`
			Schema    string          `json:"schema"`
			Leaf      string          `json:"leaf"`
			ChainHash string          `json:"chain_hash"`
			Entry     json.RawMessage `json:"entry"`
		}
		if err := json.Unmarshal([]byte(line), &g); err != nil {
			t.Fatalf("golden line: %v", err)
		}
		names = append(names, g.Name)
		header := map[string]any{
			"type":        "header",
			"schema":      g.Schema,
			"log_id":      "golden-log",
			"tenant_id":   "tenant-golden",
			"exported_at": "2026-09-28T13:00:00Z",
			"entry_count": 1,
			"pre_anchor":  true,
		}
		hb, err := json.Marshal(header)
		if err != nil {
			t.Fatal(err)
		}
		doc := string(hb) + "\n" + string(g.Entry) + "\n"
		exp, err := LoadExportReader(strings.NewReader(doc))
		if err != nil {
			t.Fatalf("%s: load: %v", g.Name, err)
		}
		if len(exp.Entries) != 1 {
			t.Fatalf("%s: want 1 entry, got %d", g.Name, len(exp.Entries))
		}
		e := exp.Entries[0]
		pre, err := e.preimage()
		if err != nil {
			t.Fatalf("%s: preimage: %v", g.Name, err)
		}
		leaf := hash.SHA256Hex(pre)
		chain := hash.Chain("", pre)
		if leaf != g.Leaf {
			t.Fatalf("%s: leaf drifted: open=%s golden=%s", g.Name, leaf, g.Leaf)
		}
		if chain != g.ChainHash {
			t.Fatalf("%s: chain_hash drifted: open=%s golden=%s", g.Name, chain, g.ChainHash)
		}
		recomputed, err := e.RecomputeLeaf()
		if err != nil {
			t.Fatalf("%s: RecomputeLeaf: %v", g.Name, err)
		}
		if recomputed != g.Leaf {
			t.Fatalf("%s: RecomputeLeaf drifted: %s vs %s", g.Name, recomputed, g.Leaf)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"v2-zero-amount", "v2-eur", "v2-jpy", "v2-tombstone",
	} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("golden missing branch %s", want)
		}
	}
}
