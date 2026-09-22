package verifier

// The shredding report's semantics: protected fields and key-destruction
// records are a READING of intact evidence. They add warnings and counts; they
// never fail a chain, and an export with neither reads exactly as it always
// has.

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

// shreddedLog rewrites entries 1..nProtected of a three-entry fixture log to
// carry a marked ciphertext actor id and makes entry 3 the sealed
// key-destruction record, re-chaining and re-signing so every claim in the
// file is honest — the verifier under test must recompute all of it.
func shreddedLog(t *testing.T, nProtected int) string {
	t.Helper()
	entries, _, pub, _ := buildLog(t, 3)
	for i := 0; i < nProtected; i++ {
		entries[i].ActorID = ProtectedFieldMarker + "dGVzdC1jaXBoZXJ0ZXh0"
	}
	entries[2].Capability = KeyShredCapability
	rechain(t, entries)
	head := hash.TreeHead{
		LogID:    hash.DeriveLogID(entries[0].TenantID),
		Index:    entries[len(entries)-1].Sequence,
		TreeSize: uint64(len(entries)),
		SignedAt: entries[len(entries)-1].OccurredAt.Add(time.Hour),
	}
	leaves := make([]string, len(entries))
	for i, e := range entries {
		leaves[i] = e.Leaf
	}
	head.RootHash = hash.MerkleRoot(leaves)
	head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))
	path := filepath.Join(t.TempDir(), "export.jsonl")
	if err := os.WriteFile(path, []byte(exportJSONL(t, entries, head, pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// rechain recomputes every chain hash and leaf after a fixture edit, so the
// test exercises the verifier's own recomputation against honest claims.
func rechain(t *testing.T, entries []EntryView) {
	t.Helper()
	prev := ""
	for i := range entries {
		pre, err := entries[i].preimage()
		if err != nil {
			t.Fatalf("preimage %d: %v", i, err)
		}
		entries[i].ChainHash = hash.Chain(prev, pre)
		entries[i].Leaf = hash.SHA256Hex(pre)
		prev = entries[i].ChainHash
	}
}

func TestShreddedExportVerifiesAndReportsUnreadable(t *testing.T) {
	path := shreddedLog(t, 2)
	res, err := VerifyExport(path, nil)
	if err != nil {
		t.Fatalf("VerifyExport: %v", err)
	}
	if !res.OK || !res.ChainOK || !res.RootOK || !res.SignatureOK {
		t.Fatalf("a shredded export failed verification: ok=%v errors=%v", res.OK, res.Errors)
	}
	if res.ProtectedEntries != 2 {
		t.Fatalf("ProtectedEntries = %d, want 2", res.ProtectedEntries)
	}
	if len(res.ShredEvents) != 1 || res.ShredEvents[0].Sequence != 3 {
		t.Fatalf("ShredEvents = %+v", res.ShredEvents)
	}
	var sawProtected, sawUnreadable bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "enc:v1:") {
			sawProtected = true
		}
		if strings.Contains(w, "unreadable after shredding") {
			sawUnreadable = true
		}
	}
	if !sawProtected || !sawUnreadable {
		t.Fatalf("warnings = %v", res.Warnings)
	}
	if res.Gapped {
		t.Fatal("a shredded export is complete, not gapped: nothing is missing, fields are unreadable")
	}
}

func TestUnprotectedExportReportsNoShredding(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	path := filepath.Join(t.TempDir(), "export.jsonl")
	if err := os.WriteFile(path, []byte(exportJSONL(t, entries, head, pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyExport(path, nil)
	if err != nil {
		t.Fatalf("VerifyExport: %v", err)
	}
	if !res.OK {
		t.Fatalf("plain export failed: %v", res.Errors)
	}
	if res.ProtectedEntries != 0 || len(res.ShredEvents) != 0 {
		t.Fatalf("plain export reported shredding: %+v", res)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "enc:v1:") || strings.Contains(w, "shredding") {
			t.Fatalf("plain export carries a shredding warning: %q", w)
		}
	}
}

func TestTamperedProtectedFieldFailsTheChain(t *testing.T) {
	path := shreddedLog(t, 2)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one character inside the first ciphertext: the leaf over the
	// preimage no longer matches, and that is a chain failure — the same
	// tamper evidence as on any other field.
	i := strings.Index(string(raw), ProtectedFieldMarker)
	if i < 0 {
		t.Fatal("no protected field in the fixture")
	}
	b := []byte(string(raw))
	at := i + len(ProtectedFieldMarker) + 3
	if b[at] == 'A' {
		b[at] = 'B'
	} else {
		b[at] = 'A'
	}
	tampered := filepath.Join(t.TempDir(), "tampered.jsonl")
	if err := os.WriteFile(tampered, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyExport(tampered, nil)
	if err != nil {
		t.Fatalf("VerifyExport: %v", err)
	}
	if res.OK || res.ChainOK {
		t.Fatalf("a tampered ciphertext verified: %+v", res)
	}
}
