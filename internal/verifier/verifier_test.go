package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aaes-dev/aaesverify/internal/hash"
	"github.com/aaes-dev/aaesverify/internal/types"
)

// testPriv returns the fixed key the fixtures are signed with.
func testPriv() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testPub() ed25519.PublicKey { return testPriv().Public().(ed25519.PublicKey) }

// buildLog builds a chain the way the producer claims to: canonical entry
// bytes, chained, hashed into leaves, committed to by a signed head. It is an
// independent reimplementation on purpose.
func buildLog(t *testing.T, n int) (entries []EntryView, head hash.TreeHead, pub ed25519.PublicKey, leaves []string) {
	t.Helper()
	base := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	const tenant = "tenant-a"
	prev := ""
	leaves = make([]string, 0, n)
	for i := 1; i <= n; i++ {
		e := EntryView{
			TenantID:   tenant,
			Sequence:   uint64(i),
			RecordHash: fmt.Sprintf("record-%d", i),
			IntentID:   fmt.Sprintf("intent-%d", i),
			ActorID:    "agent-1",
			Capability: "payments.transfer",
			Tier:       types.R3RiskTier,
			Allowed:    true,
			GrantID:    fmt.Sprintf("grant-%d", i),
			AmountUSD:  float64(i) * 3.25,
			OccurredAt: base.Add(time.Duration(i) * time.Second),
			LinkedAt:   base.Add(time.Duration(i) * time.Second),
		}
		pre, err := e.preimage()
		if err != nil {
			t.Fatalf("preimage %d: %v", i, err)
		}
		chain := hash.Chain(prev, pre)
		leaf := hash.SHA256Hex(pre)
		e.ChainHash = chain
		e.Leaf = leaf
		prev = chain
		entries = append(entries, e)
		leaves = append(leaves, leaf)
	}
	// The head names the log it commits to via the tenant-derived id, exactly
	// as the producer stamps it, so fixtures verify under the log-id rule.
	head = hash.TreeHead{LogID: hash.DeriveLogID(tenant), Index: uint64(n), RootHash: hash.MerkleRoot(leaves), TreeSize: uint64(n), SignedAt: base.Add(time.Hour)}
	head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))
	return entries, head, testPub(), leaves
}

func TestVerifyChainAcceptsAWellFormedLog(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 17)
	if err := VerifyChain(entries, head, pub); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if err := VerifyChain(entries, head, nil); !errors.Is(err, ErrNoPublicKey) {
		t.Fatalf("no public key: got %v", err)
	}
	if err := VerifyChain(nil, head, pub); !errors.Is(err, ErrEmptyLog) {
		t.Fatalf("empty log: got %v", err)
	}
}

func TestVerifyChainRejectsEveryTamper(t *testing.T) {
	base, baseHead, pub, _ := buildLog(t, 9)

	type mutate func([]EntryView, hash.TreeHead) ([]EntryView, hash.TreeHead)
	cases := []struct {
		name   string
		mutate mutate
		want   error
	}{
		{"amount changed", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			e[4].AmountUSD += 0.01
			return e, h
		}, ErrChain},
		{"record hash changed", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			e[2].RecordHash = "forged"
			return e, h
		}, ErrChain},
		{"allowed flag flipped", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			e[0].Allowed = false
			return e, h
		}, ErrChain},
		{"actor changed", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			e[7].ActorID = "someone-else"
			return e, h
		}, ErrChain},
		{"entry dropped", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			return append(e[:3], e[4:]...), h
		}, ErrChain},
		{"entries reordered", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			e[1], e[2] = e[2], e[1]
			return e, h
		}, ErrChain},
		{"chain hash edited", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			e[5].ChainHash = hash.SHA256Hex([]byte("forged-chain"))
			return e, h
		}, ErrChain},
		{"leaf edited", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			e[5].Leaf = hash.SHA256Hex([]byte("forged-leaf"))
			return e, h
		}, ErrChain},
		{"head root edited", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			h.RootHash = hash.SHA256Hex([]byte("forged-root"))
			return e, h
		}, ErrRoot},
		{"head size edited", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			h.TreeSize++
			return e, h
		}, ErrRoot},
		{"head signature stripped", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			h.Signature = nil
			return e, h
		}, ErrSignature},
		{"head signature forged", func(e []EntryView, h hash.TreeHead) ([]EntryView, hash.TreeHead) {
			sig := append([]byte(nil), h.Signature...)
			sig[0] ^= 0xff
			h.Signature = sig
			return e, h
		}, ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, head := tc.mutate(append([]EntryView(nil), base...), baseHead)
			if err := VerifyChain(entries, head, pub); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyReceiptRequiresItsEvidence(t *testing.T) {
	entries, head, pub, leaves := buildLog(t, 11)
	proof, err := hash.ProveInclusion(leaves, 6)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[6]
	r := ReceiptView{
		ReceiptID:  "receipt-9",
		IntentID:   entry.IntentID,
		TenantID:   entry.TenantID,
		GrantID:    entry.GrantID,
		EffectID:   "effect-9",
		Effect:     "payments.transfer",
		RecordHash: entry.RecordHash,
		IssuedAt:   entry.OccurredAt,
		Entry:      &entry,
		Leaf:       entry.Leaf,
		Proof:      &proof,
		Head:       &head,
	}
	if err := VerifyReceipt(r, pub); err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}

	noHead := r
	noHead.Head = nil
	if err := VerifyReceipt(noHead, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("missing head: got %v", err)
	}
	noProof := r
	noProof.Proof = nil
	if err := VerifyReceipt(noProof, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("missing proof: got %v", err)
	}
	otherProof, err := hash.ProveInclusion(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}
	wrongIndex := r
	wrongIndex.Proof = &otherProof
	if err := VerifyReceipt(wrongIndex, pub); !errors.Is(err, ErrInclusion) {
		t.Fatalf("proof for another index: got %v", err)
	}
	// A head signed before the receipt was issued, correctly signed with the
	// same key, must still fail: the log did not yet commit to the entry.
	lateHead := head
	lateHead.SignedAt = entry.OccurredAt.Add(-time.Hour)
	lateHead.Signature = nil
	lateHead.Signature = ed25519.Sign(testPriv(), HeadPayload(lateHead))
	late := r
	late.Head = &lateHead
	if err := VerifyReceipt(late, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("head signed before issuance: got %v", err)
	}
	// A signature by another key must fail even if everything else agrees.
	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = 99
	}
	otherPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	if err := VerifyReceipt(r, otherPub); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: got %v", err)
	}
}

func TestParseKeys(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if got, err := ParsePublicKey(hex.EncodeToString(pub)); err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("hex public key: %v %v", got, err)
	}
	if got, err := ParseSeed(hex.EncodeToString(seed)); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("hex seed: %v %v", got, err)
	}
	if _, err := ParsePublicKey("not-a-key"); err == nil {
		t.Fatal("garbage public key accepted")
	}
	if _, err := ParseSeed("abcd"); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestVerifyExportReadsTheDocumentedSchema(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 6)
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatalf("VerifyExportReader: %v", err)
	}
	if !res.OK {
		t.Fatalf("export did not verify: %v", res.Errors)
	}
	if res.EntryCount != 6 || !res.ChainOK || !res.SignatureOK {
		t.Fatalf("result: %+v", res)
	}

	tampered := strings.Replace(doc, "\"amount_usd\":19.5", "\"amount_usd\":99.5", 1)
	if tampered == doc {
		t.Fatal("test fixture did not contain the expected amount")
	}
	res, err = VerifyExportReader(strings.NewReader(tampered), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("tampered export verified")
	}
	if res.ChainOK && res.RootOK {
		t.Fatalf("tampered export reported no failing check: %+v", res)
	}
}

func TestLoadExportRejectsMalformedInput(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	good := exportJSONL(t, entries, head, pub)
	lines := strings.Split(strings.TrimRight(good, "\n"), "\n")
	header := lines[0]
	entryLines := lines[1:]

	cases := map[string]string{
		"garbage":          "this is not json\n",
		"no header":        strings.Join(entryLines, "\n") + "\n",
		"duplicate header": header + "\n" + header + "\n",
		"unknown type":     header + "\n" + strings.Replace(entryLines[0], "\"type\":\"entry\"", "\"type\":\"mystery\"", 1) + "\n",
		"missing type":     header + "\n" + strings.Replace(entryLines[0], "\"type\":\"entry\"", "", 1) + "\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := VerifyExportReader(strings.NewReader(doc), pub)
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			if res.OK {
				t.Fatalf("malformed export verified: %s", doc)
			}
			if len(res.Errors) == 0 {
				t.Fatal("no error reported")
			}
		})
	}
}

func TestEmbeddedKeyMismatchIsAnError(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONL(t, entries, head, pub)
	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = 42
	}
	other := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	res, err := VerifyExportReader(strings.NewReader(doc), other)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("mismatched key verified")
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "signed by") {
		t.Fatalf("expected a key-mismatch error, got %v", res.Errors)
	}
}

// exportJSONL renders the documented aaes.export/v1 document from in-memory
// values, independently of the producer.
func exportJSONL(t *testing.T, entries []EntryView, head hash.TreeHead, pub ed25519.PublicKey) string {
	t.Helper()
	var b strings.Builder
	header := map[string]any{
		"type":        "header",
		"schema":      ExportSchema,
		"log_id":      "test-log",
		"tenant_id":   entries[0].TenantID,
		"exported_at": head.SignedAt,
		"entry_count": len(entries),
		"head":        head,
		"public_key":  hex.EncodeToString(pub),
		"pre_anchor":  true,
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	b.Write(hb)
	b.WriteByte('\n')
	for _, e := range entries {
		line := map[string]any{"type": "entry", "chain_hash": e.ChainHash, "leaf": e.Leaf}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		for k, v := range m {
			if _, taken := line[k]; !taken {
				line[k] = v
			}
		}
		lb, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(lb)
		b.WriteByte('\n')
	}
	return b.String()
}
