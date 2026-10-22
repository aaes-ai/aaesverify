package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

func validTrustReceipt(t *testing.T) (TrustReceipt, ed25519.PublicKey) {
	t.Helper()
	entries, head, pub, leaves := buildLog(t, 11)
	proof, err := hash.ProveInclusion(leaves, 6)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[6]
	return TrustReceipt{
		Schema: TrustReceiptSchema,
		Entry:  &entry,
		Leaf:   entry.Leaf,
		Proof:  &proof,
		Head:   &head,
		Claims: FixedTrustReceiptClaims(),
	}, pub
}

func TestVerifyTrustReceiptAcceptsDecisionReceipt(t *testing.T) {
	r, pub := validTrustReceipt(t)
	raw, err := r.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyTrustReceipt(raw, pub)
	if err != nil {
		t.Fatalf("VerifyTrustReceipt: %v", err)
	}
	if got.Entry.Sequence != r.Entry.Sequence || got.Claims.Proves != trustReceiptProves {
		t.Fatalf("verified receipt changed: %+v", got)
	}
}

func TestVerifyTrustReceiptRejectsAdversarialDocuments(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*TrustReceipt)
		key      int
		want     error
		contains string
	}{
		{name: "schema", mutate: func(r *TrustReceipt) { r.Schema = "aaes.trust-receipt/v2" }, want: ErrReceipt, contains: "schema"},
		{name: "missing entry", mutate: func(r *TrustReceipt) { r.Entry = nil }, want: ErrReceipt, contains: "no decision entry"},
		{name: "missing head", mutate: func(r *TrustReceipt) { r.Head = nil }, want: ErrReceipt, contains: "no signed tree head"},
		{name: "missing proof", mutate: func(r *TrustReceipt) { r.Proof = nil }, want: ErrReceipt, contains: "no inclusion proof"},
		{name: "missing leaf", mutate: func(r *TrustReceipt) { r.Leaf = "" }, want: ErrReceipt, contains: "no leaf attached"},
		{name: "missing claims", mutate: func(r *TrustReceipt) { r.Claims = TrustReceiptClaims{} }, want: ErrReceipt, contains: "fixed decision-only"},
		{name: "altered proves text", mutate: func(r *TrustReceipt) { r.Claims.Proves += " and execution" }, want: ErrReceipt, contains: "fixed decision-only"},
		{name: "altered limits text", mutate: func(r *TrustReceipt) { r.Claims.DoesNotProve[0] = "nothing" }, want: ErrReceipt, contains: "fixed decision-only"},
		{name: "tenant", mutate: func(r *TrustReceipt) { r.Entry.TenantID = "other" }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "sequence", mutate: func(r *TrustReceipt) { r.Entry.Sequence++ }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "record hash", mutate: func(r *TrustReceipt) { r.Entry.RecordHash = "forged" }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "intent", mutate: func(r *TrustReceipt) { r.Entry.IntentID = "forged" }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "actor", mutate: func(r *TrustReceipt) { r.Entry.ActorID = "forged" }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "capability", mutate: func(r *TrustReceipt) { r.Entry.Capability = "forged" }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "tier", mutate: func(r *TrustReceipt) { r.Entry.Tier = types.R4RiskTier }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "allowed", mutate: func(r *TrustReceipt) { r.Entry.Allowed = !r.Entry.Allowed }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "grant", mutate: func(r *TrustReceipt) { r.Entry.GrantID = "forged" }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "amount minor", mutate: func(r *TrustReceipt) { r.Entry.AmountMinor++ }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "amount currency", mutate: func(r *TrustReceipt) { r.Entry.AmountCurrency = "EUR" }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "occurred at", mutate: func(r *TrustReceipt) { r.Entry.OccurredAt = r.Entry.OccurredAt.Add(time.Second) }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "linked at", mutate: func(r *TrustReceipt) { r.Entry.LinkedAt = r.Entry.LinkedAt.Add(time.Second) }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "tombstone", mutate: func(r *TrustReceipt) { r.Entry.Tombstone = &TombstoneView{FromSequence: 1, ToSequence: 1} }, want: ErrReceipt, contains: "tombstone entries are not decision receipts"},
		{name: "leaf", mutate: func(r *TrustReceipt) { r.Leaf = hash.SHA256Hex([]byte("forged")) }, want: ErrReceipt, contains: "recomputed from the entry"},
		{name: "entry leaf claim", mutate: func(r *TrustReceipt) { r.Entry.Leaf = hash.SHA256Hex([]byte("forged")) }, want: ErrReceipt, contains: "entry leaf"},
		{name: "proof sibling", mutate: func(r *TrustReceipt) { r.Proof.Siblings[0] = hash.SHA256Hex([]byte("forged")) }, want: ErrInclusion},
		{name: "proof index", mutate: func(r *TrustReceipt) { r.Proof.Index++ }, want: ErrInclusion},
		{name: "wrong key", key: 1, want: ErrSignature},
		{name: "no key", key: 2, want: ErrNoPublicKey},
		{name: "stripped signature", mutate: func(r *TrustReceipt) { r.Head.Signature = nil }, want: ErrSignature},
		{name: "unknown head algorithm", mutate: func(r *TrustReceipt) {
			r.Head.Algorithm = "rsa"
			r.Head.Signature = ed25519.Sign(testPriv(), HeadPayload(*r.Head))
		}, want: ErrSignature, contains: "algorithm"},
		{name: "head of another log", mutate: func(r *TrustReceipt) {
			r.Head.LogID = hash.DeriveLogID("other-tenant")
			r.Head.Signature = ed25519.Sign(testPriv(), HeadPayload(*r.Head))
		}, want: ErrLogIDMismatch},
		{name: "proof larger than head", mutate: func(r *TrustReceipt) { r.Proof.TreeSize = r.Head.TreeSize + 1 }, want: ErrReceipt, contains: "proof covers"},
		{name: "valid proof for another root", mutate: func(r *TrustReceipt) {
			r.Proof.RootHash = hash.SHA256Hex([]byte("other-root"))
		}, want: ErrReceipt, contains: "proof root"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, pub := validTrustReceipt(t)
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			key := []byte(pub)
			switch tc.key {
			case 1:
				seed := make([]byte, ed25519.SeedSize)
				for i := range seed {
					seed[i] = 99
				}
				key = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			case 2:
				key = nil
			}
			raw, err := r.MarshalIndent()
			if err != nil {
				t.Fatal(err)
			}
			_, err = VerifyTrustReceipt(raw, key)
			if err == nil {
				t.Fatal("adversarial receipt verified")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if tc.contains != "" && !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error = %v, want substring %q", err, tc.contains)
			}
		})
	}
}

func TestVerifyTrustReceiptStrictDecoding(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value any
		entry bool
	}{
		{name: "class", key: "class", value: "executed"},
		{name: "effect", key: "effect", value: "executed"},
		{name: "nested outcome", key: "class", value: "executed", entry: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, pub := validTrustReceipt(t)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			target := doc
			if tc.entry {
				target = doc["entry"].(map[string]any)
			}
			target[tc.key] = tc.value
			raw, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyTrustReceipt(raw, pub); !errors.Is(err, ErrReceipt) || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("unknown field accepted or misreported: %v", err)
			}
		})
	}
}

func TestVerifyTrustReceiptRefusesRealTombstoneEntry(t *testing.T) {
	entries, head, pub := buildGappedLog(t, []uint64{7, 8, 9, 10, 11}, retentionTombstone())
	leaves := make([]string, len(entries))
	for i := range entries {
		leaves[i] = entries[i].Leaf
	}
	proof, err := hash.ProveInclusion(leaves, uint64(len(entries)-1))
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[len(entries)-1]
	if entry.Tombstone == nil {
		t.Fatal("fixture did not end in a tombstone")
	}
	r := TrustReceipt{
		Schema: TrustReceiptSchema,
		Entry:  &entry,
		Leaf:   entry.Leaf,
		Proof:  &proof,
		Head:   &head,
		Claims: FixedTrustReceiptClaims(),
	}
	raw, err := r.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyTrustReceipt(raw, pub)
	if !errors.Is(err, ErrReceipt) || !strings.Contains(err.Error(), "tombstone entries are not decision receipts") {
		t.Fatalf("tombstone decision receipt: %v", err)
	}
}

func TestVerifyTrustReceiptRefusesTrailingDocuments(t *testing.T) {
	r, pub := validTrustReceipt(t)
	raw, err := r.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTrustReceipt(append(raw, []byte(`{}`)...), pub); !errors.Is(err, ErrReceipt) || !strings.Contains(err.Error(), "multiple JSON documents") {
		t.Fatalf("second document: %v", err)
	}
	if _, err := VerifyTrustReceipt(append(raw, []byte(`garbage`)...), pub); !errors.Is(err, ErrReceipt) || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("trailing data: %v", err)
	}
}

func TestVerifyTrustReceiptRejectsDuplicateKeys(t *testing.T) {
	r, pub := validTrustReceipt(t)
	r.Anchor = &AnchorView{Head: *r.Head, Witnesses: []WitnessView{{WitnessID: "witness-1"}}}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	targets := []struct {
		name        string
		key         string
		escaped     string
		folded      string
		conflicting string
		identical   string
	}{
		{name: "top level schema", key: "schema", escaped: `sch\u0065ma`, folded: "Schema", conflicting: "aaes.trust-receipt/v2", identical: TrustReceiptSchema},
		{name: "entry", key: "tenant_id", escaped: `tenant\u005fid`, folded: "Tenant_ID", conflicting: "other", identical: r.Entry.TenantID},
		{name: "head", key: "log_id", escaped: `log\u005fid`, folded: "Log_Id", conflicting: "other", identical: r.Head.LogID},
		{name: "proof", key: "root_hash", escaped: `root\u005fhash`, folded: "Root_Hash", conflicting: "other", identical: r.Proof.RootHash},
		{name: "claims", key: "proves", escaped: `pro\u0076es`, folded: "Proves", conflicting: "execution", identical: trustReceiptProves},
		{name: "witness in array", key: "witness_id", escaped: `witness\u005fid`, folded: "Witness_ID", conflicting: "other", identical: "witness-1"},
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			tests := []struct {
				name     string
				spelling string
				value    string
				reported string
			}{
				{name: "conflicting", spelling: target.key, value: target.conflicting, reported: target.key},
				{name: "identical", spelling: target.key, value: target.identical, reported: target.key},
				{name: "conflicting escaped", spelling: target.escaped, value: target.conflicting, reported: target.key},
				{name: "identical escaped", spelling: target.escaped, value: target.identical, reported: target.key},
				{name: "conflicting fold", spelling: target.folded, value: target.conflicting, reported: target.folded},
				{name: "identical fold", spelling: target.folded, value: target.identical, reported: target.folded},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					duplicate := duplicateReceiptMember(t, raw, target.key, tc.spelling, tc.value)
					_, err := VerifyTrustReceipt(duplicate, pub)
					want := `duplicate object key "` + tc.reported + `"`
					if !errors.Is(err, ErrReceipt) || !strings.Contains(err.Error(), want) {
						t.Fatalf("duplicate accepted or misreported: %v, want substring %q", err, want)
					}
				})
			}
		})
	}
}

func duplicateReceiptMember(t *testing.T, raw []byte, key, spelling, value string) []byte {
	t.Helper()
	marker := `"` + key + `":`
	if !strings.Contains(string(raw), marker) {
		t.Fatalf("receipt does not contain member %q", marker)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := marker + string(encoded) + `,"` + spelling + `":`
	return []byte(strings.Replace(string(raw), marker, duplicate, 1))
}

func TestTrustReceiptEntryHashDoesNotFoldNonASCIIValues(t *testing.T) {
	// Entry canonicalization preserves string values; only object keys are folded.
	r, _ := validTrustReceipt(t)
	tests := []struct {
		name  string
		first string
		other string
	}{
		{name: "Kelvin sign then k", first: "\u212a", other: "k"},
		{name: "k then Kelvin sign", first: "k", other: "\u212a"},
		{name: "long s then s", first: "\u017f", other: "s"},
		{name: "s then long s", first: "s", other: "\u017f"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafForIntent := func(intent string) string {
				entry := *r.Entry
				entry.IntentID = intent
				leaf, err := entry.RecomputeLeaf()
				if err != nil {
					t.Fatal(err)
				}
				return leaf
			}
			firstLeaf := leafForIntent(tc.first)
			otherLeaf := leafForIntent(tc.other)
			if firstLeaf == otherLeaf {
				t.Fatalf("entry intents %q and %q hashed identically: %s", tc.first, tc.other, firstLeaf)
			}
		})
	}
}

func TestFoldJSONKeyNonASCIIPairs(t *testing.T) {
	tests := []struct {
		name  string
		first string
		other string
	}{
		{name: "Kelvin sign then k", first: "\u212a", other: "k"},
		{name: "k then Kelvin sign", first: "k", other: "\u212a"},
		{name: "long s then s", first: "\u017f", other: "s"},
		{name: "s then long s", first: "s", other: "\u017f"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if first, other := foldJSONKey(tc.first), foldJSONKey(tc.other); first != other {
				t.Fatalf("foldJSONKey(%q) = %q, foldJSONKey(%q) = %q", tc.first, first, tc.other, other)
			}
		})
	}
}
