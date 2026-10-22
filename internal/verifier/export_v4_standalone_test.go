package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// Standalone proof bundles (design sections 4.9 and 9.4): the receipt bundle
// verifies leaf AND parent proofs against one pinned head; approval and
// summary standalone results are inclusion-only and never upgrade to
// history/ancestry/profile verdicts.

// buildReceiptBundleV4 assembles the positive-control bundle from a built
// export: entry 2 is the receipt's parent.
func buildReceiptBundleV4(t *testing.T) (ReceiptBundleV1, *v4Built) {
	t.Helper()
	doc := newV4Builder(t).build()
	exp, err := LoadExportReader(strings.NewReader(doc.text))
	if err != nil {
		t.Fatal(err)
	}
	parentProof, err := hash.ProveInclusion(doc.leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	receiptProof, err := hash.ProveInclusion(doc.leaves, 2)
	if err != nil {
		t.Fatal(err)
	}
	b := ReceiptBundleV1{
		Schema:       ReceiptBundleSchemaV1,
		KeyID:        doc.signing.id,
		Head:         doc.head,
		ParentLeaf:   exp.Entries[1],
		ParentProof:  parentProof,
		ReceiptLeaf:  exp.Receipts[0],
		ReceiptProof: receiptProof,
	}
	return b, doc
}

// resignBundleAfterReceiptMutation rebuilds both inclusion proofs and the
// head signature after the receipt leaf changes, so a later refusal is the
// parent-binding check rather than a stale proof.
func resignBundleAfterReceiptMutation(t *testing.T, b *ReceiptBundleV1, doc *v4Built) {
	t.Helper()
	leaf, err := b.ReceiptLeaf.RecomputeLeafV4()
	if err != nil {
		t.Fatal(err)
	}
	b.ReceiptLeaf.Leaf = leaf
	leaves := append([]string(nil), doc.leaves...)
	leaves[2] = leaf
	b.ParentProof, err = hash.ProveInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	b.ReceiptProof, err = hash.ProveInclusion(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}
	b.Head.RootHash = hash.MerkleRoot(leaves)
	b.Head.TreeSize = uint64(len(leaves))
	b.Head.Signature = ed25519.Sign(doc.signing.priv, HeadPayload(b.Head))
}

func TestReceiptBundleV4Positive(t *testing.T) {
	b, doc := buildReceiptBundleV4(t)
	res := VerifyReceiptBundleV1(b, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(doc.head)})
	if !res.OK || res.ReceiptLeafAndParentVerified == nil || !*res.ReceiptLeafAndParentVerified {
		t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
	}
	if res.ReceiptParentBinding != labelVerified || res.ReceiptExecutionValidity != labelNotChecked || res.ExpectedFinalHead != labelVerified {
		t.Fatalf("binding=%q execution=%q final=%q", res.ReceiptParentBinding, res.ReceiptExecutionValidity, res.ExpectedFinalHead)
	}

	// The wire round trip: marshal, strictly decode, verify again. The
	// parent_leaf needs its "entry" discriminator on the wire.
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatal(err)
	}
	parentRaw, err := json.Marshal(entryLeafV4{Type: lineEntry, EntryView: b.ParentLeaf})
	if err != nil {
		t.Fatal(err)
	}
	asMap["parent_leaf"] = parentRaw
	raw, err = json.Marshal(asMap)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReceiptBundleV1(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res := VerifyReceiptBundleV1(decoded, VerifyOptions{Keyring: doc.signing.keyring()}); !res.OK {
		t.Fatalf("decoded bundle: %v", res.Errors)
	}
	// Without an expected-final pin the bundle is historical evidence.
	res = VerifyReceiptBundleV1(b, VerifyOptions{Keyring: doc.signing.keyring()})
	if !res.OK || res.AntiRollback != labelNotChecked || res.LatestState != labelNotChecked || res.ExpectedFinalHead != labelNotChecked {
		t.Fatalf("unpinned: ok=%v anti_rollback=%q latest=%q final=%q", res.OK, res.AntiRollback, res.LatestState, res.ExpectedFinalHead)
	}
}

func TestReceiptBundleV4Refusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(b *ReceiptBundleV1, doc *v4Built)
		opts func(doc *v4Built) VerifyOptions
		frag string
	}{
		{"fabricated parent entry", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ParentLeaf.IntentID = "intent-forged"
		}, nil, "recomputed leaf"},
		{"parent proof omitted", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ParentProof = hash.InclusionProof{}
		}, nil, "parent inclusion"},
		{"receipt proof omitted", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ReceiptProof = hash.InclusionProof{}
		}, nil, "receipt inclusion"},
		{"proofs from a different tree", func(b *ReceiptBundleV1, doc *v4Built) {
			other := newV4Builder(t)
			other.specs = append(other.specs, v4ApprovalSpec(v4ApprovalPending("ap-x", "tenant-a", 30, v4Base.Add(9*time.Minute))))
			od := other.build()
			var err error
			b.ParentProof, err = hash.ProveInclusion(od.leaves, 1)
			if err != nil {
				t.Fatal(err)
			}
		}, nil, "tree_size"},
		{"swapped proof positions", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ParentProof, b.ReceiptProof = b.ReceiptProof, b.ParentProof
		}, nil, ""},
		{"sequence mismatch", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ReceiptLeaf.Sequence = v4uintp(1)
			resignBundleAfterReceiptMutation(t, b, doc)
		}, nil, "proven parent"},
		{"record hash mismatch", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ReceiptLeaf.RecordHash = "deadbeef"
			resignBundleAfterReceiptMutation(t, b, doc)
		}, nil, "proven parent"},
		{"nested intent mismatch", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ReceiptLeaf.Receipt.IntentID = v4str("intent-other")
			resignBundleAfterReceiptMutation(t, b, doc)
		}, nil, "receipt parent binding"},
		{"nested grant mismatch", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ReceiptLeaf.Receipt.GrantID = v4str("grant-other")
			resignBundleAfterReceiptMutation(t, b, doc)
		}, nil, "receipt parent binding"},
		{"cross-tenant receipt", func(b *ReceiptBundleV1, doc *v4Built) {
			b.ReceiptLeaf.Receipt.TenantID = v4str("tenant-b")
			resignBundleAfterReceiptMutation(t, b, doc)
		}, nil, "receipt parent binding"},
		{"unknown key id", nil, func(doc *v4Built) VerifyOptions {
			return VerifyOptions{Keyring: newV4KeyPair("ledger-k9", 77).keyring()}
		}, "key_id"},
		{"no keyring", nil, func(doc *v4Built) VerifyOptions { return VerifyOptions{} }, "keyring"},
		{"legacy head refused", func(b *ReceiptBundleV1, doc *v4Built) {
			b.Head.Schema = ""
		}, nil, "schema"},
		{"expected-final mismatch", nil, func(doc *v4Built) VerifyOptions {
			pin := v4Pin(doc.head)
			pin.TreeSize++
			return VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: pin}
		}, "expected final"},
		{"expected schema v3 refuses v4 bundle", nil, func(doc *v4Built) VerifyOptions {
			return VerifyOptions{Keyring: doc.signing.keyring(), ExpectedSchema: ExportSchemaV3}
		}, "schema"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, doc := buildReceiptBundleV4(t)
			if tc.mut != nil {
				tc.mut(&b, doc)
			}
			opts := VerifyOptions{Keyring: doc.signing.keyring()}
			if tc.opts != nil {
				opts = tc.opts(doc)
			}
			res := VerifyReceiptBundleV1(b, opts)
			if res.OK || res.ReceiptParentBinding == labelVerified {
				t.Fatalf("%s passed: %+v", tc.name, res)
			}
			if res.ReceiptExecutionValidity != labelNotChecked {
				t.Fatalf("execution validity must stay not_checked: %q", res.ReceiptExecutionValidity)
			}
			if tc.frag != "" && !strings.Contains(strings.Join(res.Errors, " "), tc.frag) {
				t.Fatalf("errors=%v, want fragment %q", res.Errors, tc.frag)
			}
			if tc.frag == "proven parent" || tc.frag == "receipt parent binding" {
				if res.ReceiptParentBinding != labelFailed {
					t.Fatalf("binding=%q errors=%v", res.ReceiptParentBinding, res.Errors)
				}
			}
		})
	}
}

// TestReceiptBundleV4ParentMustPrecede builds a tree with the receipt BEFORE
// its parent so both proofs verify and only the ordering rule can fail it.
func TestReceiptBundleV4ParentMustPrecede(t *testing.T) {
	kp := newV4KeyPair("ledger-k1", 11)
	entry := v4Entry("tenant-a", 1, v4Base)
	receipt := v4ReceiptLeaf(entry, "rc-1", types.EffectExecuted, v4Base.Add(time.Minute))
	receipt.ChainHash = "claim"
	receipt.Leaf = "claim" // exporter claims are excluded from the preimage
	entryLeaf, err := entry.RecomputeLeaf()
	if err != nil {
		t.Fatal(err)
	}
	receiptLeafHex, err := receipt.RecomputeLeafV4()
	if err != nil {
		t.Fatal(err)
	}
	leaves := []string{receiptLeafHex, entryLeaf} // receipt first
	head := hash.TreeHead{
		Algorithm: HeadSignatureAlgorithm,
		Schema:    ExportSchemaV4,
		LogID:     hash.DeriveLogID("tenant-a"),
		Index:     1,
		RootHash:  hash.MerkleRoot(leaves),
		TreeSize:  2,
		SignedAt:  v4Base,
	}
	head.Signature = ed25519.Sign(kp.priv, HeadPayload(head))
	parentProof, _ := hash.ProveInclusion(leaves, 1)
	receiptProof, _ := hash.ProveInclusion(leaves, 0)
	entry.Leaf = entryLeaf
	receipt.Leaf = receiptLeafHex
	b := ReceiptBundleV1{
		Schema: ReceiptBundleSchemaV1, KeyID: kp.id, Head: head,
		ParentLeaf: entry, ParentProof: parentProof,
		ReceiptLeaf: *receipt, ReceiptProof: receiptProof,
	}
	res := VerifyReceiptBundleV1(b, VerifyOptions{Keyring: kp.keyring()})
	if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "precede") {
		t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
	}
}

func TestStandaloneApprovalV4InclusionOnly(t *testing.T) {
	doc := newV4Builder(t).build()
	exp, err := LoadExportReader(strings.NewReader(doc.text))
	if err != nil {
		t.Fatal(err)
	}
	leaf := exp.Approvals[0]
	proof, err := hash.ProveInclusion(doc.leaves, 3)
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyStandaloneApprovalV4(leaf, proof, doc.head, doc.signing.id, VerifyOptions{Keyring: doc.signing.keyring()})
	if !res.OK || res.LeafInclusionVerified == nil || !*res.LeafInclusionVerified {
		t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
	}
	if res.ApprovalSourceHistory != labelNotChecked {
		t.Fatalf("a standalone approval must not report history verified: %q", res.ApprovalSourceHistory)
	}
	// A tampered field breaks the recomputed leaf and the proof.
	leaf.Approval.Approver = v4str("mallory")
	if res := VerifyStandaloneApprovalV4(leaf, proof, doc.head, doc.signing.id, VerifyOptions{Keyring: doc.signing.keyring()}); res.OK {
		t.Fatal("tampered approval leaf passed")
	}
	// A state the record rules refuse is not standalone-verifiable either:
	// the leaf-level shape checks still apply.
	bad := exp.Approvals[0]
	*bad.Approval.State = 0
	badProof, _ := hash.ProveInclusion(doc.leaves, 3)
	if res := VerifyStandaloneApprovalV4(bad, badProof, doc.head, doc.signing.id, VerifyOptions{Keyring: doc.signing.keyring()}); res.OK {
		t.Fatal("state-0 approval leaf passed standalone verification")
	}
}
