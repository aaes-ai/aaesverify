package verifier

import (
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// TestV4PositiveControls: a fully valid v4 export verifies in each freshness
// mode with the correct labels, and receipt_execution_validity is ALWAYS
// not_checked — a required disclosure, never an optional warning.
func TestV4PositiveControls(t *testing.T) {
	doc := newV4Builder(t).build()
	keyring := doc.signing.keyring()

	t.Run("unpinned internal consistency", func(t *testing.T) {
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: keyring})
		if !res.OK || res.Verdict != VerdictUnpinnedV4 {
			t.Fatalf("unpinned: ok=%v verdict=%q errors=%v", res.OK, res.Verdict, res.Errors)
		}
		if res.AntiRollback != labelNotChecked || res.LatestState != labelNotChecked {
			t.Fatalf("unpinned labels: anti_rollback=%q latest_state=%q", res.AntiRollback, res.LatestState)
		}
		if res.CryptographicConsistency == nil || !*res.CryptographicConsistency {
			t.Fatalf("cryptographic_consistency = %v", res.CryptographicConsistency)
		}
		if res.ReceiptIdentityAndParent != labelVerified || res.ApprovalSourceHistory != labelVerified {
			t.Fatalf("scoped labels: receipt=%q approval=%q", res.ReceiptIdentityAndParent, res.ApprovalSourceHistory)
		}
		if res.ReceiptExecutionValidity != labelNotChecked {
			t.Fatalf("receipt_execution_validity = %q, want always not_checked", res.ReceiptExecutionValidity)
		}
		if res.KeySource != "keyring" {
			t.Fatalf("key_source = %q", res.KeySource)
		}
		if res.HeadTreeSize != 4 || res.EntryCount != 2 {
			t.Fatalf("counts: tree_size=%d entries=%d", res.HeadTreeSize, res.EntryCount)
		}
	})

	t.Run("expected final head", func(t *testing.T) {
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring:       keyring,
			ExpectedFinal: v4Pin(doc.head),
		})
		if !res.OK || res.ExpectedFinalHead != labelVerified {
			t.Fatalf("expected-final: ok=%v label=%q errors=%v", res.OK, res.ExpectedFinalHead, res.Errors)
		}
		if res.Verdict != "CONSISTENT" {
			t.Fatalf("witness-less current verdict = %q, want CONSISTENT", res.Verdict)
		}
		if res.AntiRollback != labelVerified || res.LatestState != labelNotChecked {
			t.Fatalf("labels: anti_rollback=%q latest_state=%q", res.AntiRollback, res.LatestState)
		}
	})

	t.Run("tree size floor", func(t *testing.T) {
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: keyring, MinTreeSize: 4})
		if !res.OK || res.TreeSizeFloor != labelSatisfied || res.Verdict != VerdictFloorV4 {
			t.Fatalf("floor: ok=%v label=%q verdict=%q errors=%v", res.OK, res.TreeSizeFloor, res.Verdict, res.Errors)
		}
		if res.ContinuityFromCutover != labelNotChecked || res.LatestState != labelNotChecked {
			t.Fatalf("floor labels: continuity=%q latest=%q", res.ContinuityFromCutover, res.LatestState)
		}
	})
}

// TestV4InterleavedTypedLeaves is the interleaved positive control: typed
// leaves sit BETWEEN decision entries in log order, and the chain and root
// still cover every leaf in file order.
func TestV4InterleavedTypedLeaves(t *testing.T) {
	b := newV4Builder(t)
	e2 := v4Entry("tenant-a", 2, v4Base.Add(4*time.Minute))
	// entry, receipt, entry, approval, receipt
	b.specs = []v4Spec{
		b.specs[0],
		v4ReceiptSpec(v4ReceiptLeaf(*b.specs[0].entry, "rc-early", types.EffectDenied, v4Base.Add(90*time.Second))),
		v4EntrySpec(e2),
		b.specs[3],
		v4ReceiptSpec(v4ReceiptLeaf(e2, "rc-late", types.EffectAuthorized, v4Base.Add(5*time.Minute))),
	}
	doc := b.build()
	res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(doc.head)})
	if !res.OK || res.ExpectedFinalHead != labelVerified {
		t.Fatalf("interleaved: ok=%v errors=%v", res.OK, res.Errors)
	}
	exp, err := LoadExportReader(strings.NewReader(doc.text))
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, l := range exp.LeavesV4 {
		kinds = append(kinds, l.Kind)
	}
	want := []string{"entry", "receipt", "entry", "approval", "receipt"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("leaf order = %v, want %v", kinds, want)
	}
	if len(exp.Entries) != 2 || len(exp.Receipts) != 2 || len(exp.Approvals) != 1 {
		t.Fatalf("typed slices: entries=%d receipts=%d approvals=%d", len(exp.Entries), len(exp.Receipts), len(exp.Approvals))
	}
}

// TestV4HeaderCountIndexRefusals covers the section 4.1 guards: every count,
// index, first-leaf, head-schema, algorithm and header-field rule gets a
// failing case.
func TestV4HeaderCountIndexRefusals(t *testing.T) {
	cases := []struct {
		name   string
		head   func(*hash.TreeHead)
		header func(map[string]any)
		frag   string
	}{
		{"head schema missing", func(h *hash.TreeHead) { h.Schema = "" }, nil, "signed schema"},
		{"head schema v3", func(h *hash.TreeHead) { h.Schema = ExportSchemaV3 }, nil, "signed schema"},
		{"head algorithm missing", func(h *hash.TreeHead) { h.Algorithm = "" }, nil, "algorithm"},
		{"head tree_size entries only", func(h *hash.TreeHead) { h.TreeSize = 2 }, nil, "tree_size"},
		{"head index not last decision", func(h *hash.TreeHead) { h.Index = 99 }, nil, "head index"},
		{"head log_id other tenant", func(h *hash.TreeHead) { h.LogID = hash.DeriveLogID("tenant-b") }, nil, "log_id"},
		{"leaf_count wrong", nil, func(h map[string]any) { h["leaf_count"] = 3 }, "leaf_count 3"},
		{"entry_count wrong", nil, func(h map[string]any) { h["entry_count"] = 3 }, "declares 3 entries"},
		{"leaf_count below entry_count", nil, func(h map[string]any) { h["leaf_count"] = 1 }, "below entry_count"},
		{"signing_key_id missing", nil, func(h map[string]any) { delete(h, "signing_key_id") }, "signing_key_id"},
		{"exported_at zero", nil, func(h map[string]any) { h["exported_at"] = "0001-01-01T00:00:00Z" }, "exported_at"},
		{"signature_algorithm not ed25519", nil, func(h map[string]any) { h["signature_algorithm"] = "rsa" }, "signature_algorithm"},
		{"public_key not hex", nil, func(h map[string]any) { h["public_key"] = "zz" }, "public_key"},
		{"public_key wrong length", nil, func(h map[string]any) { h["public_key"] = "ab" }, "public_key"},
		{"head pre_anchor without header flag", nil, func(h map[string]any) { delete(h, "pre_anchor") }, "pre_anchor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newV4Builder(t)
			b.mutateHead = tc.head
			b.mutateHeader = tc.header
			doc := b.build()
			res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
			if res.OK {
				t.Fatalf("export passed: %+v", res)
			}
			if !strings.Contains(strings.Join(res.Errors, " "), tc.frag) {
				t.Fatalf("errors %v do not name %q", res.Errors, tc.frag)
			}
		})
	}

	t.Run("header signature_algorithm disagrees with signed head algorithm", func(t *testing.T) {
		// The header claims ed25519; the signed head names nothing (a mutation
		// that also breaks the signature, but the disagreement must be named).
		b := newV4Builder(t)
		b.mutateHead = func(h *hash.TreeHead) { h.Algorithm = "" }
		b.mutateHeader = func(h map[string]any) { h["signature_algorithm"] = "ed25519" }
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		joined := strings.Join(res.Errors, " ")
		if res.OK || !strings.Contains(joined, "algorithm") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("decision-free export refused", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs = b.specs[2:] // only the receipt and approval, no decision
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), ErrEmptyLog.Error()) {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("first leaf is not an entry", func(t *testing.T) {
		b := newV4Builder(t)
		// receipt first, then the two entries
		b.specs = []v4Spec{b.specs[2], b.specs[0], b.specs[1], b.specs[3]}
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "first leaf") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("expected tenant mismatch", func(t *testing.T) {
		doc := newV4Builder(t).build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedTenantID: "tenant-b"})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "tenant") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("expected log id mismatch", func(t *testing.T) {
		doc := newV4Builder(t).build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedLogID: hash.DeriveLogID("tenant-b")})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "log") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}

// TestV4ChainCoversEveryLeafType pins section 4.3: the chain and root run
// over ALL leaf types in file order. Filtering to decisions before chaining
// is a verification bug — these cases fail closed against it.
func TestV4ChainCoversEveryLeafType(t *testing.T) {
	t.Run("typed leaf content tamper fails leaf chain and root", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[2].receipt.Receipt.Effect = v4str("payments.refund")
		doc := b.build() // claims recomputed over the tampered content? NO: build computes honest claims.
		// Honest rebuild passes; now tamper the CLAIMED leaf of the receipt.
		lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")
		var receiptLine map[string]any
		if err := jsonUnmarshal([]byte(lines[3]), &receiptLine); err != nil {
			t.Fatal(err)
		}
		receiptLine["leaf"] = hash.SHA256Hex([]byte("forged"))
		tampered := spliceLine(t, lines, 3, receiptLine)
		res := verifyV4(t, tampered, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || res.ChainOK {
			t.Fatalf("tampered receipt leaf claim passed: ok=%v chain=%v", res.OK, res.ChainOK)
		}
	})

	t.Run("entries-only chain claim fails", func(t *testing.T) {
		// A verifier that filters typed leaves before chaining would compute
		// the chain of an entry FOLLOWING a typed leaf from the previous
		// entry's chain directly. Present exactly that (wrong) claim: it must
		// fail, because the receipt's preimage links the chain between them.
		b := newV4Builder(t)
		e2 := v4Entry("tenant-a", 2, v4Base.Add(4*time.Minute))
		// entry, receipt bound to it, entry: the receipt links the chain
		// between the two entries.
		b.specs = []v4Spec{
			b.specs[0],
			v4ReceiptSpec(v4ReceiptLeaf(*b.specs[0].entry, "rc-mid", types.EffectExecuted, v4Base.Add(2*time.Minute))),
			v4EntrySpec(e2),
			b.specs[3],
		}
		pre0, err := b.specs[0].entry.preimage()
		if err != nil {
			t.Fatal(err)
		}
		pre2, err := e2.preimage()
		if err != nil {
			t.Fatal(err)
		}
		entriesOnlyChain := hash.Chain(hash.Chain("", pre0), pre2)
		doc := b.build()
		lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")
		var entryLine map[string]any
		if err := jsonUnmarshalV4([]byte(lines[3]), &entryLine); err != nil {
			t.Fatal(err)
		}
		if entryLine["chain_hash"] == entriesOnlyChain {
			t.Fatal("fixture did not change the claim: the receipt must sit between the two entries")
		}
		entryLine["chain_hash"] = entriesOnlyChain
		tampered := spliceLine(t, lines, 3, entryLine)
		res := verifyV4(t, tampered, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || res.ChainOK {
			t.Fatalf("entries-only chain passed: ok=%v", res.OK)
		}
	})

	t.Run("entries-only root fails", func(t *testing.T) {
		// A head computed over the decision leaves only — the bug's root —
		// does not match the all-leaf recomputation.
		b := newV4Builder(t)
		_, leaves, _, lastSeq := b.leafClaims()
		entryLeaves := leaves[:2]
		b.mutateHead = func(h *hash.TreeHead) {
			h.RootHash = hash.MerkleRoot(entryLeaves)
			h.TreeSize = uint64(len(entryLeaves))
			h.Index = lastSeq
		}
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || res.RootOK {
			t.Fatalf("entries-only root passed: ok=%v root=%v errors=%v", res.OK, res.RootOK, res.Errors)
		}
	})

	t.Run("recompute all but keep the old signature", func(t *testing.T) {
		// The whole leaf series is honestly recomputed after a content
		// change, but the head keeps the ORIGINAL signature: the signature
		// must fail even though chain and root agree with the mutated head.
		original := newV4Builder(t).build()
		b := newV4Builder(t)
		b.specs[2].receipt.Receipt.Effect = v4str("payments.refund")
		b.headSignature = original.head.Signature
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || res.SignatureOK || !res.ChainOK || !res.RootOK {
			t.Fatalf("ok=%v sig=%v chain=%v root=%v", res.OK, res.SignatureOK, res.ChainOK, res.RootOK)
		}
		if res.CryptographicConsistency == nil || *res.CryptographicConsistency {
			t.Fatal("cryptographic_consistency true after a signature failure")
		}
		if res.ReceiptIdentityAndParent != labelNotChecked {
			t.Fatalf("scoped checks ran over failed crypto: %q", res.ReceiptIdentityAndParent)
		}
	})

	t.Run("typed leaf deleted while retaining the old head", func(t *testing.T) {
		doc := newV4Builder(t).build()
		lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")
		// Drop the receipt line, keep head and counts.
		out := strings.Join(append(lines[:3], lines[4:]...), "\n") + "\n"
		res := verifyV4(t, out, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK {
			t.Fatalf("a stripped typed leaf passed: %+v", res)
		}
	})

	t.Run("summary leaf joins the chain", func(t *testing.T) {
		b := newV4Builder(t)
		sum := validSummaryLeafTypedV4(t, b.tenant)
		b.specs = append(b.specs, v4SummarySpec(sum))
		// The input names a genuine signed head over the one-entry prefix.
		b.localPrefixInputs = map[int]map[int]uint64{len(b.specs) - 1: {0: 1}}
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(doc.head)})
		if !res.OK || res.ExpectedFinalHead != labelVerified {
			t.Fatalf("summary export: ok=%v errors=%v", res.OK, res.Errors)
		}
		if res.SummaryAncestry != labelVerified || res.SummaryInputsVerified == nil || !*res.SummaryInputsVerified {
			t.Fatalf("summary ancestry=%q inputsVerified=%v errors=%v", res.SummaryAncestry, res.SummaryInputsVerified, res.Errors)
		}
	})
}

// TestV4EmbeddedKeyUnpinned verifies the embedded-key fallback proves
// internal consistency only, with the honesty warning the legacy path prints.
func TestV4EmbeddedKeyUnpinned(t *testing.T) {
	doc := newV4Builder(t).build()
	res := verifyV4(t, doc.text, VerifyOptions{})
	if !res.OK || res.KeySource != "embedded" || res.Verdict != VerdictUnpinnedV4 {
		t.Fatalf("ok=%v key_source=%q verdict=%q errors=%v", res.OK, res.KeySource, res.Verdict, res.Errors)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "embedded") {
		t.Fatalf("embedded warning missing: %v", res.Warnings)
	}
}

// jsonUnmarshal exists so fixture code shares one error-checked unmarshal.
func jsonUnmarshal(raw []byte, v any) error {
	return jsonUnmarshalV4(raw, v)
}

// spliceLine replaces line i of a document with a re-marshaled object.
func spliceLine(t *testing.T, lines []string, i int, obj map[string]any) string {
	t.Helper()
	raw := marshalV4(t, obj)
	out := append([]string{}, lines...)
	out[i] = string(raw)
	return strings.Join(out, "\n") + "\n"
}
