package verifier

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Freshness modes, rotation, witness independence and the genuine-legacy-head
// rollback attack (design sections 4.7, 6.2–6.4 and 9.3).

// rotatedBuilder returns an export with a K1 legacy anchor over the
// decision-only prefix and a K2-signed final head.
func rotatedBuilder(t *testing.T) (*v4ExportBuilder, *v4KeyPair, *v4KeyPair) {
	t.Helper()
	k1 := newV4KeyPair("ledger-k1", 11)
	k2 := newV4KeyPair("ledger-k2", 22)
	b := newV4Builder(t)
	b.signing = k2
	b.anchors = append(b.anchors, v4AnchorSpec{key: k1, treeSize: 2, legacy: true})
	return b, k1, k2
}

func TestV4RotationAndAnchorKeyring(t *testing.T) {
	t.Run("K1 anchor and K2 final with the full keyring", func(t *testing.T) {
		b, k1, k2 := rotatedBuilder(t)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: mergeKeyringsV4(k1, k2), ExpectedFinal: v4Pin(doc.head)})
		if !res.OK || res.AnchorsOK != true || res.ExpectedFinalHead != labelVerified {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("retired K1 removed from the keyring", func(t *testing.T) {
		b, _, k2 := rotatedBuilder(t)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: k2.keyring(), ExpectedFinal: v4Pin(doc.head)})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "ledger-k1") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("anchor without key_id", func(t *testing.T) {
		b, k1, k2 := rotatedBuilder(t)
		b.anchors[0].omitKeyID = true
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: mergeKeyringsV4(k1, k2), ExpectedFinal: v4Pin(doc.head)})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "key_id") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("unknown anchor key_id", func(t *testing.T) {
		b, k1, k2 := rotatedBuilder(t)
		k3 := newV4KeyPair("ledger-k9", 33)
		b.anchors[0].key = k3 // signed by an unauthorized key
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: mergeKeyringsV4(k1, k2), ExpectedFinal: v4Pin(doc.head)})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "ledger-k9") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("embedded key cannot satisfy expected-final", func(t *testing.T) {
		doc := newV4Builder(t).build()
		res := verifyV4(t, doc.text, VerifyOptions{ExpectedFinal: v4Pin(doc.head)})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "keyring") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("legacy anchor over a typed prefix refused", func(t *testing.T) {
		b, k1, k2 := rotatedBuilder(t)
		b.anchors[0].treeSize = 3 // covers the receipt leaf under a legacy head
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: mergeKeyringsV4(k1, k2), ExpectedFinal: v4Pin(doc.head)})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "typed") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}

func TestV4WitnessIndependenceWholeKeyring(t *testing.T) {
	// K1 countersigns the final K2 head: cryptographically valid, but K1 is an
	// authorised ledger key, so it is never an independent witness.
	build := func(t *testing.T) (*v4Built, *v4KeyPair, *v4KeyPair) {
		b, k1, k2 := rotatedBuilder(t)
		b.anchors = append(b.anchors, v4AnchorSpec{
			key: k2, treeSize: 4, // covers the final head's tree
			witnesses: []v4WitnessSpec{{id: "witness-as-k1", key: k1}},
		})
		return b.build(), k1, k2
	}
	t.Run("ledger key as witness is not independent", func(t *testing.T) {
		doc, k1, k2 := build(t)
		// Cryptographic verification only (no PASS-eligible mode): the
		// overlapping pin is legal, the signature verifies, and it is always
		// reported non-independent (section 4.7).
		opts := VerifyOptions{
			Keyring:            mergeKeyringsV4(k1, k2),
			TrustedWitnessKeys: map[string][]byte{"witness-as-k1": k1.pub},
		}
		res := verifyV4(t, doc.text, opts)
		if !res.OK || res.WitnessesVerified == 0 {
			t.Fatalf("the countersignature should verify cryptographically: ok=%v witnesses=%d errors=%v", res.OK, res.WitnessesVerified, res.Errors)
		}
		if res.IndependentWitnesses != 0 || res.Verdict == "PASS" {
			t.Fatalf("a ledger key must not be independent: independent=%d verdict=%q", res.IndependentWitnesses, res.Verdict)
		}
	})
	t.Run("require-independent fails and trust-context overlap is a config error", func(t *testing.T) {
		doc, k1, k2 := build(t)
		opts := VerifyOptions{
			Keyring:            mergeKeyringsV4(k1, k2),
			ExpectedFinal:      v4Pin(doc.head),
			TrustedWitnessKeys: map[string][]byte{"witness-as-k1": k1.pub},
		}
		res := verifyV4(t, doc.text, opts)
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "same key") {
			t.Fatalf("overlapping ledger and witness keys: ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("the same key under a second witness id stays excluded", func(t *testing.T) {
		doc, k1, k2 := build(t)
		opts := VerifyOptions{
			Keyring:            mergeKeyringsV4(k1, k2),
			ExpectedFinal:      v4Pin(doc.head),
			TrustedWitnessKeys: map[string][]byte{"someone-else": k1.pub}, // byte-level match
		}
		res := verifyV4(t, doc.text, opts)
		if res.IndependentWitnesses != 0 {
			t.Fatalf("key-aliased witness counted as independent")
		}
	})
}

func TestV4FreshnessModes(t *testing.T) {
	t.Run("expected-final rejects an earlier genuine state", func(t *testing.T) {
		big := newV4Builder(t)
		big.specs = append(big.specs, v4ApprovalSpec(v4ApprovalPending("ap-2", "tenant-a", 30, v4Base.Add(9*time.Hour))))
		bigDoc := big.build()
		smallDoc := newV4Builder(t).build()
		res := verifyV4(t, smallDoc.text, VerifyOptions{
			Keyring: smallDoc.signing.keyring(), ExpectedFinal: v4Pin(bigDoc.head),
		})
		if res.OK || res.ExpectedFinalHead != labelFailed {
			t.Fatalf("ok=%v final=%q", res.OK, res.ExpectedFinalHead)
		}
	})
	t.Run("unchanged decision index while the tree grows", func(t *testing.T) {
		withReceipt := newV4Builder(t).build() // 4 leaves, last decision seq 2
		b := newV4Builder(t)
		b.specs = b.specs[:2] // decisions only: same head.index, size 2
		smallDoc := b.build()
		res := verifyV4(t, smallDoc.text, VerifyOptions{
			Keyring: smallDoc.signing.keyring(), ExpectedFinal: v4Pin(withReceipt.head),
		})
		if res.OK {
			t.Fatal("a decision-only prefix passed the pin of the larger state")
		}
	})
	t.Run("cutover continuity requires the anchor", func(t *testing.T) {
		b, k1, k2 := rotatedBuilder(t)
		doc := b.build()
		cutover := v4Pin(doc.anchorHeads[0])
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: mergeKeyringsV4(k1, k2), Cutover: cutover})
		if !res.OK || res.ContinuityFromCutover != labelVerified || res.LatestState != labelNotChecked {
			t.Fatalf("ok=%v continuity=%q latest=%q errors=%v", res.OK, res.ContinuityFromCutover, res.LatestState, res.Errors)
		}
		if res.Verdict != VerdictContinuityV4 {
			t.Fatalf("continuity must not produce the current headline: %q", res.Verdict)
		}
		// Without the cutover anchor in the export, continuity fails.
		noAnchor := newV4Builder(t).build()
		res = verifyV4(t, noAnchor.text, VerifyOptions{Keyring: noAnchor.signing.keyring(), Cutover: cutover})
		if res.OK || res.ContinuityFromCutover != labelFailed || !strings.Contains(strings.Join(res.Errors, " "), "not present as a verified anchor") {
			t.Fatalf("ok=%v continuity=%q errors=%v", res.OK, res.ContinuityFromCutover, res.Errors)
		}
	})
	t.Run("tree size floor", func(t *testing.T) {
		doc := newV4Builder(t).build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), MinTreeSize: 3})
		if !res.OK || res.TreeSizeFloor != labelSatisfied ||
			res.ContinuityFromCutover != labelNotChecked || res.LatestState != labelNotChecked {
			t.Fatalf("ok=%v floor=%q errors=%v", res.OK, res.TreeSizeFloor, res.Errors)
		}
		if res.Verdict != VerdictFloorV4 {
			t.Fatalf("floor must not produce the current headline: %q", res.Verdict)
		}
		res = verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), MinTreeSize: 99})
		if res.OK || res.TreeSizeFloor != labelFailed {
			t.Fatalf("below-floor state passed: ok=%v floor=%q", res.OK, res.TreeSizeFloor)
		}
	})
	t.Run("equivocation: two roots at one tree size", func(t *testing.T) {
		b, k1, k2 := rotatedBuilder(t)
		b.anchors[0].legacy = false
		b.anchors[0].treeSize = 4 // the final tree size, but a different root
		b.anchors[0].mutate = func(h *hash.TreeHead) { h.RootHash = hash.SHA256Hex([]byte("other state")) }
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: mergeKeyringsV4(k1, k2), ExpectedFinal: v4Pin(doc.head)})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "different roots") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}

// TestV4GenuineLegacyHeadRollback is the section 9.3 attack: strip the typed
// leaves, relabel the decision prefix v3, and substitute a genuine legacy head
// over exactly those decisions. Historical mode accepts the artifact as valid
// v3; every current-v4 mode refuses it before any success verdict.
func TestV4GenuineLegacyHeadRollback(t *testing.T) {
	kp := newV4KeyPair("ledger-k1", 11)
	doc := newV4Builder(t).build()
	lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")
	// The genuine legacy head over the two-entry prefix.
	legacyHead := hash.TreeHead{
		Algorithm: HeadSignatureAlgorithm,
		LogID:     hash.DeriveLogID("tenant-a"),
		Index:     2,
		RootHash:  hash.MerkleRoot(doc.leaves[:2]),
		TreeSize:  2,
		SignedAt:  v4Base,
		PreAnchor: true,
	}
	legacyHead.Signature = ed25519.Sign(kp.priv, HeadPayload(legacyHead))
	hdr := map[string]any{
		"type":        "header",
		"schema":      ExportSchemaV3,
		"log_id":      "log-tenant-a",
		"tenant_id":   "tenant-a",
		"exported_at": v4Base,
		"entry_count": 2,
		"head":        legacyHead,
		"public_key":  encodeKeyHexV4(kp.pub),
		"pre_anchor":  true,
	}
	attack := string(marshalV4(t, hdr)) + "\n" + strings.Join(lines[1:3], "\n") + "\n"

	// Historical mode: a valid v3 artifact, exactly as section 6.2 predicts.
	hist := VerifyExportReaderResult(strings.NewReader(attack), kp.pub, VerifyOptions{})
	if !hist.OK || hist.Schema != ExportSchemaV3 {
		t.Fatalf("historical mode must accept the genuine v3 prefix: %v", hist.Errors)
	}
	// Current-v4 modes refuse it before any success verdict.
	if res := VerifyExportReaderResult(strings.NewReader(attack), kp.pub, VerifyOptions{ExpectedSchema: ExportSchemaV4}); res.OK {
		t.Fatal("expected-schema v4 accepted a relabelled v3 prefix")
	}
	pinned := &HeadPin{LogID: legacyHead.LogID, Index: 2, RootHash: legacyHead.RootHash, TreeSize: 4}
	res := VerifyExportReaderResult(strings.NewReader(attack), kp.pub, VerifyOptions{ExpectedFinal: pinned})
	if res.OK {
		t.Fatal("expected-final mode accepted a relabelled v3 prefix")
	}
}
