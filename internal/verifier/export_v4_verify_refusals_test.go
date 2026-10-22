package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Verification-time refusals of design sections 4.7, 4.8, 6.2 and 6.4: anchor
// head rules, keyring resolution, freshness modes, header identity, leaf
// claims, decision sequencing, and the standalone proof APIs.

func errsContain(res *Result, frag string) bool {
	return strings.Contains(strings.Join(res.Errors, " "), frag)
}

// anchorDoc builds an otherwise-valid export carrying one anchor over the
// two-leaf decision prefix, with the head mutated before signing.
func anchorDoc(t *testing.T, mutate func(*hash.TreeHead)) *v4Built {
	t.Helper()
	b := newV4Builder(t)
	b.anchors = append(b.anchors, v4AnchorSpec{key: b.signing, treeSize: 2, mutate: mutate})
	return b.build()
}

func TestV4AnchorRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*hash.TreeHead)
		frag   string
	}{
		{"unknown signed schema", func(h *hash.TreeHead) { h.Schema = "aaes.bogus/v9" }, "unknown signed schema"},
		{"v4 head with a wrong algorithm", func(h *hash.TreeHead) { h.Algorithm = "rsa" }, "must name algorithm"},
		{"head of another log", func(h *hash.TreeHead) { h.LogID = hash.DeriveLogID("tenant-b") }, "head names"},
		{"tree size zero", func(h *hash.TreeHead) { h.TreeSize = 0 }, "tree_size 0"},
		{"tree size past the log", func(h *hash.TreeHead) { h.TreeSize = 99 }, "covers 99"},
		{"root is not the prefix root", func(h *hash.TreeHead) { h.RootHash = hash.SHA256Hex([]byte("other")) }, "is not the root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := anchorDoc(t, tc.mutate)
			res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
			if res.OK || res.AnchorsOK || !errsContain(res, tc.frag) {
				t.Fatalf("ok=%v anchorsOK=%v errors=%v", res.OK, res.AnchorsOK, res.Errors)
			}
		})
	}

	t.Run("anchor head signed under a different key than its keyring entry", func(t *testing.T) {
		doc := anchorDoc(t, nil)
		// The keyring maps the anchor's key_id to a different key, so the
		// signature check itself fails after resolution succeeds.
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: newV4KeyPair("ledger-k1", 99).keyring()})
		if res.OK || res.AnchorsOK || !errsContain(res, "anchor 0") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("timestamp digest does not cover the anchor head", func(t *testing.T) {
		doc := newV4Builder(t).build()
		head := hash.TreeHead{
			Algorithm: HeadSignatureAlgorithm,
			Schema:    ExportSchemaV4,
			LogID:     hash.DeriveLogID("tenant-a"),
			Index:     doc.head.Index,
			RootHash:  doc.head.RootHash,
			TreeSize:  doc.head.TreeSize,
			SignedAt:  v4Base.Add(2 * time.Hour),
		}
		head.Signature = ed25519.Sign(doc.signing.priv, HeadPayload(head))
		line := map[string]any{
			"type": "anchor", "head": head, "key_id": doc.signing.id,
			"timestamp": map[string]any{
				"authority": "tsa.example",
				"digest":    strings.Repeat("0", 64),
				"time":      v4Base.Add(2 * time.Hour),
			},
		}
		text := doc.text + string(marshalV4(t, line)) + "\n"
		res := verifyV4(t, text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || res.AnchorsOK || !errsContain(res, "timestamp digest") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}

func TestV4IndependentWitnessCounted(t *testing.T) {
	// A caller-pinned witness whose key is no authorised ledger key epoch is
	// independent (design section 4.7): the true branch of the exclusion.
	w := newV4KeyPair("witness-1", 66)
	b := newV4Builder(t)
	b.anchors = append(b.anchors, v4AnchorSpec{
		key:       b.signing,
		treeSize:  4, // covers the final head
		witnesses: []v4WitnessSpec{{id: "w1", key: w}},
	})
	doc := b.build()
	res := verifyV4(t, doc.text, VerifyOptions{
		Keyring:            doc.signing.keyring(),
		TrustedWitnessKeys: map[string][]byte{"w1": w.pub},
	})
	if !res.OK || res.IndependentWitnesses != 1 {
		t.Fatalf("ok=%v independent=%d errors=%v", res.OK, res.IndependentWitnesses, res.Errors)
	}
}

func TestV4KeyringResolutionRefusals(t *testing.T) {
	t.Run("embedded key disagrees with the keyring entry", func(t *testing.T) {
		other := newV4KeyPair("other", 77)
		b := newV4Builder(t)
		b.mutateHeader = func(m map[string]any) { m["public_key"] = hex.EncodeToString(other.pub) }
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "disagrees with keyring entry") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("embedded key is not a parseable key", func(t *testing.T) {
		b := newV4Builder(t)
		b.mutateHeader = func(m map[string]any) { m["public_key"] = "zz" }
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{})
		if res.OK || !errsContain(res, "embedded public key") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("no keyring and no embedded key", func(t *testing.T) {
		b := newV4Builder(t)
		b.embedKey = false
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{})
		if res.OK || !errsContain(res, "no public key supplied") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("anchor key_id without a keyring", func(t *testing.T) {
		doc := anchorDoc(t, nil)
		res := verifyV4(t, doc.text, VerifyOptions{})
		if res.OK || !errsContain(res, "no caller-pinned keyring") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}

func TestV4DispatchAndFreshnessRefusals(t *testing.T) {
	t.Run("two freshness modes at once", func(t *testing.T) {
		doc := newV4Builder(t).build()
		pin := v4Pin(doc.head)
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(), ExpectedFinal: pin, Cutover: pin,
		})
		if res.OK || !errsContain(res, "mutually exclusive") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("expected-final pin met but the signature is forged", func(t *testing.T) {
		b := newV4Builder(t)
		b.headSignature = []byte("forged")
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(doc.head),
		})
		if res.OK || res.ExpectedFinalHead != labelFailed || !errsContain(res, "did not verify under its resolved key") {
			t.Fatalf("ok=%v final=%q errors=%v", res.OK, res.ExpectedFinalHead, res.Errors)
		}
	})
	t.Run("cutover pin above the final tree size", func(t *testing.T) {
		doc := newV4Builder(t).build()
		pin := v4Pin(doc.head)
		pin.TreeSize += 10
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), Cutover: pin})
		if res.OK || res.ContinuityFromCutover != labelFailed || !errsContain(res, "below the pinned cutover") {
			t.Fatalf("ok=%v continuity=%q errors=%v", res.OK, res.ContinuityFromCutover, res.Errors)
		}
	})
}

// TestV4ChainWalkRefusals covers the unified chain walk's leaf-claim and
// decision-sequence guards plus the header's tenant-agreement rule.
func TestV4ChainWalkRefusals(t *testing.T) {
	dropMember := func(t *testing.T, doc *v4Built, lineIdx int, member string) string {
		t.Helper()
		lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[lineIdx]), &m); err != nil {
			t.Fatal(err)
		}
		delete(m, member)
		lines[lineIdx] = string(marshalV4(t, m))
		return strings.Join(lines, "\n") + "\n"
	}
	t.Run("missing chain_hash claim", func(t *testing.T) {
		doc := newV4Builder(t).build()
		res := verifyV4(t, dropMember(t, doc, 1, "chain_hash"), VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "missing chain_hash") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("missing leaf claim", func(t *testing.T) {
		doc := newV4Builder(t).build()
		res := verifyV4(t, dropMember(t, doc, 2, "leaf"), VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "missing leaf") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("entry without tenant_id", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[1].entry.TenantID = ""
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "missing tenant_id") || !errsContain(res, "belongs to tenant") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("decision sequence goes backwards", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[1].entry.Sequence = 1
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "does not follow") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}

// TestV4ScopedVerdicts covers the gapped and shredded headlines of
// verdictV4 with otherwise-valid exports.
func TestV4ScopedVerdicts(t *testing.T) {
	builderFor := func(t *testing.T, specs ...v4Spec) *v4Built {
		t.Helper()
		b := &v4ExportBuilder{
			t: t, tenant: "tenant-a", exported: v4Base.Add(time.Hour),
			preAnchor: true, embedKey: true,
			signing: newV4KeyPair("ledger-k1", 11), specs: specs,
		}
		return b.build()
	}
	t.Run("gapped history with a covering tombstone", func(t *testing.T) {
		e3 := v4Entry("tenant-a", 3, v4Base.Add(2*time.Minute))
		e3.Tombstone = &TombstoneView{
			FromSequence: 2, ToSequence: 2,
			Reason: "retention window elapsed", AuthorizedBy: "ops-policy",
			RemovedAt: v4Base.Add(3 * time.Minute),
		}
		doc := builderFor(t, v4EntrySpec(v4Entry("tenant-a", 1, v4Base)), v4EntrySpec(e3))
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if !res.OK || !res.Gapped || res.Verdict != "OK_WITH_GAPS" {
			t.Fatalf("ok=%v gapped=%v verdict=%q errors=%v", res.OK, res.Gapped, res.Verdict, res.Errors)
		}
	})
	t.Run("sealed key-destruction record", func(t *testing.T) {
		e2 := v4Entry("tenant-a", 2, v4Base.Add(time.Minute))
		e2.Capability = KeyShredCapability
		doc := builderFor(t, v4EntrySpec(v4Entry("tenant-a", 1, v4Base)), v4EntrySpec(e2))
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if !res.OK || len(res.ShredEvents) != 1 || res.Verdict != "OK_WITH_SHREDDED_FIELDS" {
			t.Fatalf("ok=%v shreds=%d verdict=%q errors=%v", res.OK, len(res.ShredEvents), res.Verdict, res.Errors)
		}
	})
}

// TestV4VerifyExportEntrypoint covers the VerifyExportV4 entrypoint on an
// already-parsed export.
func TestV4VerifyExportEntrypoint(t *testing.T) {
	doc := newV4Builder(t).build()
	exp, err := LoadExportReader(strings.NewReader(doc.text))
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyExportV4(exp, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(doc.head)})
	if !res.OK || res.ExpectedFinalHead != labelVerified {
		t.Fatalf("ok=%v final=%q errors=%v", res.OK, res.ExpectedFinalHead, res.Errors)
	}
}

func TestV4StandaloneRefusals(t *testing.T) {
	t.Run("bundle head log_id is not the pinned log", func(t *testing.T) {
		b, doc := buildReceiptBundleV4(t)
		res := VerifyReceiptBundleV1(b, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedLogID: "log-other"})
		if res.OK || !errsContain(res, "caller-pinned logical log") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("bundle receipt tenant is not the pinned tenant", func(t *testing.T) {
		b, doc := buildReceiptBundleV4(t)
		res := VerifyReceiptBundleV1(b, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedTenantID: "tenant-b"})
		if res.OK || !errsContain(res, "is not the expected tenant") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("parent leaf cannot be canonicalised", func(t *testing.T) {
		b, doc := buildReceiptBundleV4(t)
		b.ParentLeaf.OccurredAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		res := VerifyReceiptBundleV1(b, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "parent leaf") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("receipt leaf cannot be canonicalised", func(t *testing.T) {
		b, doc := buildReceiptBundleV4(t)
		b.ReceiptLeaf.Type = "bogus"
		res := VerifyReceiptBundleV1(b, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "receipt leaf") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("standalone approval leaf fails its own validation", func(t *testing.T) {
		doc := newV4Builder(t).build()
		exp, err := LoadExportReader(strings.NewReader(doc.text))
		if err != nil {
			t.Fatal(err)
		}
		leaf := exp.Approvals[0]
		leaf.Type = "bogus"
		proof, err := hash.ProveInclusion(doc.leaves, 3)
		if err != nil {
			t.Fatal(err)
		}
		res := VerifyStandaloneApprovalV4(leaf, proof, doc.head, doc.signing.id, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || res.ApprovalSourceHistory != labelNotChecked {
			t.Fatalf("ok=%v history=%q errors=%v", res.OK, res.ApprovalSourceHistory, res.Errors)
		}
	})
	t.Run("standalone summary leaf fails validation with a pinned producer key", func(t *testing.T) {
		doc := newV4Builder(t).build()
		producer := newV4KeyPair("producer-k1", 55)
		leaf := *validSummaryLeafTypedV4(t, "tenant-a")
		leaf.Type = "bogus"
		leaf.ProducerSignature = &ProducerSignatureV4{
			Algorithm: HeadSignatureAlgorithm, KeyID: producer.id, Signature: []byte("sig"),
		}
		proof, err := hash.ProveInclusion(doc.leaves, 0)
		if err != nil {
			t.Fatal(err)
		}
		res := VerifyStandaloneSummaryV4(leaf, proof, doc.head, doc.signing.id, VerifyOptions{
			Keyring:                    doc.signing.keyring(),
			TrustedSummaryProducerKeys: producer.keyring(),
		})
		if res.OK || res.SummaryProducerAuthorship != labelFailed || !errsContain(res, "producer payload") {
			t.Fatalf("ok=%v authorship=%q errors=%v", res.OK, res.SummaryProducerAuthorship, res.Errors)
		}
	})
}

func TestV4SummaryInputRefusals(t *testing.T) {
	// localPrefix builds an export whose summary names a genuine signed
	// local-prefix head, then applies fn to the input before the final build.
	localPrefix := func(t *testing.T, fn func(sum *SummaryLeafViewV4)) *v4Built {
		t.Helper()
		b := newV4Builder(t)
		sum := validSummaryLeafTypedV4(t, b.tenant)
		b.specs = append(b.specs, v4SummarySpec(sum))
		b.localPrefixInputs = map[int]map[int]uint64{len(b.specs) - 1: {0: 1}}
		b.build() // fixes the genuine signed local-prefix input head
		b.localPrefixInputs = nil
		if fn != nil {
			fn(sum)
		}
		return b.build()
	}
	t.Run("local prefix head index disagrees with the prefix", func(t *testing.T) {
		doc := localPrefix(t, func(sum *SummaryLeafViewV4) { sum.Inputs[0].Head.Index = 99 })
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "input head index") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("local input key_id is not in the keyring", func(t *testing.T) {
		doc := localPrefix(t, func(sum *SummaryLeafViewV4) { sum.Inputs[0].KeyID = "ledger-k9" })
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "key_id") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("local input head signature does not verify", func(t *testing.T) {
		doc := localPrefix(t, func(sum *SummaryLeafViewV4) { sum.Inputs[0].Head.Signature = []byte("bad") })
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "input head signature") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("referenced export does not parse", func(t *testing.T) {
		b, tbDoc, _ := referencedSummaryBuilder(t)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "tb-current", Export: []byte("not an export"), Keyring: tbDoc.signing.keyring(),
			}},
		})
		if res.OK || !errsContain(res, "does not parse") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("limitations that are not a string array", func(t *testing.T) {
		b := newV4Builder(t)
		sum := validSummaryLeafTypedV4(t, b.tenant)
		sum.Profile = "aaes.other/v1"
		sum.Body = json.RawMessage(`{"limitations":{"x":1}}`)
		b.specs = append(b.specs, v4SummarySpec(sum))
		b.localPrefixInputs = map[int]map[int]uint64{len(b.specs) - 1: {0: 1}}
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !errsContain(res, "latest_state limitation") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}
