package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Summary input integrity and freshness (design sections 5.3 and 9.4):
// local-prefix and referenced-export resolution, per-input freshness, and the
// section 5.2 limitation requirements.

// newV4BuilderForTenant is a minimal one-decision export for a tenant.
func newV4BuilderForTenant(t *testing.T, tenant string, seed byte) *v4ExportBuilder {
	t.Helper()
	return &v4ExportBuilder{
		t:         t,
		tenant:    tenant,
		exported:  v4Base.Add(time.Hour),
		preAnchor: true,
		embedKey:  true,
		signing:   newV4KeyPair("ledger-"+tenant, seed),
		specs:     []v4Spec{v4EntrySpec(v4Entry(tenant, 1, v4Base))},
	}
}

// referencedSummaryBuilder builds a tenant-a export whose summary names the
// final head of the tenant-b export as input "tb-current".
func referencedSummaryBuilder(t *testing.T) (*v4ExportBuilder, *v4Built, *SummaryLeafViewV4) {
	t.Helper()
	tb := newV4BuilderForTenant(t, "tenant-b", 21)
	tbDoc := tb.build()
	b := newV4Builder(t)
	sum := validSummaryLeafTypedV4(t, b.tenant)
	sum.Inputs = []SummaryInputV4{{
		InputID:  "tb-current",
		Schema:   ExportSchemaV4,
		TenantID: "tenant-b",
		KeyID:    tb.signing.id,
		Head:     tbDoc.head,
	}}
	sum.Body = json.RawMessage(`{"limitations":[]}`)
	b.specs = append(b.specs, v4SummarySpec(sum))
	return b, tbDoc, sum
}

func TestSummaryInputReferencedExport(t *testing.T) {
	t.Run("fresh referenced v4 input verifies", func(t *testing.T) {
		b, tbDoc, _ := referencedSummaryBuilder(t)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring:       doc.signing.keyring(),
			ExpectedFinal: v4Pin(doc.head),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "tb-current", Export: []byte(tbDoc.text),
				Keyring: tbDoc.signing.keyring(), ExpectedFinal: v4Pin(tbDoc.head),
			}},
		})
		if !res.OK || res.SummaryAncestry != labelVerified {
			t.Fatalf("ok=%v ancestry=%q errors=%v", res.OK, res.SummaryAncestry, res.Errors)
		}
		if len(res.SummaryInputs) != 1 || res.SummaryInputs[0].LatestState != labelVerified {
			t.Fatalf("inputs=%+v", res.SummaryInputs)
		}
	})

	t.Run("unpinned referenced input stays not_checked with limitation", func(t *testing.T) {
		b, tbDoc, sum := referencedSummaryBuilder(t)
		sum.Body = json.RawMessage(`{"limitations":["input tb-current: latest_state not_checked, no expected-final pin supplied"]}`)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "tb-current", Export: []byte(tbDoc.text), Keyring: tbDoc.signing.keyring(),
			}},
		})
		if !res.OK {
			t.Fatalf("integrity should pass: %v", res.Errors)
		}
		if res.SummaryInputs[0].LatestState != labelNotChecked || res.SummaryInputs[0].Integrity != labelVerified {
			t.Fatalf("inputs=%+v", res.SummaryInputs)
		}
	})

	t.Run("missing referenced export", func(t *testing.T) {
		b, _, _ := referencedSummaryBuilder(t)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "no referenced export supplied") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("head mismatch against referenced export", func(t *testing.T) {
		b, tbDoc, sum := referencedSummaryBuilder(t)
		sum.Inputs[0].Head.SignedAt = sum.Inputs[0].Head.SignedAt.Add(time.Second)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "tb-current", Export: []byte(tbDoc.text), Keyring: tbDoc.signing.keyring(),
			}},
		})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "neither the referenced export's verified final head nor one of its anchors") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("unverified referenced export", func(t *testing.T) {
		b, tbDoc, _ := referencedSummaryBuilder(t)
		tampered := strings.Replace(tbDoc.text, `"allowed":true`, `"allowed":false`, 1)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "tb-current", Export: []byte(tampered), Keyring: tbDoc.signing.keyring(),
			}},
		})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "referenced export does not verify") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("missing input key in referenced keyring", func(t *testing.T) {
		b, tbDoc, _ := referencedSummaryBuilder(t)
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "tb-current", Export: []byte(tbDoc.text), Keyring: newV4KeyPair("ledger-k9", 77).keyring(),
			}},
		})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "key_id") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})

	t.Run("anchor-only match is not fresh", func(t *testing.T) {
		tb := newV4BuilderForTenant(t, "tenant-b", 21)
		tb.anchors = append(tb.anchors, v4AnchorSpec{key: tb.signing, treeSize: 1})
		tbDoc := tb.build()
		b := newV4Builder(t)
		sum := validSummaryLeafTypedV4(t, b.tenant)
		sum.Inputs = []SummaryInputV4{{
			InputID: "tb-anchor", Schema: ExportSchemaV4, TenantID: "tenant-b",
			KeyID: tb.signing.id, Head: tbDoc.anchorHeads[0],
		}}
		sum.Body = json.RawMessage(`{"limitations":["input tb-anchor matched an anchor, not the final head: latest_state not_checked"]}`)
		b.specs = append(b.specs, v4SummarySpec(sum))
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{
			Keyring: doc.signing.keyring(),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "tb-anchor", Export: []byte(tbDoc.text),
				Keyring: tbDoc.signing.keyring(), ExpectedFinal: v4Pin(tbDoc.head),
			}},
		})
		if !res.OK || res.SummaryInputs[0].LatestState != labelNotChecked {
			t.Fatalf("ok=%v inputs=%+v errors=%v", res.OK, res.SummaryInputs, res.Errors)
		}
	})

	t.Run("referenced legacy v3 export needs both limitations", func(t *testing.T) {
		raw, err := os.ReadFile("../store_versions/testdata/export_v3.jsonl")
		if err != nil {
			t.Skip("retained v3 fixture unavailable:", err)
		}
		pubHex, err := os.ReadFile("../store_versions/testdata/public_key.hex")
		if err != nil {
			t.Skip(err)
		}
		pub, err := ParsePublicKey(strings.TrimSpace(string(pubHex)))
		if err != nil {
			t.Fatal(err)
		}
		refExp, err := LoadExportReader(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		b := newV4Builder(t)
		sum := validSummaryLeafTypedV4(t, b.tenant)
		sum.Inputs = []SummaryInputV4{{
			InputID: "legacy-v3", Schema: ExportSchemaV3, TenantID: refExp.Header.TenantID,
			KeyID: "ledger-legacy", Head: refExp.Header.Head,
		}}
		sum.Body = json.RawMessage(`{"limitations":["legacy-v3 signs decision entries only; receipt/approval fields are not signed", "legacy-v3 is historical evidence: latest_state not_checked"]}`)
		b.specs = append(b.specs, v4SummarySpec(sum))
		doc := b.build()
		opts := VerifyOptions{
			Keyring: doc.signing.keyring(),
			SummaryReferences: []SummaryReferenceV4{{
				InputID: "legacy-v3", Export: raw, Keyring: map[string]ed25519.PublicKey{"ledger-legacy": ed25519.PublicKey(pub)},
			}},
		}
		res := verifyV4(t, doc.text, opts)
		if !res.OK || res.SummaryInputs[0].Integrity != labelVerified || res.SummaryInputs[0].LatestState != labelNotChecked {
			t.Fatalf("ok=%v inputs=%+v errors=%v", res.OK, res.SummaryInputs, res.Errors)
		}
		// Dropping the limitations entirely must fail both requirements.
		sum.Body = json.RawMessage(`{"limitations":[]}`)
		doc = b.build()
		if res := verifyV4(t, doc.text, opts); res.OK {
			t.Fatal("a legacy input without the explicit limitations passed")
		}
	})
}

func TestSummaryInputLocalPrefix(t *testing.T) {
	build := func(t *testing.T, size uint64) (*v4ExportBuilder, *v4Built) {
		t.Helper()
		b := newV4Builder(t)
		sum := validSummaryLeafTypedV4(t, b.tenant)
		b.specs = append(b.specs, v4SummarySpec(sum))
		b.localPrefixInputs = map[int]map[int]uint64{len(b.specs) - 1: {0: size}}
		return b, b.build()
	}
	t.Run("self-reference refused", func(t *testing.T) {
		b, _ := build(t, 1)
		// Push the input's tree size past the leaves before the summary.
		b.localPrefixInputs[len(b.specs)-1][0] = uint64(len(b.specs))
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "self-reference or later state") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("wrong prefix root refused", func(t *testing.T) {
		b, _ := build(t, 2)
		sum := b.specs[len(b.specs)-1].summary
		sum.Inputs[0].Head.RootHash = hash.SHA256Hex([]byte("wrong"))
		b.localPrefixInputs = nil // keep the mutation; do not re-derive the head
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "prefix root") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("legacy local input over typed prefix refused", func(t *testing.T) {
		b, _ := build(t, 3) // prefix covers a receipt leaf
		sum := b.specs[len(b.specs)-1].summary
		sum.Inputs[0].Schema = ExportSchemaV3
		sum.Inputs[0].Head.Schema = ""
		sum.Body = json.RawMessage(`{"limitations":["self-prior signs decision entries only", "self-prior: latest_state not_checked"]}`)
		b.localPrefixInputs = nil
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "decision-only prefix") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("missing local key refused", func(t *testing.T) {
		_, doc := build(t, 1)
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: newV4KeyPair("ledger-k9", 77).keyring()})
		if res.OK {
			t.Fatal("unknown input key passed")
		}
	})
	t.Run("duplicate summary_id refused", func(t *testing.T) {
		b, _ := build(t, 1)
		second := validSummaryLeafTypedV4(t, b.tenant)
		second.Inputs[0].Head = b.specs[len(b.specs)-1].summary.Inputs[0].Head
		b.specs = append(b.specs, v4SummarySpec(second))
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "duplicates the summary_id") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
}

func TestStandaloneSummaryV4InclusionOnly(t *testing.T) {
	b := newV4Builder(t)
	sum := validSummaryLeafTypedV4(t, b.tenant)
	b.specs = append(b.specs, v4SummarySpec(sum))
	b.localPrefixInputs = map[int]map[int]uint64{len(b.specs) - 1: {0: 1}}
	b.build() // fixes the genuine local-prefix input head
	b.localPrefixInputs = nil
	producer := newV4KeyPair("producer-k1", 55)
	sum.ChainHash = "claim"
	sum.Leaf = "claim" // exporter claims are excluded from the preimage
	payload, err := sum.SummaryProducerPayloadV4()
	if err != nil {
		t.Fatal(err)
	}
	sum.ProducerSignature = &ProducerSignatureV4{Algorithm: HeadSignatureAlgorithm, KeyID: producer.id, Signature: ed25519.Sign(producer.priv, payload)}
	doc := b.build()
	exp, err := LoadExportReader(strings.NewReader(doc.text))
	if err != nil {
		t.Fatal(err)
	}
	leaf := exp.Summaries[0]
	proof, err := hash.ProveInclusion(doc.leaves, uint64(len(doc.leaves)-1))
	if err != nil {
		t.Fatal(err)
	}
	opts := VerifyOptions{Keyring: doc.signing.keyring(), TrustedSummaryProducerKeys: producer.keyring()}
	res := VerifyStandaloneSummaryV4(leaf, proof, doc.head, doc.signing.id, opts)
	if !res.OK || res.LeafInclusionVerified == nil || !*res.LeafInclusionVerified {
		t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
	}
	if res.SummaryAncestry != labelNotChecked || res.SummaryProfile != labelNotChecked {
		t.Fatalf("ancestry=%q profile=%q: standalone inclusion must not upgrade either", res.SummaryAncestry, res.SummaryProfile)
	}
	if res.SummaryProducerAuthorship != labelVerified {
		t.Fatalf("producer authorship=%q, want verified under the pinned producer key", res.SummaryProducerAuthorship)
	}
	// Without the pin, authorship is unverified but inclusion still holds.
	res = VerifyStandaloneSummaryV4(leaf, proof, doc.head, doc.signing.id, VerifyOptions{Keyring: doc.signing.keyring()})
	if !res.OK || res.SummaryProducerAuthorship != labelNotChecked {
		t.Fatalf("unpinned: ok=%v authorship=%q errors=%v", res.OK, res.SummaryProducerAuthorship, res.Errors)
	}
	// A forged producer signature under the pinned key fails.
	leaf.ProducerSignature.Signature = ed25519.Sign(newV4KeyPair("forger", 99).priv, payload)
	if res := VerifyStandaloneSummaryV4(leaf, proof, doc.head, doc.signing.id, opts); res.OK {
		t.Fatal("forged producer signature passed")
	}
}
