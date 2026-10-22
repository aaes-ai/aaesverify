package verifier

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// TestV4GoldenVectors pins the canonical encodings of a complete v4 export
// (design section 9.1): one decision entry, one receipt, one approval and one
// summary leaf, a K1 anchor with a K2 final head (rotation), and a
// receipt+parent proof bundle. Every key is seed-derived and every timestamp
// fixed, so the pinned values are stable; any drift in CJSON, the chain, the
// Merkle conventions or the head payload turns this test red.
func TestV4GoldenVectors(t *testing.T) {
	k1 := newV4KeyPair("ledger-k1", 11)
	k2 := newV4KeyPair("ledger-k2", 22)
	b := newV4Builder(t) // tenant-a: entries 1-2, receipt rc-1, approval ap-1
	b.signing = k2       // the final head is signed by K2
	sum := validSummaryLeafTypedV4(t, b.tenant)
	sum.Inputs[0].KeyID = "ledger-k2" // fixLocalPrefixHeads signs with b.signing
	b.specs = append(b.specs, v4SummarySpec(sum))
	b.localPrefixInputs = map[int]map[int]uint64{len(b.specs) - 1: {0: 1}}
	b.anchors = append(b.anchors, v4AnchorSpec{key: k1, treeSize: 2})
	doc := b.build()

	wantLeaves := []string{
		"bd12b83c8ec154f4640723a05011378360e232530a23317e4b87989216b820d1",
		"d4efcc7bd0d2b9753941663bf2ce278f887ff34c54d84282fc2847fbec5a16cf",
		"49f8b9900f191cbe5ceabd95d350aed5ff4151de095f6ebe563ff8ec96d47360",
		"2cecf972f3b662492578ec33da15681c2c1f543936ed70ac7719ad48dd0e13a7",
		"85a69565ea6c9bb13ca7cc67dc579786d04b93fb3963c10c70b0e277ec782f62",
	}
	wantChains := []string{
		"6bf6e313d71945592be77c6d3921b932e4542fcca65519200ff94ef9814760fe",
		"f0cede1da31dfa04eb0a51aab734e0e19d3e8be5c284dcbb4e17e4de6b1d21d0",
		"ff0e57608008eaba4801f8d2b383750da716e21dead2fa3bca8c89c8f1301d7f",
		"5b74e572687466ea2ce47f0a8f7b0cf4e45a09e39cdf8cb7c7d3410f3682321f",
		"fe91e023c6c838483b3748dee8e53558d46d4d8301dc8f0883f12261ffe072f0",
	}
	for i := range wantLeaves {
		if doc.leaves[i] != wantLeaves[i] || doc.chains[i] != wantChains[i] {
			t.Fatalf("leaf/chain %d drifted:\nleaf  %s\nchain %s", i, doc.leaves[i], doc.chains[i])
		}
	}
	if doc.head.RootHash != "bfb46603adc5f45a90bd129fcf022b3dd9343775cfd577018f9483774680ad53" {
		t.Fatalf("root drifted: %s", doc.head.RootHash)
	}
	const wantHeadSig = "0093a0838f41bd0fcf172e91508b66ae4ea2f5b82be45142cad85cf5bc4b99aae0390bebb8338a23fa862ed0e64bba3e36b5a86568157eb120340d6246a2d60b"
	if got := hex.EncodeToString(doc.head.Signature); got != wantHeadSig {
		t.Fatalf("K2 head signature drifted: %s", got)
	}
	if doc.anchorHeads[0].RootHash != "69286f49b9cb487c2154fbd11f48f798c15ef35ab77912241d2647faeb5a2cb2" {
		t.Fatalf("K1 anchor root drifted: %s", doc.anchorHeads[0].RootHash)
	}
	const wantAnchorSig = "623e8bbb21ce08c471b41dae26ee87e3fa48b99d141019f6eed9e3ff03760520e57f3674b6c3740b9b70759aa5274e679ae3023ea916b4aa4b103e0113236a08"
	if got := hex.EncodeToString(doc.anchorHeads[0].Signature); got != wantAnchorSig {
		t.Fatalf("K1 anchor signature drifted: %s", got)
	}

	// The receipt preimage pins the required-present zero encodings of
	// section 4.5 (class, rail_confirmed, the three zero timestamps) and the
	// exclusion of chain_hash and leaf.
	exp, err := LoadExportReader(strings.NewReader(doc.text))
	if err != nil {
		t.Fatal(err)
	}
	pre, err := exp.Receipts[0].PreimageV4()
	if err != nil {
		t.Fatal(err)
	}
	wantPre := `{"linked_at":"2026-02-03T04:07:06Z","receipt":{"class":2,"confirmed_at":"0001-01-01T00:00:00Z","grant_id":"grant-2","intent_id":"intent-tenant-a-2","issued_at":"2026-02-03T04:06:06Z","observed_at":"0001-01-01T00:00:00Z","rail_confirmed":true,"receipt_id":"rc-1","record_hash":"5c73ae90ea82ce8865d74dbce1cf9011848ce68bea1dbb120bed9af9fda1b063","reported_at":"0001-01-01T00:00:00Z","tenant_id":"tenant-a"},"record_hash":"5c73ae90ea82ce8865d74dbce1cf9011848ce68bea1dbb120bed9af9fda1b063","schema":"aaes.export/v4","sequence":2,"type":"receipt"}`
	if string(pre) != wantPre {
		t.Fatalf("receipt preimage drifted:\n%s", pre)
	}

	// The bundle proof pins the inclusion-proof encoding against this tree.
	proof, err := hash.ProveInclusion(doc.leaves, 2)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Index != 2 || proof.TreeSize != 5 || len(proof.Siblings) != 3 ||
		proof.Siblings[0] != "daaa1eb40d7235c1eb5e9314de84b58d9cd6763db419f07c0e78c4acd8ce4ea9" ||
		proof.RootHash != doc.head.RootHash {
		t.Fatalf("receipt proof drifted: %+v", proof)
	}

	// And the pinned bytes verify end to end in expected-final mode with the
	// rotation-aware keyring.
	res := verifyV4(t, doc.text, VerifyOptions{
		Keyring:       mergeKeyringsV4(k1, k2),
		ExpectedFinal: v4Pin(doc.head),
	})
	if !res.OK || res.ExpectedFinalHead != labelVerified {
		t.Fatalf("golden export failed verification: %v", res.Errors)
	}
}
