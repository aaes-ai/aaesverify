package hash

import (
	"math"
	"testing"
)

func TestProveInclusionRejectsAnIndexOutsideTheTree(t *testing.T) {
	leaves := []string{"a", "b"}
	if _, err := ProveInclusion(leaves, 2); err == nil {
		t.Fatal("index equal to tree size was accepted")
	}
	if _, err := ProveInclusion(leaves, 99); err == nil {
		t.Fatal("index far past the tree was accepted")
	}
	if _, err := ProveInclusion(nil, 0); err == nil {
		t.Fatal("index 0 on an empty tree was accepted")
	}
}

func TestVerifyInclusionRejectsSelfSiblingTampering(t *testing.T) {
	leaves := []string{"e0", "e1", "e2"}
	p, err := ProveInclusion(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(leaves[2], p) {
		t.Fatal("valid last-leaf proof on an odd-width tree failed")
	}

	wrongFlag := p
	wrongFlag.SelfSiblings = append([]bool(nil), p.SelfSiblings...)
	wrongFlag.SelfSiblings[0] = !wrongFlag.SelfSiblings[0]
	if VerifyInclusion(leaves[2], wrongFlag) {
		t.Fatal("a proof whose self-sibling flag disagrees with tree geometry verified")
	}

	populated := p
	populated.Siblings = append([]string(nil), p.Siblings...)
	populated.Siblings[0] = "deadbeef"
	if VerifyInclusion(leaves[2], populated) {
		t.Fatal("a duplicate-last step that carried a sibling value verified")
	}
}

func TestVerifyInclusionRejectsImpossibleProofs(t *testing.T) {
	leaves := []string{"e0", "e1", "e2"}
	p, err := ProveInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(leaves[1], p) {
		t.Fatal("valid proof failed")
	}
	badIndex := p
	badIndex.Index = badIndex.TreeSize
	if VerifyInclusion(leaves[1], badIndex) {
		t.Fatal("a proof whose index is past tree size verified")
	}
	mismatch := p
	mismatch.SelfSiblings = mismatch.SelfSiblings[:0]
	if VerifyInclusion(leaves[1], mismatch) {
		t.Fatal("a proof whose sibling and self-sibling slices disagree in length verified")
	}
	paired := []string{"e0", "e1"}
	pairProof, err := ProveInclusion(paired, 0)
	if err != nil {
		t.Fatal(err)
	}
	emptySib := pairProof
	emptySib.Siblings = append([]string(nil), pairProof.Siblings...)
	emptySib.Siblings[0] = ""
	if VerifyInclusion(paired[0], emptySib) {
		t.Fatal("a missing sibling at a paired level verified")
	}
}

func TestVerifyInclusionRejectsAProofForADifferentTreePosition(t *testing.T) {
	// A valid two-leaf proof for index 0 used to verify unchanged with Index=2
	// and TreeSize=3: only the low index bit was consumed, so the path still
	// hashed to the two-leaf root. The trusted head is the two-leaf tree; a
	// proof that claims a third leaf is a different tree.
	leaves := []string{"e0", "e1"}
	p, err := ProveInclusion(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(leaves[0], p) {
		t.Fatal("valid two-leaf proof failed")
	}
	moved := p
	moved.Index = 2
	moved.TreeSize = 3
	if VerifyInclusion(leaves[0], moved) {
		t.Fatal("a two-leaf path verified as a proof that index 2 is in a three-leaf tree")
	}
	head := TreeHead{TreeSize: uint64(len(leaves)), RootHash: MerkleRoot(leaves)}
	if !VerifyInclusionAgainst(leaves[0], p, head) {
		t.Fatal("valid proof failed against its own tree head")
	}
	three := TreeHead{TreeSize: 3, RootHash: MerkleRoot([]string{"e0", "e1", "e2"})}
	if VerifyInclusionAgainst(leaves[0], p, three) {
		t.Fatal("a two-leaf proof verified against a three-leaf head")
	}
	forgedHead := TreeHead{TreeSize: 3, RootHash: p.RootHash}
	if VerifyInclusionAgainst(leaves[0], moved, forgedHead) {
		t.Fatal("a two-leaf path verified against a head that claimed three leaves and the two-leaf root")
	}
}

func TestVerifyConsistencyRejectsAFromSizeLargerThanToSize(t *testing.T) {
	// Sizes are consistent with the slice lengths so the first length check
	// passes; FromSize > ToSize must still fail closed.
	forged := ConsistencyProof{
		FromSize:  2,
		ToSize:    1,
		FromRoot:  MerkleRoot([]string{"a", "b"}),
		ToRoot:    MerkleRoot([]string{"a"}),
		OldLeaves: []string{"a", "b"},
		NewLeaves: []string{"a"},
	}
	if VerifyConsistency(forged, forged.FromRoot, forged.ToRoot) {
		t.Fatal("a proof claiming the older tree is larger than the newer one verified")
	}
}

func TestMerkleGeometryOddWidthsPowersOfTwoAndUint64Boundary(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 16} {
		leaves := make([]string, n)
		for i := range leaves {
			leaves[i] = "leaf-" + string(rune('a'+i))
		}
		wantDepth := merkleProofDepth(uint64(n))
		for i := range leaves {
			p, err := ProveInclusion(leaves, uint64(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if len(p.Siblings) != wantDepth {
				t.Fatalf("n=%d i=%d: siblings=%d depth=%d", n, i, len(p.Siblings), wantDepth)
			}
			if !VerifyInclusion(leaves[i], p) {
				t.Fatalf("n=%d i=%d: valid proof failed", n, i)
			}
		}
	}

	if merkleProofDepth(0) != 0 || merkleProofDepth(1) != 0 {
		t.Fatalf("empty/single depth = %d / %d", merkleProofDepth(0), merkleProofDepth(1))
	}
	if merkleProofDepth(math.MaxUint64) != 64 {
		t.Fatalf("MaxUint64 depth = %d, want 64 (must not wrap to 1)", merkleProofDepth(math.MaxUint64))
	}
	if merkleProofDepth(1<<63) != 63 {
		t.Fatalf("2^63 depth = %d, want 63", merkleProofDepth(1<<63))
	}

	// A one-sibling proof at MaxUint64 used to pass the depth check because
	// (MaxUint64+1)/2 wrapped to 0 and the depth loop returned 1.
	wrapped := InclusionProof{
		Index: 0, TreeSize: math.MaxUint64,
		Siblings: []string{"x"}, SelfSiblings: []bool{false}, RootHash: "x",
	}
	if VerifyInclusion("leaf", wrapped) {
		t.Fatal("a 1-level proof for MaxUint64 verified")
	}
}
