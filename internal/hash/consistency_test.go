package hash

import "testing"

// A consistency proof must not verify for two trees that are not in a prefix
// relation. The earlier implementation returned only the new root and therefore
// verified forged proofs; this test is the regression that catches that.
func TestConsistencyRejectsForgedProof(t *testing.T) {
	leavesA := []string{"a", "b", "c", "d"}
	leavesB := []string{"w", "x", "y", "z"} // unrelated to A

	forged := ConsistencyProof{
		FromSize:  uint64(len(leavesA)),
		ToSize:    uint64(len(leavesB)),
		FromRoot:  MerkleRoot(leavesA),
		ToRoot:    MerkleRoot(leavesB),
		OldLeaves: leavesA,
		NewLeaves: leavesB, // not a prefix extension of A
	}
	if VerifyConsistency(forged, MerkleRoot(leavesA), MerkleRoot(leavesB)) {
		t.Fatal("forged consistency proof verified over unrelated trees")
	}
}

func TestConsistencyRejectsSwappedRoots(t *testing.T) {
	old := []string{"a", "b"}
	nw := []string{"a", "b", "c"}
	p, err := ProveConsistency(old, nw)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyConsistency(p, MerkleRoot(nw), MerkleRoot(old)) {
		t.Fatal("proof verified with roots swapped")
	}
	if !VerifyConsistency(p, MerkleRoot(old), MerkleRoot(nw)) {
		t.Fatal("valid proof failed to verify")
	}
}

func TestConsistencyRejectsTruncatedLeafMaterial(t *testing.T) {
	old := []string{"a", "b"}
	nw := []string{"a", "b", "c", "d"}
	p, err := ProveConsistency(old, nw)
	if err != nil {
		t.Fatal(err)
	}
	// A proof that omits material cannot be checked, so it must be refused rather
	// than accepted on the strength of its claimed roots.
	p.NewLeaves = p.NewLeaves[:2]
	if VerifyConsistency(p, MerkleRoot(old), MerkleRoot(nw)) {
		t.Fatal("truncated proof material was accepted")
	}
}

func TestConsistencyAcrossGrowth(t *testing.T) {
	// Every prefix length of a growing log must produce a proof that verifies.
	full := []string{"e0", "e1", "e2", "e3", "e4", "e5", "e6"}
	for m := 0; m <= len(full); m++ {
		for n := m; n <= len(full); n++ {
			old := full[:m]
			nw := full[:n]
			p, err := ProveConsistency(old, nw)
			if err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			if !VerifyConsistency(p, MerkleRoot(old), MerkleRoot(nw)) {
				t.Fatalf("m=%d n=%d: valid proof rejected", m, n)
			}
		}
	}
}
