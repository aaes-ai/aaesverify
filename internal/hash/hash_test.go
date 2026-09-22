package hash

import (
	"math"
	"testing"
)

func TestCanonicalJSONDeterministic(t *testing.T) {
	a, err := CanonicalJSON(map[string]any{"b": 1, "a": "x", "c": []any{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != `{"a":"x","b":1,"c":[1,2]}` {
		t.Fatalf("unexpected canonical form: %s", a)
	}
	// Integral floats must not change the bytes.
	b, err := CanonicalJSON(map[string]any{"a": "x", "b": 1.0, "c": []any{1.0, 2.0}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(a) {
		t.Fatalf("integral floats changed encoding:\n%s\n%s", a, b)
	}
}

func TestCanonicalJSONRejectsNonFinite(t *testing.T) {
	if _, err := CanonicalJSON(map[string]any{"x": math.Inf(1)}); err == nil {
		t.Fatal("expected error for non-finite float")
	}
}

func TestChainIsOrderSensitive(t *testing.T) {
	h1 := Chain("", []byte("a"))
	if h1 != Chain("", []byte("a")) {
		t.Fatal("chain is not deterministic")
	}
	if h1 == Chain("", []byte("b")) {
		t.Fatal("chain ignores entry bytes")
	}
	if Chain("p1", []byte("a")) == Chain("p2", []byte("a")) {
		t.Fatal("chain ignores previous hash")
	}
}

func TestMerkleInclusionProofs(t *testing.T) {
	leaves := []string{"e0", "e1", "e2", "e3", "e4"} // odd count exercises duplicate-last
	root := MerkleRoot(leaves)
	for i := range leaves {
		p, err := ProveInclusion(leaves, uint64(i))
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		if !VerifyInclusion(leaves[i], p) {
			t.Fatalf("inclusion proof %d failed to verify", i)
		}
		if p.RootHash != root {
			t.Fatalf("proof %d root mismatch", i)
		}
	}
}

// Every tree width from 1 to 17 must produce verifiable proofs, including the
// duplicated-last node at odd widths.
func TestMerkleProofsAllWidths(t *testing.T) {
	for n := 1; n <= 17; n++ {
		leaves := make([]string, n)
		for i := range leaves {
			leaves[i] = "leaf-" + string(rune('a'+i))
		}
		root := MerkleRoot(leaves)
		for i := range leaves {
			p, err := ProveInclusion(leaves, uint64(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(leaves[i], p) {
				t.Fatalf("n=%d i=%d: proof failed to verify against root %s", n, i, root)
			}
		}
	}
}

func TestMerkleTamperDetection(t *testing.T) {
	leaves := []string{"e0", "e1", "e2"}
	p, err := ProveInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyInclusion("tampered", p) {
		t.Fatal("tampered leaf verified against proof")
	}
}

func TestConsistencyProof(t *testing.T) {
	old := []string{"a", "b"}
	nw := []string{"a", "b", "c", "d"}
	p, err := ProveConsistency(old, nw)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyConsistency(p, MerkleRoot(old), MerkleRoot(nw)) {
		t.Fatal("consistency proof failed")
	}
	if _, err := ProveConsistency(nw, old); err == nil {
		t.Fatal("expected error when old tree is larger")
	}
	notPrefix := []string{"z", "b"}
	if _, err := ProveConsistency(notPrefix, nw); err == nil {
		t.Fatal("expected error for non-prefix tree")
	}
}
