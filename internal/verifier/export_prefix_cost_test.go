package verifier

import (
	"fmt"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Every requested prefix size gets the root MerkleRoot would compute, and the
// walk stays near-linear. Before the frontier, n distinct sizes (one per
// unsigned anchor line) cost n²/2 leaf hashes: 20,000 sizes took about a
// minute, and a 1 GiB export could hold a million.
func TestPrefixFactsAreExactAndNearLinear(t *testing.T) {
	const n = 20000
	leaves := make([]string, n)
	decision := make([]bool, n)
	seq := make([]uint64, n)
	kinds := make([]string, n)
	sizes := make([]uint64, 0, n+2)
	for i := range leaves {
		leaves[i] = hash.SHA256Hex([]byte(fmt.Sprintf("leaf-%d", i)))
		decision[i], seq[i], kinds[i] = true, uint64(i+1), lineEntry
		sizes = append(sizes, uint64(i+1))
	}
	sizes = append(sizes, 0, n+5)
	start := time.Now()
	facts := factsForSizes(leaves, decision, seq, kinds, sizes, "")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("%d prefix sizes took %s", n, elapsed)
	}
	if len(facts) != n+1 {
		t.Fatalf("%d facts, want %d (sizes past the log are dropped)", len(facts), n+1)
	}
	for _, sz := range []uint64{0, 1, 2, 3, 7, 1000, 4097, n - 1, n} {
		if got, want := facts[sz].root, hash.MerkleRoot(leaves[:sz]); got != want {
			t.Fatalf("size %d: root %s, want %s", sz, got, want)
		}
	}
	if facts[n].lastDecision != n || !facts[n].hasDecision {
		t.Fatalf("size %d fact: %+v", n, facts[n])
	}
}
