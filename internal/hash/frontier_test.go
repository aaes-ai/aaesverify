package hash

import (
	"fmt"
	"testing"
)

// The frontier must agree with MerkleRoot on every prefix, including the
// odd sizes where the duplicate-last rule pads a level.
func TestMerkleFrontierMatchesMerkleRootOnEveryPrefix(t *testing.T) {
	var leaves []string
	var f MerkleFrontier
	if got, want := f.Root(), MerkleRoot(nil); got != want || f.Size() != 0 {
		t.Fatalf("empty frontier root %s, want %s", got, want)
	}
	for i := 0; i < 300; i++ {
		leaf := SHA256Hex([]byte(fmt.Sprintf("leaf-%d", i)))
		leaves = append(leaves, leaf)
		f.Append(leaf)
		if got, want := f.Root(), MerkleRoot(leaves); got != want || f.Size() != uint64(len(leaves)) {
			t.Fatalf("size %d: frontier root %s, MerkleRoot %s", len(leaves), got, want)
		}
	}
}
