package hash

// MerkleFrontier computes MerkleRoot of every prefix of a leaf list in one
// pass. It keeps the root of each complete power-of-two subtree on the right
// edge, so Append and Root cost O(log n) hashes. Recomputing MerkleRoot from
// scratch for every prefix costs O(n) each, and an export can name a prefix
// size per anchor line, which made verification quadratic in hostile input.
type MerkleFrontier struct {
	size uint64
	// nodes[j] is the root of the complete 2^j-leaf subtree ending at the
	// current size; it is meaningful only while bit j of size is set.
	nodes []string
}

// Size is the number of leaves appended so far.
func (f *MerkleFrontier) Size() uint64 { return f.size }

// Append adds the next leaf hash.
func (f *MerkleFrontier) Append(leafHex string) {
	node := leafHash(leafHex)
	j := 0
	for (f.size>>j)&1 == 1 {
		node = nodeHash(f.nodes[j], node)
		j++
	}
	if j == len(f.nodes) {
		f.nodes = append(f.nodes, "")
	}
	f.nodes[j] = node
	f.size++
}

// Root is MerkleRoot over the leaves appended so far. At each level the
// complete nodes are fixed; only the right-edge node built from the partial
// remainder changes, and it pairs with the last complete node when their
// count is odd, or duplicates itself when no complete node is left to pair.
func (f *MerkleFrontier) Root() string {
	if f.size == 0 {
		return MerkleRoot(nil)
	}
	partial := ""
	for j := 0; ; j++ {
		complete := f.size >> j
		switch {
		case complete == 0:
			return partial
		case complete == 1 && partial == "":
			return f.nodes[j]
		case complete&1 == 1 && partial != "":
			partial = nodeHash(f.nodes[j], partial)
		case complete&1 == 1:
			partial = nodeHash(f.nodes[j], f.nodes[j])
		case partial != "":
			partial = nodeHash(partial, partial)
		}
	}
}
