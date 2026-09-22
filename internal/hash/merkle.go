package hash

import (
	"fmt"
	"time"
)

// TreeHead is a signed commitment to the log state at a point in time.
type TreeHead struct {
	// LogID identifies the log this head belongs to, and it is INSIDE the
	// signed payload (the canonical bytes HeadPayload covers). Without it the
	// payload is only {index, root_hash, tree_size, signed_at}; for an empty
	// tree those collapse to constants every log shares, and a head signed by
	// one log's key — together with a witness countersignature over it — could
	// be replayed as an anchor of a different log run under the same key. The
	// value is derived from the tenant id by DeriveLogID, the one helper both
	// the producer and the offline verifier call, so the two sides cannot
	// drift onto different derivations. Heads written before the field
	// existed canonicalise with an empty log_id; verifiers reject those as
	// legacy material rather than treating them as naming any log.
	//
	// The tag deliberately has no omitempty: log_id is always present in the
	// canonical bytes, so removing it is a visible signature break rather
	// than a quiet return to the legacy encoding.
	LogID     string    `json:"log_id"`
	Index     uint64    `json:"index"`
	RootHash  string    `json:"root_hash"`
	TreeSize  uint64    `json:"tree_size"`
	SignedAt  time.Time `json:"signed_at"`
	Signature []byte    `json:"signature,omitempty"`
}

// InclusionProof proves a leaf is in the tree.
//
// SelfSiblings[i] marks a level where the node had no sibling and was hashed
// with itself (the duplicate-last convention). The verifier must substitute the
// hash it has just computed rather than a recorded value, because the recorded
// value lives at the child level and the verifier holds the parent.
type InclusionProof struct {
	Index        uint64   `json:"index"`
	TreeSize     uint64   `json:"tree_size"`
	Siblings     []string `json:"siblings"`
	SelfSiblings []bool   `json:"self_siblings"`
	RootHash     string   `json:"root_hash"`
}

// ConsistencyProof proves an older tree is a prefix of a newer one.
//
// The proof carries the old leaves and the leaves added since. The verifier
// recomputes both roots from them, so a forged proof cannot verify: without the
// leaf material a verifier has nothing to check the claims against.
//
// Trade-off, stated deliberately: this is an audit-scale proof, not a compact
// RFC 6962 proof. It is O(n) in tree size rather than O(log n). That is
// acceptable while a tenant's log is measured in millions of short hashes, and
// it buys a verifier simple enough for a customer's auditor to read. If log size
// becomes a problem, move to compact CT proofs rather than weakening the check.
type ConsistencyProof struct {
	FromSize  uint64   `json:"from_size"`
	ToSize    uint64   `json:"to_size"`
	FromRoot  string   `json:"from_root"`
	ToRoot    string   `json:"to_root"`
	OldLeaves []string `json:"old_leaves"`
	NewLeaves []string `json:"new_leaves"`
}

func leafHash(leafHex string) string { return SHA256Hex([]byte("leaf:" + leafHex)) }

func nodeHash(l, r string) string { return SHA256Hex([]byte("node:" + l + ":" + r)) }

// MerkleRoot computes the root over ordered leaf hashes. Levels with an odd
// number of nodes duplicate their last node before pairing.
func MerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return SHA256Hex([]byte("aaes/empty"))
	}
	level := make([]string, len(leaves))
	for i, l := range leaves {
		level[i] = leafHash(l)
	}
	for len(level) > 1 {
		level = parentLevel(level)
	}
	return level[0]
}

func parentLevel(level []string) []string {
	next := make([]string, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		if i+1 < len(level) {
			next = append(next, nodeHash(level[i], level[i+1]))
		} else {
			next = append(next, nodeHash(level[i], level[i]))
		}
	}
	return next
}

// ProveInclusion returns the audit path for the leaf at index.
func ProveInclusion(leaves []string, index uint64) (InclusionProof, error) {
	if index >= uint64(len(leaves)) {
		return InclusionProof{}, fmt.Errorf("hash: index %d out of range for %d leaves", index, len(leaves))
	}
	level := make([]string, len(leaves))
	for i, l := range leaves {
		level[i] = leafHash(l)
	}
	idx := index
	var siblings []string
	var self []bool
	for len(level) > 1 {
		next := parentLevel(level)
		if idx%2 == 0 {
			if idx+1 < uint64(len(level)) {
				siblings = append(siblings, level[idx+1])
				self = append(self, false)
			} else {
				// Duplicated last node: record a placeholder and mark it.
				siblings = append(siblings, "")
				self = append(self, true)
			}
		} else {
			siblings = append(siblings, level[idx-1])
			self = append(self, false)
		}
		idx /= 2
		level = next
	}
	return InclusionProof{
		Index:        index,
		TreeSize:     uint64(len(leaves)),
		Siblings:     siblings,
		SelfSiblings: self,
		RootHash:     MerkleRoot(leaves),
	}, nil
}

// merkleProofDepth is the number of parent steps a tree of the given size takes
// to reach a single root. It is the length ProveInclusion writes, and the
// verifier must require exactly that many levels or a proof for a smaller
// tree can be presented as a proof for a larger one.
// ceilHalf is overflow-safe ceiling division by two: (width+1)/2 wraps to 0
// at math.MaxUint64, which made a 2^64-1 tree look like depth 1.
func ceilHalf(width uint64) uint64 {
	return width/2 + width%2
}

func merkleProofDepth(treeSize uint64) int {
	if treeSize <= 1 {
		return 0
	}
	depth := 0
	for treeSize > 1 {
		depth++
		treeSize = ceilHalf(treeSize)
	}
	return depth
}

// VerifyInclusion recomputes the root from a leaf and its audit path.
//
// Level width is tracked with the index so a self-sibling flag is derived
// from the geometry (duplicate-last at an odd width) rather than believed, the
// path must contain exactly the levels a tree of that size needs, and it must
// finish on a single root. Callers that hold a trusted tree head should use
// VerifyInclusionAgainst so a proof cannot name a different size or root than
// the head committed to.
func VerifyInclusion(leafHex string, p InclusionProof) bool {
	if p.TreeSize == 0 || p.Index >= p.TreeSize {
		return false
	}
	if len(p.Siblings) != len(p.SelfSiblings) {
		return false
	}
	if len(p.Siblings) != merkleProofDepth(p.TreeSize) {
		return false
	}
	h := leafHash(leafHex)
	idx := p.Index
	width := p.TreeSize
	for i, sib := range p.Siblings {
		self := width%2 == 1 && idx == width-1
		if p.SelfSiblings[i] != self {
			return false
		}
		if self {
			// ProveInclusion records no sibling value at a duplicate-last
			// position; the hash to pair is the node the verifier just computed.
			if sib != "" {
				return false
			}
			sib = h
		} else if sib == "" {
			return false
		}
		if idx%2 == 0 {
			h = nodeHash(h, sib)
		} else {
			h = nodeHash(sib, h)
		}
		idx /= 2
		width = ceilHalf(width)
	}
	if width != 1 {
		return false
	}
	return h == p.RootHash
}

// VerifyInclusionAgainst is VerifyInclusion bound to a trusted tree head.
// A proof whose size or root disagrees with the head is refused even if the
// path hashes to the proof's own claimed root.
func VerifyInclusionAgainst(leafHex string, p InclusionProof, head TreeHead) bool {
	if head.TreeSize == 0 || p.TreeSize != head.TreeSize || p.RootHash != head.RootHash {
		return false
	}
	return VerifyInclusion(leafHex, p)
}

// ProveConsistency proves that oldLeaves is an exact prefix of newLeaves.
//
// Status: no production caller. It is kept because docs/INTERFACES.md
// section 5 freezes it into the published hash API and ADR-003/ADR-006 cite
// it as the closed "vacuous consistency proof" finding, not because any
// export path uses it. The property an auditor actually relies on -- that
// each anchor's signed root is the root of a genuine prefix of THIS export's
// entries -- is enforced where it counts, at verification time, by
// internal/verifier's checkExportAnchor recomputing every anchor root over
// the export's own entry prefix (verifier/export_anchor.go); a proof object
// carried alongside the export would prove nothing that recomputation does
// not already prove.
func ProveConsistency(oldLeaves, newLeaves []string) (ConsistencyProof, error) {
	if uint64(len(oldLeaves)) > uint64(len(newLeaves)) {
		return ConsistencyProof{}, fmt.Errorf("hash: old tree larger than new tree")
	}
	for i := range oldLeaves {
		if oldLeaves[i] != newLeaves[i] {
			return ConsistencyProof{}, fmt.Errorf("hash: old tree is not a prefix of new tree at %d", i)
		}
	}
	return ConsistencyProof{
		FromSize:  uint64(len(oldLeaves)),
		ToSize:    uint64(len(newLeaves)),
		FromRoot:  MerkleRoot(oldLeaves),
		ToRoot:    MerkleRoot(newLeaves),
		OldLeaves: append([]string(nil), oldLeaves...),
		NewLeaves: append([]string(nil), newLeaves...),
	}, nil
}

// VerifyConsistency recomputes both roots from the proof's leaf material and
// requires them to match the claimed roots, and requires the older tree to be an
// exact prefix of the newer one.
//
// Status: like ProveConsistency it has no production caller; it stays
// because INTERFACES.md section 5 freezes it into the published API, and
// this package's tests exercise it. The prefix property it checks between
// two leaf lists is what internal/verifier establishes per anchor by
// recomputation -- see the note on ProveConsistency.
func VerifyConsistency(p ConsistencyProof, oldRoot, newRoot string) bool {
	if p.FromSize != uint64(len(p.OldLeaves)) || p.ToSize != uint64(len(p.NewLeaves)) {
		return false
	}
	if p.FromSize > p.ToSize {
		return false
	}
	// The newer leaf list must begin with the older one, element for element.
	if len(p.NewLeaves) < len(p.OldLeaves) {
		return false
	}
	for i, l := range p.OldLeaves {
		if p.NewLeaves[i] != l {
			return false
		}
	}
	if MerkleRoot(p.OldLeaves) != oldRoot || MerkleRoot(p.NewLeaves) != newRoot {
		return false
	}
	return p.FromRoot == oldRoot && p.ToRoot == newRoot
}
