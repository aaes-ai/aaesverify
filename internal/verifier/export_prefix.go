package verifier

import "github.com/aaes-ai/aaesverify/internal/hash"

// prefixFact is the Merkle root and the last decision sequence of one tree
// size, recorded once while the export's leaves are already in hand.
type prefixFact struct {
	root           string
	lastDecision   uint64
	hasDecision    bool
	firstOther     int
	firstOtherKind string
}

// exportPrefixFacts records one fact for every anchor and local-summary tree
// size. fullRoot is the chain walk's root of the whole leaf list; a prefix
// that is the whole log reuses it.
func exportPrefixFacts(exp *ExportFile, leaves []string, fullRoot string) map[uint64]prefixFact {
	sizes := make([]uint64, 0, len(exp.Anchors))
	for _, a := range exp.Anchors {
		sizes = append(sizes, a.Head.TreeSize)
	}
	decision := make([]bool, len(leaves))
	seq := make([]uint64, len(leaves))
	kinds := make([]string, len(leaves))
	if exp.Header.Schema == ExportSchemaV4 && len(exp.LeavesV4) == len(leaves) {
		for i, l := range exp.LeavesV4 {
			kinds[i] = l.Kind
			if l.Kind == lineEntry && l.Entry != nil {
				decision[i] = true
				seq[i] = l.Entry.Sequence
			}
		}
		for _, leaf := range exp.LeavesV4 {
			if leaf.Kind != lineSummaryV4 || leaf.Summary == nil {
				continue
			}
			for _, in := range leaf.Summary.Inputs {
				sizes = append(sizes, in.Head.TreeSize)
			}
		}
	} else {
		for i := range leaves {
			decision[i] = true
			kinds[i] = lineEntry
			if i < len(exp.Entries) {
				seq[i] = exp.Entries[i].Sequence
			}
		}
	}
	return factsForSizes(leaves, decision, seq, kinds, sizes, fullRoot)
}

func factsForSizes(leaves []string, decision []bool, seq []uint64, kinds []string, sizes []uint64, fullRoot string) map[uint64]prefixFact {
	n := uint64(len(leaves))
	want := map[uint64]struct{}{}
	for _, sz := range sizes {
		if sz <= n {
			want[sz] = struct{}{}
		}
	}
	out := make(map[uint64]prefixFact, len(want))
	if _, ok := want[0]; ok {
		out[0] = prefixFact{root: hash.MerkleRoot(nil), firstOther: -1}
	}
	var last uint64
	has := false
	otherAt := -1
	otherKind := ""
	// One frontier walk serves every requested size: anchors and summary
	// inputs are untrusted lines, so a root per size recomputed from scratch
	// would make a hostile export quadratic.
	var frontier hash.MerkleFrontier
	for i := range leaves {
		frontier.Append(leaves[i])
		if i < len(decision) && decision[i] {
			if i < len(seq) {
				last = seq[i]
			}
			has = true
		} else if otherAt < 0 {
			otherAt = i
			if i < len(kinds) {
				otherKind = kinds[i]
			}
		}
		sz := uint64(i + 1)
		if _, ok := want[sz]; !ok {
			continue
		}
		root := fullRoot
		if sz != n || fullRoot == "" {
			root = frontier.Root()
		}
		out[sz] = prefixFact{
			root: root, lastDecision: last, hasDecision: has,
			firstOther: otherAt, firstOtherKind: otherKind,
		}
	}
	return out
}
