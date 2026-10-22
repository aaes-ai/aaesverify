package verifier

// noteExportAnchorEquivocation records the root claimed at this tree size.
// Two different roots at one tree size in one log are an equivocation
// error, not a newer state (design section 6.4). This is checked on the
// claimed head before any signature verdict, so a forged anchor cannot
// launder a fork past the check.
func noteExportAnchorEquivocation(a AnchorView, equivocation map[uint64]string, i int, fail func(format string, args ...any) bool) bool {
	if prev, seen := equivocation[a.Head.TreeSize]; seen && prev != a.Head.RootHash {
		return fail("anchor %d: %v (tree_size %d)", i, ErrEquivocation, a.Head.TreeSize)
	}
	equivocation[a.Head.TreeSize] = a.Head.RootHash
	return true
}

// checkExportAnchorHeadV4 resolves the anchor key and checks the signed head,
// the log binding, and that the tree size names a non-empty prefix of the log.
func checkExportAnchorHeadV4(a AnchorView, opts VerifyOptions, wantLogID string, leaves []string, i int, fail func(format string, args ...any) bool) bool {
	key, err := resolveAnchorKeyV4(i, a.KeyID, opts)
	if err != nil {
		return fail("%v", err)
	}
	if err := checkAnchorHeadShapeV4(a.Head); err != nil {
		return fail("anchor %d: %v", i, err)
	}
	if err := VerifyTreeHead(a.Head, key, a.Algorithm); err != nil {
		return fail("anchor %d: %v", i, err)
	}
	if err := checkHeadLogID(a.Head, wantLogID); err != nil {
		return fail("anchor %d: %v", i, err)
	}
	if a.Head.TreeSize == 0 {
		return fail("anchor %d: tree_size 0 commits to no entries and is never evidence; its witnesses are not counted", i)
	}
	if a.Head.TreeSize > uint64(len(leaves)) {
		return fail("anchor %d: covers %d leaves, log has %d", i, a.Head.TreeSize, len(leaves))
	}
	return true
}

// checkExportAnchorPrefixV4 checks the anchor head against the prefix it
// claims: the root, the last decision index, and the legacy-head rule that a
// head without a signed schema cannot cover a typed leaf.
func checkExportAnchorPrefixV4(a AnchorView, prefixes map[uint64]prefixFact, i int, fail func(format string, args ...any) bool) bool {
	fact, ok := prefixes[a.Head.TreeSize]
	if !ok || fact.root != a.Head.RootHash {
		got := ""
		if ok {
			got = fact.root
		}
		return fail("anchor %d: root %s is not the root of the first %d leaves (%s)",
			i, a.Head.RootHash, a.Head.TreeSize, got)
	}
	if !fact.hasDecision || a.Head.Index != fact.lastDecision {
		return fail("anchor %d: head index is %d, prefix's last decision sequence is %d", i, a.Head.Index, fact.lastDecision)
	}
	if a.Head.Schema == "" && fact.firstOther >= 0 {
		return fail("anchor %d: a legacy head (no signed schema) commits to a prefix containing a %s leaf at position %d; a typed history cannot be downgraded at an anchor boundary", i, fact.firstOtherKind, fact.firstOther)
	}
	return true
}
