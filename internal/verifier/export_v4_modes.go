package verifier

import (
	"github.com/aaes-ai/aaesverify/internal/hash"
)

// The freshness modes of design section 6.4. Exactly one is requested at a
// time (checkExpectedSchemaV4 enforces exclusivity before dispatch). Only
// expected-final-head mode supplies the exact-state anti-deletion property
// and may produce an unqualified current-v4 verdict; cutover continuity and
// the tree-size floor verify only their named property, always with
// latest_state "not_checked".

// applyFreshnessV4 evaluates the requested mode and sets the result labels.
// verifiedAnchors are the heads of the anchors that passed every check; the
// continuity mode may match the cutover pin only against those — a retained
// anchor IS the continuity evidence, and no consistency-proof format is
// accepted in its place (the A3 amendment to section 6.4).
func applyFreshnessV4(exp *ExportFile, res *Result, opts VerifyOptions, verifiedAnchors []hash.TreeHead) {
	final := exp.Header.Head
	switch {
	case opts.ExpectedFinal != nil:
		applyExpectedFinalV4(exp, res, opts, final)
	case opts.Cutover != nil:
		applyCutoverV4(res, *opts.Cutover, final, verifiedAnchors)
	case opts.MinTreeSize != 0:
		if final.TreeSize >= opts.MinTreeSize {
			res.TreeSizeFloor = labelSatisfied
			res.Warnings = append(res.Warnings, "tree_size_floor is neither continuity nor freshness: leaves past the floor may be hidden and latest state was not checked")
		} else {
			res.TreeSizeFloor = labelFailed
			res.addError("tree_size_floor: final tree_size %d is below the pinned minimum %d", final.TreeSize, opts.MinTreeSize)
		}
	default:
		res.Warnings = append(res.Warnings, "no freshness pin was supplied: this is unpinned internal-consistency verification, not current v4 evidence; anti_rollback and latest_state were not checked")
	}
}

// applyExpectedFinalV4 is the only current-evidence mode: the final head must
// match the pinned log id, index, root and tree size exactly and verify under
// its resolved key — resolved through the caller-pinned keyring, never the
// embedded key.
func applyExpectedFinalV4(exp *ExportFile, res *Result, opts VerifyOptions, final hash.TreeHead) {
	pin := *opts.ExpectedFinal
	if res.KeySource != "keyring" {
		res.ExpectedFinalHead = labelFailed
		res.addError("expected_final_head: the final head must verify under the caller-pinned keyring; an embedded or missing key proves internal consistency only")
		return
	}
	if !pin.matches(final) {
		res.ExpectedFinalHead = labelFailed
		res.addError("expected_final_head: the final head is (log %s, index %d, root %s, size %d), the pin expects (log %s, index %d, root %s, size %d)",
			final.LogID, final.Index, final.RootHash, final.TreeSize, pin.LogID, pin.Index, pin.RootHash, pin.TreeSize)
		return
	}
	if !res.SignatureOK {
		res.ExpectedFinalHead = labelFailed
		res.addError("expected_final_head: the pinned head did not verify under its resolved key")
		return
	}
	res.ExpectedFinalHead = labelVerified
	// Expected-final is the one mode with the section 2.3 exact-state
	// anti-deletion property. "Current" is the caller's designated state: the
	// verifier never independently discovers the world's latest state, so
	// latest_state stays not_checked in every mode.
	res.AntiRollback = labelVerified
}

// applyCutoverV4 verifies continuity from a previously accepted cutover head:
// the final tree must reach at least the cutover size AND the export must
// contain the exact cutover head as a verified anchor. A legacy v2/v3 cutover
// head is allowed only over its decision-only prefix, which the anchor checks
// have already enforced.
func applyCutoverV4(res *Result, pin HeadPin, final hash.TreeHead, verifiedAnchors []hash.TreeHead) {
	if final.TreeSize < pin.TreeSize {
		res.ContinuityFromCutover = labelFailed
		res.addError("continuity_from_cutover: final tree_size %d is below the pinned cutover size %d", final.TreeSize, pin.TreeSize)
		return
	}
	for _, a := range verifiedAnchors {
		if pin.matches(a) {
			res.ContinuityFromCutover = labelVerified
			res.Warnings = append(res.Warnings, "continuity_from_cutover is not freshness: leaves past the cutover may be hidden and latest state was not checked")
			return
		}
	}
	res.ContinuityFromCutover = labelFailed
	res.addError("continuity_from_cutover: the pinned cutover head (log %s, index %d, root %s, size %d) is not present as a verified anchor; a caller-supplied consistency proof is not a substitute",
		pin.LogID, pin.Index, pin.RootHash, pin.TreeSize)
}
