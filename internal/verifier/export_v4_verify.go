package verifier

import (
	"crypto/ed25519"
	"fmt"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// The aaes.export/v4 verification path (design sections 4.1,
// 4.3, 4.7, 4.8 and 6.4). The flow mirrors verifyParsed: header and count
// checks, the unified chain/root walk over EVERY leaf type in file order,
// per-head keyring resolution and signature checks, anchor checks, the scoped
// record checks of section 4.8 (run only after the cryptographic phase
// passes), and the freshness-mode evaluation of section 6.4.

// Scoped result labels (design sections 4.8 and 6.4).
const (
	labelVerified   = "verified"
	labelFailed     = "failed"
	labelNotChecked = "not_checked"
	labelSatisfied  = "satisfied"
)

// Scoped v4 verdict headlines. Only expected-final-head mode may issue the
// legacy headlines (PASS with independent attestation, CONSISTENT without);
// the weaker modes use these labels so a continuity or floor result can never
// read as current v4 evidence (design sections 6.4 and 8.1).
const (
	// VerdictContinuityV4 is a cutover-continuity success: the pinned cutover
	// head is present as a verified anchor and the tree grew, but leaves past
	// the cutover may be hidden and latest state was not checked.
	VerdictContinuityV4 = "CONTINUITY_FROM_CUTOVER"
	// VerdictFloorV4 is a minimum-tree-size-floor success: neither continuity
	// nor freshness was established.
	VerdictFloorV4 = "TREE_SIZE_FLOOR_SATISFIED"
	// VerdictUnpinnedV4 is an unpinned internal-consistency success:
	// anti-rollback and latest state were not checked.
	VerdictUnpinnedV4 = "UNPINNED_CONSISTENCY"
)

// VerifyExportV4 verifies an already-parsed aaes.export/v4 export. The usual
// entrypoint is VerifyExportReaderResult, which parses and dispatches here on
// the header schema.
func VerifyExportV4(exp *ExportFile, opts VerifyOptions) *Result {
	return verifyParsedV4(exp, opts)
}

func verifyParsedV4(exp *ExportFile, opts VerifyOptions) *Result {
	res := &Result{
		OK:                 true,
		Schema:             exp.Header.Schema,
		LogID:              exp.Header.LogID,
		TenantID:           exp.Header.TenantID,
		ExportedAt:         exp.Header.ExportedAt,
		EntryCount:         len(exp.Entries),
		DeclaredEntryCount: exp.Header.EntryCount,
		HeadIndex:          exp.Header.Head.Index,
		HeadTreeSize:       exp.Header.Head.TreeSize,
		HeadRoot:           exp.Header.Head.RootHash,
		HeadSignedAt:       exp.Header.Head.SignedAt,
		AnchorCount:        len(exp.Anchors),
		ResultSchema:       ResultSchemaV2,
		// The offline format does not reconstruct receipt execution/lifecycle
		// histories; this disclosure rides EVERY v4 result (section 4.8).
		ReceiptExecutionValidity: labelNotChecked,
		ExpectedFinalHead:        labelNotChecked,
		ContinuityFromCutover:    labelNotChecked,
		TreeSizeFloor:            labelNotChecked,
		LatestState:              labelNotChecked,
		AntiRollback:             labelNotChecked,
	}

	wantLogID := checkHeaderV4(exp, res, opts)
	if err := checkTrustContextV4(opts); err != nil {
		res.addError("%v", err)
	}
	finalKey, keyErr := resolveFinalKeyV4(exp, opts, res)
	if keyErr != nil {
		res.addError("%v", keyErr)
	}
	if keyErr == nil {
		res.PublicKeyHex = encodeKeyHexV4(finalKey)
	}

	st := checkChainV4(exp, exp.Header.Head, finalKey, keyErr == nil)
	reportChainStateV4(res, st, keyErr == nil)
	if st.chainErr == nil {
		checkGaps(exp, res)
		checkShredding(exp, res)
	}

	prefixes := exportPrefixFacts(exp, st.leaves, st.recomputed)
	verifiedAnchors := checkAnchorsV4(exp, res, opts, st.leaves, wantLogID, finalKey, keyErr == nil, prefixes)

	// Cryptographic consistency gates the scoped record checks: section 4.8
	// checks run after crypto, and a parser that omits them cannot claim their
	// success.
	cryptoOK := keyErr == nil && res.ChainOK && res.RootOK && res.SignatureOK && res.AnchorsOK && len(res.Errors) == 0
	res.CryptographicConsistency = &cryptoOK
	if cryptoOK {
		res.ReceiptIdentityAndParent = checkReceiptsV4(exp, res)
		res.ApprovalSourceHistory = checkApprovalsV4(exp, res)
		checkSummariesV4(exp, res, opts, st.leaves, prefixes)
	} else {
		res.ReceiptIdentityAndParent = labelNotChecked
		res.ApprovalSourceHistory = labelNotChecked
		if len(exp.Summaries) > 0 {
			res.SummaryAncestry = labelNotChecked
			res.SummaryProfile = labelNotChecked
		}
	}

	requireEvidence(exp, res, opts)
	applyFreshnessV4(exp, res, opts, verifiedAnchors)

	if len(res.Errors) > 0 {
		res.OK = false
	}
	verdictV4(res, opts)
	return res
}

// reportChainStateV4 copies the chain walk's outcome into the result. A
// missing or unusable key is not a passing signature check, exactly as on the
// legacy path.
func reportChainStateV4(res *Result, st chainState, keyOK bool) {
	res.RecomputedRoot = st.recomputed
	res.ChainOK = st.chainErr == nil
	res.RootOK = st.rootErr == nil
	res.SignatureOK = keyOK && st.sigErr == nil
	if st.chainErr != nil {
		res.addError("%v", st.chainErr)
	}
	for _, e := range st.entryErrors {
		res.addError("%s", e)
	}
	if st.rootErr != nil {
		res.addError("%v", st.rootErr)
	}
	if st.sigErr != nil {
		res.addError("%v", st.sigErr)
	}
}

// checkAnchorsV4 verifies every anchor against the caller-pinned keyring and
// returns the heads that verified, for the cutover-continuity check.
func checkAnchorsV4(exp *ExportFile, res *Result, opts VerifyOptions, leaves []string, wantLogID string, finalKey ed25519.PublicKey, keyOK bool, prefixes map[uint64]prefixFact) []hash.TreeHead {
	res.AnchorsOK = true
	ev := &verifyEvidence{}
	independentSeen := witnessIdentities{}
	excluded := keyringValuesV4(opts, finalKey, keyOK)
	equivocation := map[uint64]string{exp.Header.Head.TreeSize: exp.Header.Head.RootHash}
	verified := make([]hash.TreeHead, 0, len(exp.Anchors))
	for i, a := range exp.Anchors {
		if checkExportAnchorV4(exp, res, opts, leaves, wantLogID, i, a, &independentSeen, ev, excluded, equivocation, prefixes) {
			verified = append(verified, a.Head)
		}
	}
	appendHonestyWarnings(res, opts, ev)
	return verified
}

// checkChainV4 recomputes the unified chain and root over EVERY leaf type in
// file order (design section 4.3). Filtering to decisions before chaining is
// a v4 verification bug: a typed leaf's preimage links the same chain.
func checkChainV4(exp *ExportFile, head hash.TreeHead, pubKey []byte, checkSig bool) chainState {
	st := chainState{contiguous: true}
	if checkSig && len(pubKey) > 0 {
		st.sigErr = VerifyTreeHead(head, pubKey)
	}
	if len(exp.LeavesV4) == 0 || len(exp.Entries) == 0 {
		st.chainErr = ErrEmptyLog
		st.rootErr = fmt.Errorf("%w: no entries to recompute the head root from", ErrRoot)
		return st
	}
	st.firstSeq = exp.Entries[0].Sequence
	st.lastSeq = exp.Entries[len(exp.Entries)-1].Sequence
	leaves := make([]string, 0, len(exp.LeavesV4))
	prev := ""
	var prevSeq uint64
	entryOrdinal := 0
	var errs []string
	for i, l := range exp.LeavesV4 {
		chain := hash.Chain(prev, l.Preimage)
		leaf := hash.SHA256Hex(l.Preimage)
		errs = checkLeafClaimsV4(errs, i, l, chain, leaf)
		if l.Kind == lineEntry {
			entryOrdinal++
			prevSeq = checkEntrySequenceV4(&st, &errs, i, l.Entry, entryOrdinal, prevSeq)
		}
		leaves = append(leaves, leaf)
		prev = chain
	}
	if len(errs) > 0 {
		st.chainErr = fmt.Errorf("%w: %s", ErrChain, errs[0])
		st.entryErrors = errs[1:]
	}
	st.leaves = leaves
	st.recomputed = hash.MerkleRoot(leaves)
	checkHeadAgainstLeavesV4(&st, head, exp.Entries)
	return st
}

// checkLeafClaimsV4 compares one leaf's exporter claims against the
// recomputed chain link and leaf hash.
func checkLeafClaimsV4(errs []string, i int, l LeafV4, chain, leaf string) []string {
	if l.ChainHash == "" {
		errs = append(errs, fmt.Sprintf("leaf %d (%s): missing chain_hash", i, l.Kind))
	} else if l.ChainHash != chain {
		errs = append(errs, fmt.Sprintf("leaf %d (%s): chain hash is %s, recomputed %s", i, l.Kind, l.ChainHash, chain))
	}
	if l.Leaf == "" {
		errs = append(errs, fmt.Sprintf("leaf %d (%s): missing leaf", i, l.Kind))
	} else if l.Leaf != leaf {
		errs = append(errs, fmt.Sprintf("leaf %d (%s): leaf is %s, recomputed %s", i, l.Kind, l.Leaf, leaf))
	}
	return errs
}

// checkEntrySequenceV4 applies the decision-sequence ordering rules to one
// entry leaf and returns the new previous sequence.
func checkEntrySequenceV4(st *chainState, errs *[]string, i int, e *EntryView, ordinal int, prevSeq uint64) uint64 {
	if e.TenantID == "" {
		*errs = append(*errs, fmt.Sprintf("leaf %d: missing tenant_id", i))
	}
	if ordinal > 1 {
		if e.Sequence <= prevSeq {
			*errs = append(*errs, fmt.Sprintf("leaf %d: sequence %d does not follow %d", i, e.Sequence, prevSeq))
		}
		if e.Sequence != prevSeq+1 {
			st.contiguous = false
		}
	}
	return e.Sequence
}

// checkHeadAgainstLeavesV4 compares the signed head against the recomputed
// tree state.
func checkHeadAgainstLeavesV4(st *chainState, head hash.TreeHead, entries []EntryView) {
	if head.TreeSize != uint64(len(st.leaves)) {
		st.rootErr = fmt.Errorf("%w: head tree_size is %d, export has %d leaves", ErrRoot, head.TreeSize, len(st.leaves))
	} else if head.RootHash != st.recomputed {
		st.rootErr = fmt.Errorf("%w: head root is %s, recomputed %s", ErrRoot, head.RootHash, st.recomputed)
	} else if head.Index != entries[len(entries)-1].Sequence {
		st.rootErr = fmt.Errorf("%w: head index is %d, last entry sequence is %d", ErrRoot, head.Index, entries[len(entries)-1].Sequence)
	}
}

// verdictV4 composes the headline. PASS/CONSISTENT — the current-v4 headline —
// requires expected-final-head mode with the pin verified; the weaker modes
// keep their scoped labels even when every check passed (design section 8.1).
func verdictV4(res *Result, opts VerifyOptions) {
	switch {
	case !res.OK:
		res.Verdict = "FAIL"
	case res.Gapped || len(res.Gaps) > 0:
		res.Verdict = "OK_WITH_GAPS"
	case len(res.ShredEvents) > 0:
		res.Verdict = "OK_WITH_SHREDDED_FIELDS"
	case opts.ExpectedFinal != nil && res.ExpectedFinalHead == labelVerified:
		res.Verdict = res.IntegrityHeadline()
	case opts.Cutover != nil:
		res.Verdict = VerdictContinuityV4
	case opts.MinTreeSize != 0:
		res.Verdict = VerdictFloorV4
	default:
		res.Verdict = VerdictUnpinnedV4
	}
}
