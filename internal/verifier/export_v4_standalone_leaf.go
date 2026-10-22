package verifier

import (
	"crypto/ed25519"
	"fmt"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// newStandaloneResultV4 seeds the disclosures every standalone v4 result
// carries (design sections 4.8 and 4.9).
func newStandaloneResultV4() *Result {
	return &Result{
		OK:                       true,
		ResultSchema:             ResultSchemaV2,
		ReceiptExecutionValidity: labelNotChecked,
		ExpectedFinalHead:        labelNotChecked,
		ContinuityFromCutover:    labelNotChecked,
		TreeSizeFloor:            labelNotChecked,
		LatestState:              labelNotChecked,
		AntiRollback:             labelNotChecked,
	}
}

// VerifyStandaloneApprovalV4 verifies one approval leaf's inclusion under one
// v4 signed head. Inclusion of the recorded fields is ALL it establishes:
// global source ordering, first-pending history, immutable raise facts and
// legal successors require the full per-tenant series of section 4.8, so
// approval_source_history is always "not_checked" here.
func VerifyStandaloneApprovalV4(leaf ApprovalLeafViewV4, proof hash.InclusionProof, head hash.TreeHead, keyID string, opts VerifyOptions) *Result {
	res := newStandaloneResultV4()
	res.ApprovalSourceHistory = labelNotChecked
	if err := leaf.ValidateV4(); err != nil {
		res.addError("%v", err)
		finishStandaloneLeafV4(res, false)
		return res
	}
	ok := verifyStandaloneLeafV4(res, head, keyID, opts, *leaf.Approval.TenantID)
	if leafHex, err := leaf.RecomputeLeafV4(); err != nil {
		res.addError("approval leaf: %v", err)
		ok = false
	} else if !verifyProofAgainstHeadV4(res, leafHex, proof, head, "approval") {
		ok = false
	}
	ok = applyStandaloneExpectedFinal(res, head, opts, ok)
	finishStandaloneLeafV4(res, ok)
	return res
}

// VerifyStandaloneSummaryV4 verifies one summary leaf's inclusion under one
// v4 signed head, plus its optional producer signature when the caller pins
// the producer key. It establishes inclusion only: summary_ancestry and
// summary_profile stay "not_checked" because input ancestry and profile
// correctness need the section 5.3 evidence a standalone leaf does not carry.
func VerifyStandaloneSummaryV4(leaf SummaryLeafViewV4, proof hash.InclusionProof, head hash.TreeHead, keyID string, opts VerifyOptions) *Result {
	res := newStandaloneResultV4()
	res.SummaryAncestry = labelNotChecked
	res.SummaryProfile = labelNotChecked
	res.SummaryProducerAuthorship = labelNotChecked
	ok := verifyStandaloneLeafV4(res, head, keyID, opts, leaf.TenantID)
	if err := leaf.ValidateV4(); err != nil {
		res.addError("%v", err)
		ok = false
	}
	if leafHex, err := leaf.RecomputeLeafV4(); err != nil {
		res.addError("summary leaf: %v", err)
		ok = false
	} else if !verifyProofAgainstHeadV4(res, leafHex, proof, head, "summary") {
		ok = false
	}
	res.SummaryProducerAuthorship = checkSummaryProducerV4(&leaf, opts, res)
	if res.SummaryProducerAuthorship == labelFailed {
		ok = false
	}
	ok = applyStandaloneExpectedFinal(res, head, opts, ok)
	finishStandaloneLeafV4(res, ok)
	return res
}

// verifyStandaloneLeafV4 runs the head checks shared by the standalone
// approval and summary paths: complete v4 head, keyring-resolved signature,
// and the head's log id derived from the leaf's tenant.
func verifyStandaloneLeafV4(res *Result, head hash.TreeHead, keyID string, opts VerifyOptions, tenant string) bool {
	ok := true
	if err := validateHeadV4(head); err != nil {
		res.addError("%v", err)
		ok = false
	}
	key, err := resolveBundleKeyV4(keyID, opts)
	if err != nil {
		res.addError("%v", err)
		ok = false
	} else if err := VerifyTreeHead(head, key); err != nil {
		res.addError("standalone head: %v", err)
		ok = false
	}
	if head.LogID != hash.DeriveLogID(tenant) {
		res.addError("%v: head log_id does not derive from the leaf tenant", ErrLogIDMismatch)
		ok = false
	}
	return ok
}

// applyStandaloneExpectedFinal labels the pinned head only after the crypto
// path has succeeded. A matching pin on a failed head or proof stays
// not_checked. A mismatch is a failure whether or not crypto succeeded.
func applyStandaloneExpectedFinal(res *Result, head hash.TreeHead, opts VerifyOptions, ok bool) bool {
	if opts.ExpectedFinal == nil {
		return ok
	}
	if !opts.ExpectedFinal.matches(head) {
		res.ExpectedFinalHead = labelFailed
		res.addError("the head is not the caller-pinned expected final state")
		return false
	}
	if ok {
		res.ExpectedFinalHead = labelVerified
		res.AntiRollback = labelVerified
	}
	return ok
}

// verifyProofAgainstHeadV4 checks one recomputed leaf's inclusion proof
// against the head's root and tree size.
func verifyProofAgainstHeadV4(res *Result, leafHex string, proof hash.InclusionProof, head hash.TreeHead, what string) bool {
	if proof.TreeSize != head.TreeSize {
		res.addError("%s proof tree_size %d disagrees with the head's %d", what, proof.TreeSize, head.TreeSize)
		return false
	}
	if !hash.VerifyInclusionAgainst(leafHex, proof, head) {
		res.addError("%v: %s inclusion proof", ErrInclusion, what)
		return false
	}
	return true
}

// checkSummaryProducerV4 verifies the optional summary producer signature
// (design section 5.4) when the caller pins the producer key. A missing
// signature is not a failure; authorship is simply left unverified. An
// embedded public_key is internal consistency only and never satisfies a pin.
func checkSummaryProducerV4(leaf *SummaryLeafViewV4, opts VerifyOptions, res *Result) string {
	ps := leaf.ProducerSignature
	if ps == nil {
		return labelNotChecked
	}
	key, ok := opts.TrustedSummaryProducerKeys[ps.KeyID]
	if !ok {
		res.Warnings = append(res.Warnings, fmt.Sprintf("summary producer key %q is not caller-pinned; producer authorship is unverified", ps.KeyID))
		return labelNotChecked
	}
	payload, err := leaf.SummaryProducerPayloadV4()
	if err != nil {
		res.addError("summary producer payload: %v", err)
		return labelFailed
	}
	if !ed25519.Verify(key, payload, ps.Signature) {
		res.addError("%v: summary producer signature under pinned key %q", ErrSignature, ps.KeyID)
		return labelFailed
	}
	return labelVerified
}

func finishStandaloneLeafV4(res *Result, ok bool) {
	if ok {
		yes := true
		res.LeafInclusionVerified = &yes
		res.Verdict = "CONSISTENT"
		return
	}
	res.OK = false
	res.Verdict = "FAIL"
}
