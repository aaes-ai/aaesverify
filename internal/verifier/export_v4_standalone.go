package verifier

import (
	"crypto/ed25519"
	"fmt"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Standalone proof verification (design section 4.9). A standalone API must
// not borrow unproven context from the caller: every result here derives only
// from the presented leaf material, the signed head, and the caller-pinned
// keyring. None of these paths can claim a full-export result: the receipt
// bundle always carries receipt_execution_validity "not_checked", a standalone
// approval leaf always carries approval_source_history "not_checked", and a
// standalone summary leaf always carries summary_ancestry and summary_profile
// "not_checked".

// VerifyReceiptBundleV1 verifies one aaes.receipt-proof/v1 bundle: the typed
// receipt leaf and its inclusion proof, the parent decision entry and its own
// proof, and one v4 signed head resolved through the caller-pinned keyring by
// the bundle's key_id. When opts.ExpectedFinal is set the head must match that
// exact state; without it the result is historical evidence with
// anti_rollback and latest_state "not_checked".
func VerifyReceiptBundleV1(b ReceiptBundleV1, opts VerifyOptions) *Result {
	res := newStandaloneResultV4()
	res.ReceiptParentBinding = labelNotChecked
	if err := b.ValidateV4(); err != nil {
		res.addError("%v", err)
		res.OK = false
		res.Verdict = "FAIL"
		res.ReceiptParentBinding = labelFailed
		return res
	}
	ok := checkBundleTrustV4(b, opts, res)
	if !checkBundleProofsV4(b, res) {
		ok = false
	}
	if !checkBundleBindingV4(b, res) {
		ok = false
	}
	if opts.ExpectedFinal != nil {
		if !opts.ExpectedFinal.matches(b.Head) {
			res.ExpectedFinalHead = labelFailed
			res.addError("the bundle head is not the caller-pinned expected final state")
			ok = false
		} else if ok {
			res.ExpectedFinalHead = labelVerified
			res.AntiRollback = labelVerified
		}
	}
	if ok {
		yes := true
		res.ReceiptLeafAndParentVerified = &yes
		res.ReceiptParentBinding = labelVerified
		res.Verdict = "CONSISTENT"
	} else {
		res.OK = false
		res.Verdict = "FAIL"
		res.ReceiptParentBinding = labelFailed
	}
	return res
}

// checkBundleTrustV4 checks the bundle envelope, the keyring-resolved head
// signature, and the head's binding to the receipt tenant's logical log.
func checkBundleTrustV4(b ReceiptBundleV1, opts VerifyOptions, res *Result) bool {
	ok := true
	fail := func(format string, args ...any) {
		res.addError(format, args...)
		ok = false
	}
	if err := b.ValidateV4(); err != nil {
		fail("%v", err)
		return false
	}
	if opts.ExpectedSchema != "" && opts.ExpectedSchema != ExportSchemaV4 {
		fail("%v: bundle head schema is %s, caller expected %s", ErrSchema, ExportSchemaV4, opts.ExpectedSchema)
	}
	key, err := resolveBundleKeyV4(b.KeyID, opts)
	if err != nil {
		fail("%v", err)
	} else if err := VerifyTreeHead(b.Head, key); err != nil {
		fail("bundle head: %v", err)
	}
	wantLogID := hash.DeriveLogID(*b.ReceiptLeaf.Receipt.TenantID)
	if b.Head.LogID != wantLogID {
		fail("%v: bundle head log_id does not derive from the receipt tenant", ErrLogIDMismatch)
	}
	if opts.ExpectedLogID != "" && b.Head.LogID != opts.ExpectedLogID {
		fail("%v: bundle head log_id is not the caller-pinned logical log", ErrLogIDMismatch)
	}
	if opts.ExpectedTenantID != "" && *b.ReceiptLeaf.Receipt.TenantID != opts.ExpectedTenantID {
		fail("bundle receipt tenant %q is not the expected tenant %q", *b.ReceiptLeaf.Receipt.TenantID, opts.ExpectedTenantID)
	}
	return ok
}

// checkBundleProofsV4 recomputes both leaves and verifies both inclusion
// proofs against the same head root and tree size, with the parent strictly
// before the receipt. Exported chain_hash strings are not standalone proof
// inputs: the leaves are recomputed from the presented material, never
// trusted.
func checkBundleProofsV4(b ReceiptBundleV1, res *Result) bool {
	ok := true
	fail := func(format string, args ...any) {
		res.addError(format, args...)
		ok = false
	}
	parentLeaf, err := b.ParentLeaf.RecomputeLeaf()
	if err != nil {
		fail("parent leaf: %v", err)
	}
	receiptLeaf, err := b.ReceiptLeaf.RecomputeLeafV4()
	if err != nil {
		fail("receipt leaf: %v", err)
	}
	if err == nil && parentLeaf != b.ParentLeaf.Leaf {
		fail("parent_leaf.leaf is not the recomputed leaf; the claim is not a proof input")
	}
	if err == nil && receiptLeaf != b.ReceiptLeaf.Leaf {
		fail("receipt_leaf.leaf is not the recomputed leaf; the claim is not a proof input")
	}
	// Both proofs must sit in the SAME tree the head signs.
	if b.ParentProof.TreeSize != b.Head.TreeSize || b.ReceiptProof.TreeSize != b.Head.TreeSize {
		fail("proof tree_size disagrees with the head; proofs under different heads fail")
	}
	if !hash.VerifyInclusionAgainst(parentLeaf, b.ParentProof, b.Head) {
		fail("%v: parent inclusion proof", ErrInclusion)
	}
	if !hash.VerifyInclusionAgainst(receiptLeaf, b.ReceiptProof, b.Head) {
		fail("%v: receipt inclusion proof", ErrInclusion)
	}
	if b.ParentProof.Index >= b.ReceiptProof.Index {
		fail("the parent decision (position %d) must precede the receipt (position %d)", b.ParentProof.Index, b.ReceiptProof.Index)
	}
	return ok
}

// checkBundleBindingV4 applies the section 4.8 rule 1 binding checks to the
// proven parent/receipt pair.
func checkBundleBindingV4(b ReceiptBundleV1, res *Result) bool {
	ok := true
	if b.ReceiptLeaf.Sequence == nil || b.ReceiptLeaf.Receipt.TenantID == nil || b.ReceiptLeaf.Receipt.IntentID == nil || b.ReceiptLeaf.Receipt.RecordHash == nil {
		res.addError("receipt leaf is missing a required parent-binding field")
		return false
	}
	if *b.ReceiptLeaf.Sequence != b.ParentLeaf.Sequence {
		res.addError("receipt outer sequence %d does not name the proven parent sequence %d", *b.ReceiptLeaf.Sequence, b.ParentLeaf.Sequence)
		ok = false
	}
	if b.ReceiptLeaf.RecordHash != b.ParentLeaf.RecordHash {
		res.addError("receipt outer record_hash does not name the proven parent")
		ok = false
	}
	if msg := receiptParentAgreementV4(&b.ReceiptLeaf, &b.ParentLeaf); msg != "" {
		res.addError("receipt parent binding: %s", msg)
		ok = false
	}
	return ok
}

// resolveBundleKeyV4 resolves the bundle's required key_id through the
// caller-pinned keyring. A standalone bundle has no embedded-key fallback:
// the pinned keyring is the trust decision.
func resolveBundleKeyV4(keyID string, opts VerifyOptions) (ed25519.PublicKey, error) {
	if opts.Keyring == nil {
		return nil, fmt.Errorf("%w: a standalone bundle requires the caller-pinned keyring", ErrNoPublicKey)
	}
	key, ok := opts.Keyring[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: bundle key_id %q", ErrUnknownKeyID, keyID)
	}
	return key, nil
}
