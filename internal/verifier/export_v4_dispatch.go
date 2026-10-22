package verifier

import (
	"crypto/ed25519"
	"fmt"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// checkExpectedSchemaV4 enforces the v4 dispatch guards of design sections
// 6.2 and 6.3 BEFORE the legacy path can issue a historical verdict: an
// expected-schema pin must match the file's declared schema, at most one
// freshness mode may be requested, and a freshness mode on a non-v4 export is
// a downgrade refusal — a relabelled v4 prefix must never collect even a
// legacy PASS when the caller asked for a current-v4 mode.
func checkExpectedSchemaV4(exp *ExportFile, opts VerifyOptions) error {
	if freshnessModesSetV4(opts) > 1 {
		return fmt.Errorf("%w: expected-final, cutover and tree-size-floor are mutually exclusive freshness modes", ErrTrustConfig)
	}
	if opts.ExpectedSchema != "" && opts.ExpectedSchema != exp.Header.Schema {
		return fmt.Errorf("%w: caller expects %q, the export declares %q", ErrSchema, opts.ExpectedSchema, exp.Header.Schema)
	}
	if exp.Header.Schema != ExportSchemaV4 && freshnessModesSetV4(opts) > 0 {
		return fmt.Errorf("%w: v4 freshness modes require an %s export, this file declares %q", ErrSchema, ExportSchemaV4, exp.Header.Schema)
	}
	return nil
}

// refusedResult is the closed-form result for a refusal that precedes
// verification proper.
func refusedResult(exp *ExportFile, err error) *Result {
	res := &Result{
		Path:         exp.Path,
		OK:           false,
		Schema:       exp.Header.Schema,
		LogID:        exp.Header.LogID,
		TenantID:     exp.Header.TenantID,
		ExportedAt:   exp.Header.ExportedAt,
		ResultSchema: ResultSchemaV2,
		Verdict:      "FAIL",
	}
	res.addError("%v", err)
	return res
}

// checkHeaderV4 verifies the section 4.1 header, count and index rules that
// need no key. It returns the log id every signed head in this export must
// name.
func checkHeaderV4(exp *ExportFile, res *Result, opts VerifyOptions) string {
	checkHeaderSignedShapeV4(exp, res)
	checkHeaderCountsV4(exp, res)
	return checkHeaderIdentityV4(exp, res, opts)
}

// checkHeaderSignedShapeV4 checks the signed head's schema and algorithm and
// the unsigned header members that must agree with them. The signed head
// schema is authoritative against downgrade relabelling.
func checkHeaderSignedShapeV4(exp *ExportFile, res *Result) {
	h := &exp.Header
	if h.Head.Schema != ExportSchemaV4 {
		res.addError("a v4 head must carry signed schema %q, found %q; removing or changing it is a downgrade", ExportSchemaV4, h.Head.Schema)
	}
	if h.Head.Algorithm != HeadSignatureAlgorithm {
		res.addError("a v4 head must name algorithm %q, found %q", HeadSignatureAlgorithm, h.Head.Algorithm)
	}
	if h.SignatureAlgorithm != "" && h.SignatureAlgorithm != HeadSignatureAlgorithm {
		res.addError("header signature_algorithm %q, want %q", h.SignatureAlgorithm, HeadSignatureAlgorithm)
	}
	if h.SignatureAlgorithm != "" && h.Head.Algorithm != "" && h.SignatureAlgorithm != h.Head.Algorithm {
		res.addError("header signature_algorithm %q disagrees with the signed head algorithm %q", h.SignatureAlgorithm, h.Head.Algorithm)
	}
	if h.PublicKey != "" && !isEmbeddedKeyV4(h.PublicKey) {
		res.addError("header public_key must be a 32-byte lowercase-hex Ed25519 key")
	}
	if h.SigningKeyID == "" {
		res.addError("a v4 header requires a nonempty signing_key_id; the final head resolves through the caller-pinned keyring")
	}
	if h.ExportedAt.IsZero() {
		res.addError("a v4 header requires a nonzero exported_at")
	}
}

// checkHeaderCountsV4 checks the section 4.1 count, tree-size, first-leaf and
// head-index rules.
func checkHeaderCountsV4(exp *ExportFile, res *Result) {
	h := &exp.Header
	if uint64(len(exp.Entries)) != h.EntryCount {
		res.addError("header declares %d entries, file contains %d", h.EntryCount, len(exp.Entries))
	}
	if uint64(len(exp.LeavesV4)) != h.LeafCount {
		res.addError("header declares leaf_count %d, file contains %d leaves", h.LeafCount, len(exp.LeavesV4))
	}
	if h.LeafCount < h.EntryCount {
		res.addError("leaf_count %d is below entry_count %d", h.LeafCount, h.EntryCount)
	}
	if h.EntryCount == 0 {
		// A decision-free export retains the existing empty-log refusal.
		res.addError("%v", ErrEmptyLog)
	}
	if h.Head.TreeSize != h.LeafCount {
		res.addError("head tree_size is %d, header leaf_count is %d", h.Head.TreeSize, h.LeafCount)
	}
	if len(exp.LeavesV4) > 0 && exp.LeavesV4[0].Kind != lineEntry {
		res.addError("the first leaf of a v4 export is always a decision entry; found %q", exp.LeavesV4[0].Kind)
	}
	if len(exp.Entries) > 0 {
		res.FirstSequence = exp.Entries[0].Sequence
		res.LastSequence = exp.Entries[len(exp.Entries)-1].Sequence
		// head.index remains the LAST DECISION entry's journal sequence, not a
		// Merkle position and not a typed leaf's identifier.
		if h.Head.Index != res.LastSequence {
			res.addError("head index is %d, last decision entry sequence is %d", h.Head.Index, res.LastSequence)
		}
	}
}

// checkHeaderIdentityV4 checks the tenant/log-id agreement and the caller's
// expected logical-log identity. The header is not covered by the head
// signature, so it must agree with the covered per-entry tenant ids (same
// argument as the legacy path).
func checkHeaderIdentityV4(exp *ExportFile, res *Result, opts VerifyOptions) string {
	h := &exp.Header
	for i, e := range exp.Entries {
		if e.TenantID != h.TenantID {
			res.addError("header names tenant %q and entry %d (sequence %d) belongs to tenant %q; the header is not covered by the head signature, so the disagreement is treated as a relabelled export", h.TenantID, i, e.Sequence, e.TenantID)
			break
		}
	}
	wantLogID := hash.DeriveLogID(h.TenantID)
	if err := checkHeadLogID(h.Head, wantLogID); err != nil {
		res.addError("published head: %v", err)
	}
	if h.Head.PreAnchor && !h.PreAnchor {
		res.addError("signed head declares pre_anchor but the export header does not")
	}
	if opts.ExpectedTenantID != "" && opts.ExpectedTenantID != h.TenantID {
		res.addError("caller expects tenant %q, the export declares %q", opts.ExpectedTenantID, h.TenantID)
	}
	if opts.ExpectedLogID != "" && opts.ExpectedLogID != wantLogID {
		res.addError("caller expects log %q, the export's tenant derives %q", opts.ExpectedLogID, wantLogID)
	}
	return wantLogID
}

// isEmbeddedKeyV4 reports whether s is a 32-byte lowercase-hex Ed25519 key.
func isEmbeddedKeyV4(s string) bool {
	if !isHexV4(s) || len(s) != 2*ed25519.PublicKeySize {
		return false
	}
	k, err := ParsePublicKey(s)
	return err == nil && len(k) == ed25519.PublicKeySize
}
