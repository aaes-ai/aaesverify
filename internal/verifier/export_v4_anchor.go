package verifier

import (
	"fmt"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// checkExportAnchorV4 verifies one anchor of a v4 export: keyring resolution
// by its required key_id, the head signature under the resolved key, the log
// binding, the tree prefix it commits to, the historical-anchor prefix rule,
// and the evidence riding on it. It returns true only when every check
// passed, so the continuity mode can name the verified anchors.
//
// The historical-anchor rule (design section 4.7): a head WITHOUT signed
// schema uses the legacy payload rules and may witness only a decision-only
// prefix — a legacy-looking anchor over a prefix containing receipt, approval
// or summary leaves is refused even when a signature could be made to verify,
// because that is an anchor-boundary downgrade. A head with signed v4 schema
// uses the v4 payload and may cover typed leaves.
func checkExportAnchorV4(exp *ExportFile, res *Result, opts VerifyOptions, leaves []string, wantLogID string, i int, a AnchorView, independentSeen *witnessIdentities, ev *verifyEvidence, excluded [][]byte, equivocation map[uint64]string, prefixes map[uint64]prefixFact) bool {
	fail := func(format string, args ...any) bool {
		res.AnchorsOK = false
		res.addError(format, args...)
		return false
	}
	if !noteExportAnchorEquivocation(a, equivocation, i, fail) {
		return false
	}
	if !checkExportAnchorHeadV4(a, opts, wantLogID, leaves, i, fail) {
		return false
	}
	if !checkExportAnchorPrefixV4(a, prefixes, i, fail) {
		return false
	}
	// A legacy head can never count as a witness or timestamp over the final
	// v4 head merely because the other values match: the comparison includes
	// the signed schema (design section 4.7).
	coversFinal := headCoversFinalV4(a.Head, exp.Header.Head)
	if !checkAnchorTimestamp(i, a, res, opts, ev, coversFinal) {
		return false
	}
	res.AnchorsVerified++
	before := len(res.Errors)
	checkAnchorWitnessesV4(i, a, res, opts, coversFinal, independentSeen, ev, excluded)
	return len(res.Errors) == before
}

// checkAnchorHeadShapeV4 enforces the per-schema head rules of section 4.7: a
// v4 anchor head carries signed schema v4 and algorithm ed25519; a legacy
// anchor head carries no schema and follows the legacy algorithm rules; any
// other signed schema is refused.
func checkAnchorHeadShapeV4(h hash.TreeHead) error {
	switch h.Schema {
	case ExportSchemaV4:
		if h.Algorithm != HeadSignatureAlgorithm {
			return fmt.Errorf("%w: a v4 anchor head must name algorithm %q, found %q", ErrSignature, HeadSignatureAlgorithm, h.Algorithm)
		}
	case "":
		// Legacy payload and legacy algorithm rules: empty is the historical
		// Ed25519 head, an unknown name is refused by VerifyTreeHead.
	default:
		return fmt.Errorf("%w: anchor head carries unknown signed schema %q", ErrSchema, h.Schema)
	}
	return nil
}

// headCoversFinalV4 is headCoversFinal plus the signed schema: a countersigned
// head commits to the final v4 tree state only when every pinned value AND
// the schema agree.
func headCoversFinalV4(head, final hash.TreeHead) bool {
	return headCoversFinal(head, final) && head.Schema == final.Schema
}

// checkAnchorWitnessesV4 is checkAnchorWitnesses with the whole-keyring
// independence exclusion of section 4.7: a countersignature by any authorised
// ledger key epoch verifies cryptographically and increments
// WitnessesVerified, but never increments IndependentWitnesses, cannot
// satisfy RequireIndependent, and cannot enable PASS.
func checkAnchorWitnessesV4(i int, a AnchorView, res *Result, opts VerifyOptions, coversFinal bool, independentSeen *witnessIdentities, ev *verifyEvidence, excluded [][]byte) {
	checkAnchorWitnessesCore(i, a, res, coversFinal, independentSeen, ev, func(w WitnessView) bool {
		return independentWitnessV4(w, excluded, opts.TrustedWitnessKeys)
	})
}
