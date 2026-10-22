package verifier

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Summary verification inside a full export (design section 5.3). The base
// verifier establishes summary INPUT INTEGRITY only: every input head resolves
// as a verified local prefix or as a head of a caller-supplied referenced
// export that itself verifies. Freshness is evaluated independently per input
// and is never upgraded by the summary log's own expected-final pin. Profile
// correctness (summary_profile) is Ticket 3 profile work and stays
// "not_checked" here even when the profile member names a known profile.

// checkSummariesV4 runs after the cryptographic and record checks pass: a
// summary interpreted over unverified bytes would borrow unproven context.
func checkSummariesV4(exp *ExportFile, res *Result, opts VerifyOptions, leaves []string, prefixes map[uint64]prefixFact) {
	if len(exp.Summaries) == 0 {
		return
	}
	res.SummaryProfile = labelNotChecked
	allOK := true
	seenIDs := map[string]int{}
	cache := map[string]*parsedReference{}
	for pos, leaf := range exp.LeavesV4 {
		if leaf.Kind != lineSummaryV4 {
			continue
		}
		sum := leaf.Summary
		// summary_id is unique within the summary log (section 5.2).
		if prev, dup := seenIDs[sum.SummaryID]; dup {
			res.addError("summary %q at leaf %d duplicates the summary_id at leaf %d", sum.SummaryID, pos, prev)
			allOK = false
		}
		seenIDs[sum.SummaryID] = pos
		auth := checkSummaryProducerV4(sum, opts, res)
		if auth == labelFailed {
			allOK = false
		}
		res.SummaryProducerAuthorship = mergeProducerAuth(res.SummaryProducerAuthorship, auth)
		if !checkSummaryInputsV4(exp, res, opts, pos, sum, leaves, prefixes, cache) {
			allOK = false
		}
	}
	verified := allOK
	res.SummaryInputsVerified = &verified
	if allOK {
		res.SummaryAncestry = labelVerified
	} else {
		res.SummaryAncestry = labelFailed
	}
}

// checkSummaryInputsV4 verifies every input of one summary leaf at leaf
// position pos (which is also the number of leaves before it) and records the
// per-input integrity and freshness results plus the section 5.2 limitation
// requirements.
func checkSummaryInputsV4(exp *ExportFile, res *Result, opts VerifyOptions, pos int, sum *SummaryLeafViewV4, leaves []string, prefixes map[uint64]prefixFact, cache map[string]*parsedReference) bool {
	allOK := true
	limitations := summaryLimitationsV4(sum)
	for _, in := range sum.Inputs {
		integrityOK, fresh := verifySummaryInputV4(exp, res, opts, pos, in, leaves, prefixes, cache)
		if !integrityOK {
			allOK = false
		}
		ir := SummaryInputResultV4{InputID: in.InputID, LatestState: labelNotChecked}
		if integrityOK {
			ir.Integrity = labelVerified
		} else {
			ir.Integrity = labelFailed
		}
		if fresh {
			ir.LatestState = labelVerified
		}
		res.SummaryInputs = append(res.SummaryInputs, ir)
		// Section 5.2: a legacy input needs an explicit limitation that its
		// receipt/approval fields are not signed by that legacy export; every
		// input that did not pass expected-final-head mode needs an explicit
		// latest_state:"not_checked" limitation. A limitation names its input.
		if in.Schema != ExportSchemaV4 && !limitationNamesV4(limitations, in.InputID, "") {
			res.addError("summary %q: legacy input %q requires an explicit limitation that its receipt/approval fields are not signed", sum.SummaryID, in.InputID)
			allOK = false
		}
		if !fresh && !limitationNamesV4(limitations, in.InputID, "latest_state") {
			res.addError("summary %q: input %q did not pass expected-final-head mode and requires an explicit latest_state limitation", sum.SummaryID, in.InputID)
			allOK = false
		}
	}
	return allOK
}

// verifySummaryInputV4 resolves one input as a local prefix or a referenced
// export (section 5.3) and reports integrity and freshness separately.
func verifySummaryInputV4(exp *ExportFile, res *Result, opts VerifyOptions, pos int, in SummaryInputV4, leaves []string, prefixes map[uint64]prefixFact, cache map[string]*parsedReference) (integrityOK, fresh bool) {
	// "Names the summary's logical log" is judged against the DERIVED log id:
	// the header's unsigned log_id string is not trusted for this decision.
	if in.Head.LogID == hash.DeriveLogID(exp.Header.TenantID) {
		return verifyLocalPrefixInputV4(exp, res, opts, pos, in, prefixes), false
	}
	return verifyReferencedInputV4(exp, res, opts, in, cache)
}

// verifyLocalPrefixInputV4 recomputes the named prior state of THIS log: the
// input's tree size must reach no further than the leaves before the summary,
// the recomputed prefix root and decision index must match, and the head must
// verify under the input's key_id in this log's pinned keyring. A legacy local
// input covers a decision-only prefix. A local input is a prior state by
// construction, so it is never fresh.
func verifyLocalPrefixInputV4(_ *ExportFile, res *Result, opts VerifyOptions, pos int, in SummaryInputV4, prefixes map[uint64]prefixFact) bool {
	fail := func(format string, args ...any) bool {
		res.addError("summary input %q: "+format, append([]any{in.InputID}, args...)...)
		return false
	}
	if in.Head.TreeSize > uint64(pos) {
		return fail("tree_size %d reaches past the summary at leaf %d: a self-reference or later state", in.Head.TreeSize, pos)
	}
	fact, ok := prefixes[in.Head.TreeSize]
	if in.Schema != ExportSchemaV4 && ok && fact.firstOther >= 0 {
		return fail("a legacy local input covers a decision-only prefix; leaf %d is %q", fact.firstOther, fact.firstOtherKind)
	}
	if !ok || fact.root != in.Head.RootHash {
		return fail("recomputed prefix root does not match the input head")
	}
	if in.Head.Index != fact.lastDecision {
		return fail("input head index %d, prefix's last decision sequence is %d", in.Head.Index, fact.lastDecision)
	}
	key, ok := opts.Keyring[in.KeyID]
	if !ok {
		return fail("%v: key_id %q", ErrUnknownKeyID, in.KeyID)
	}
	if err := VerifyTreeHead(in.Head, key); err != nil {
		return fail("input head signature: %v", err)
	}
	return true
}

// verifyReferencedInputV4 verifies a non-local input against the
// caller-supplied referenced export: the export verifies under its own logical
// log keyring and schema rules, and the input's complete head — including
// signed_at and signature bytes — must equal its verified final or an anchor
// head. Freshness additionally requires the input to be a v4 head equal to the
// referenced export's FINAL head under the caller's expected-final pin for
// that log; anchors, cutover and floor pins stay latest_state "not_checked".
// parsedReference is one referenced export, parsed and verified once per input id.
type parsedReference struct {
	exp *ExportFile
	res *Result
	err error
}

func verifyReferencedInputV4(_ *ExportFile, res *Result, opts VerifyOptions, in SummaryInputV4, cache map[string]*parsedReference) (bool, bool) {
	fail := func(format string, args ...any) (bool, bool) {
		res.addError("summary input %q: "+format, append([]any{in.InputID}, args...)...)
		return false, false
	}
	var ref *SummaryReferenceV4
	for i := range opts.SummaryReferences {
		if opts.SummaryReferences[i].InputID == in.InputID {
			ref = &opts.SummaryReferences[i]
			break
		}
	}
	if ref == nil {
		return fail("no referenced export supplied; a non-local input may not borrow context")
	}
	key, ok := ref.Keyring[in.KeyID]
	if !ok {
		return fail("%v: key_id %q in the referenced log's keyring", ErrUnknownKeyID, in.KeyID)
	}
	parsed := cache[in.InputID]
	if parsed == nil {
		parsed = &parsedReference{}
		parsed.exp, parsed.err = LoadExportReader(bytes.NewReader(ref.Export))
		if parsed.err == nil {
			// Nested summary inputs are out of scope for the reference: it
			// carries no SummaryReferences of its own here. Trust flags that
			// change requireEvidence travel with the caller.
			parsed.res = verifyParsed(parsed.exp, key, referencedVerifyOptions(opts, ref))
		}
		cache[in.InputID] = parsed
	}
	if parsed.err != nil {
		return fail("referenced export does not parse: %v", parsed.err)
	}
	if !parsed.res.OK {
		return fail("referenced export does not verify: %s", strings.Join(parsed.res.Errors, "; "))
	}
	refExp := parsed.exp
	isFinal := headEqualsV4(in.Head, refExp.Header.Head)
	if !isFinal && !anchorHeadEqualsV4(refExp.Anchors, in.Head) {
		return fail("the input head — including signed_at and signature bytes — is neither the referenced export's verified final head nor one of its anchors")
	}
	if err := VerifyTreeHead(in.Head, key); err != nil {
		return fail("input head signature: %v", err)
	}
	fresh := in.Schema == ExportSchemaV4 && isFinal && ref.ExpectedFinal != nil && ref.ExpectedFinal.matches(in.Head)
	return true, fresh
}

// referencedVerifyOptions keeps the caller's trust flags that requireEvidence
// reads, and the referenced log's own keyring. Freshness pins stay on the
// input, not on this nested verify.
func referencedVerifyOptions(opts VerifyOptions, ref *SummaryReferenceV4) VerifyOptions {
	return VerifyOptions{
		Keyring:            ref.Keyring,
		AllowPreAnchor:     opts.AllowPreAnchor,
		RequireIndependent: opts.RequireIndependent,
		TrustedWitnessKeys: opts.TrustedWitnessKeys,
		TSARoots:           opts.TSARoots,
	}
}

// headEqualsV4 compares the complete head: tree-state identity plus signed_at
// and the signature bytes, so one logical state signed twice is two inputs.
func headEqualsV4(a, b hash.TreeHead) bool {
	return a.Algorithm == b.Algorithm && a.Schema == b.Schema &&
		a.LogID == b.LogID && a.Index == b.Index &&
		a.RootHash == b.RootHash && a.TreeSize == b.TreeSize &&
		a.SignedAt.Equal(b.SignedAt) && a.PreAnchor == b.PreAnchor &&
		bytes.Equal(a.Signature, b.Signature)
}

func anchorHeadEqualsV4(anchors []AnchorView, h hash.TreeHead) bool {
	for _, a := range anchors {
		if headEqualsV4(a.Head, h) {
			return true
		}
	}
	return false
}

// summaryLimitationsV4 extracts the limitations array from an
// envelope-validated body.
func summaryLimitationsV4(sum *SummaryLeafViewV4) []string {
	if sum != nil && sum.limitationsParsed {
		return sum.parsedLimitations
	}
	if sum == nil {
		return nil
	}
	var b struct {
		Limitations []string `json:"limitations"`
	}
	if err := json.Unmarshal(sum.Body, &b); err != nil {
		return nil
	}
	return b.Limitations
}

// limitationNamesV4 reports whether some limitation names that input as its
// own identifier. A legacy limitation must state that receipt and approval
// fields are not signed. A freshness limitation must state latest_state
// not_checked for that same input.
func limitationNamesV4(limitations []string, inputID, marker string) bool {
	if inputID == "" {
		return false
	}
	for _, l := range limitations {
		if !limitationNamesInput(l, inputID) {
			continue
		}
		switch marker {
		case "":
			if limitationSaysUnsigned(l) {
				return true
			}
		case "latest_state":
			if limitationSaysLatestStateNotChecked(l) {
				return true
			}
		default:
			if strings.Contains(l, marker) {
				return true
			}
		}
	}
	return false
}

func limitationNamesInput(l, inputID string) bool {
	for i := 0; i+len(inputID) <= len(l); {
		j := strings.Index(l[i:], inputID)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(inputID)
		if (j == 0 || !limitationIDByte(l[j-1])) && (end == len(l) || !limitationIDByte(l[end])) {
			return true
		}
		i = end
	}
	return false
}

func limitationIDByte(b byte) bool {
	return b == '-' || b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func limitationSaysUnsigned(l string) bool {
	return strings.Contains(l, "receipt") && strings.Contains(l, "approval") && strings.Contains(l, "not signed")
}

func limitationSaysLatestStateNotChecked(l string) bool {
	i := strings.Index(l, "latest_state")
	if i < 0 {
		return false
	}
	rest := strings.TrimLeft(l[i+len("latest_state"):], " \t:\"'")
	return strings.HasPrefix(rest, "not_checked")
}

func mergeProducerAuth(cur, next string) string {
	if cur == labelFailed || next == labelFailed {
		return labelFailed
	}
	if cur == "" || cur == next {
		return next
	}
	return labelNotChecked
}
