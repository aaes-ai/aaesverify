package verifier

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// VerifyOptions selects checks beyond internal consistency. Passing
// RequireIndependent is how a caller asks for independent verification: the
// independence limits this package otherwise prints as warnings become errors,
// and an export with zero independent witnesses and zero independent timestamps
// fails. It does not contact a TSA or witness; the tokens and countersignatures
// already in the file are all it uses.
//
// AllowPreAnchor accepts an export that declares pre_anchor with no anchors
// when the head signature does not cover that flag (older exports). A head
// that signs pre_anchor verifies without this opt-in.
type VerifyOptions struct {
	// TrustedWitnessKeys pins independent witness identities supplied out of band.
	// Exported keys and custody declarations never establish this trust.
	TrustedWitnessKeys map[string][]byte
	TSARoots           *x509.CertPool
	RequireIndependent bool
	AllowPreAnchor     bool
	// Keyring pins the authorised ledger keys of one logical log, key_id to
	// public key (design section 4.7). Every v4 head — the final head via the
	// header's signing_key_id, every anchor via its required key_id — resolves
	// through it; an unknown key_id is an error, never a silent skip. Without
	// a keyring a v4 export verifies only as unpinned internal consistency
	// against the embedded key.
	Keyring map[string]ed25519.PublicKey
	// ExpectedSchema, when set, is the schema the caller expects; a file
	// declaring anything else fails before verification, so a relabelled
	// export cannot pass under a parser the caller did not choose.
	ExpectedSchema string
	// ExpectedTenantID and ExpectedLogID pin the expected logical-log
	// identity for v4 verification (design section 6.4).
	ExpectedTenantID string
	ExpectedLogID    string
	// Exactly one freshness mode may be set (design section 6.4).
	// ExpectedFinal pins the exact expected final head — the only
	// current-evidence mode. Cutover pins a previously accepted cutover head
	// that must appear as a verified anchor. MinTreeSize is a minimum
	// tree-size floor. None set is unpinned internal-consistency
	// verification. Setting any of them on a v2/v3 export is a downgrade
	// refusal.
	ExpectedFinal *HeadPin
	Cutover       *HeadPin
	MinTreeSize   uint64
	// SummaryReferences supplies the referenced full export for each
	// non-local summary input (design section 5.3), matched by the input_id
	// the summary gives it. A non-local input without its reference fails.
	SummaryReferences []SummaryReferenceV4
	// TrustedSummaryProducerKeys pins summary producer keys by key_id
	// (design section 5.4). Without a pin, producer authorship is left
	// unverified; an embedded public_key is internal consistency only.
	TrustedSummaryProducerKeys map[string]ed25519.PublicKey
}

// SummaryReferenceV4 is the caller-supplied evidence for one non-local
// summary input (design section 5.3): the referenced full export, the
// caller-pinned keyring of that input's own logical log, and optionally the
// expected-final pin that makes the input CURRENT. A cutover or floor pin is
// accepted but only ever yields latest_state "not_checked" for the input.
type SummaryReferenceV4 struct {
	InputID       string
	Export        []byte
	Keyring       map[string]ed25519.PublicKey
	ExpectedFinal *HeadPin
	Cutover       *HeadPin
	MinTreeSize   uint64
}

// HeadPin pins one expected tree state by log id, decision index, root and
// tree size (design section 6.4). Tree-state comparison is by logical log
// identity and tree size, never by head.index alone: the decision index can
// remain unchanged while typed leaves grow the tree.
type HeadPin struct {
	LogID    string `json:"log_id"`
	Index    uint64 `json:"index"`
	RootHash string `json:"root_hash"`
	TreeSize uint64 `json:"tree_size"`
}

// matches reports whether h is exactly the pinned state.
func (p HeadPin) matches(h hash.TreeHead) bool {
	return p.LogID == h.LogID && p.Index == h.Index && p.RootHash == h.RootHash && p.TreeSize == h.TreeSize
}

// freshnessModesSetV4 counts the requested section 6.4 freshness modes.
func freshnessModesSetV4(opts VerifyOptions) int {
	n := 0
	if opts.ExpectedFinal != nil {
		n++
	}
	if opts.Cutover != nil {
		n++
	}
	if opts.MinTreeSize != 0 {
		n++
	}
	return n
}

// VerifyExportReaderResult verifies an export from r. Load failures become
// Result.Errors with OK=false; there is no separate error return.
func VerifyExportReaderResult(r io.Reader, pubKey []byte, opts VerifyOptions) *Result {
	exp, err := LoadExportReader(r)
	if err != nil {
		return &Result{OK: false, ResultSchema: ResultSchemaV2, Verdict: "FAIL", Errors: []string{err.Error()}}
	}
	return VerifyParsedExport(exp, pubKey, opts)
}

// VerifyParsedExport verifies an export that has already been parsed.
// Callers that just loaded the file use this instead of reading it again.
func VerifyParsedExport(exp *ExportFile, pubKey []byte, opts VerifyOptions) *Result {
	if exp == nil {
		return &Result{OK: false, ResultSchema: ResultSchemaV2, Verdict: "FAIL", Errors: []string{"verifier: no export"}}
	}
	return verifyParsed(exp, pubKey, opts)
}

// VerifyExportReaderWithOptions is VerifyExportReaderResult with a nil error
// so existing callers that still unpack (*Result, error) keep compiling.
func VerifyExportReaderWithOptions(r io.Reader, pubKey []byte, opts VerifyOptions) (*Result, error) {
	return VerifyExportReaderResult(r, pubKey, opts), nil
}

// VerifyExportWithOptions verifies a file with caller-supplied trust settings.
func VerifyExportWithOptions(path string, pubKey []byte, opts VerifyOptions) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return &Result{Path: path, OK: false, ResultSchema: ResultSchemaV2, Verdict: "FAIL", Errors: []string{err.Error()}}, fmt.Errorf("verifier: open export: %w", err)
	}
	defer f.Close()
	res := VerifyExportReaderResult(f, pubKey, opts)
	res.Path = path
	return res, nil
}

// requireEvidence fails an export that claims (or is asked to prove) more than
// the file contains. aaes.export can carry anchors, timestamps and witnesses:
// an export with none of them is incomplete unless it honestly declares it was
// written before the first anchor interval (pre_anchor). A head that signs
// that flag is trusted; an unsigned header flag still needs an explicit opt-in.
func requireEvidence(exp *ExportFile, res *Result, opts VerifyOptions) {
	if res.AnchorCount == 0 {
		if exp.Header.PreAnchor {
			if exp.Header.Head.PreAnchor {
				res.Warnings = append(res.Warnings, "pre_anchor: the export declares it was written before the first anchor interval; the head is signed but never externally timestamped or witnessed")
			} else if !opts.AllowPreAnchor {
				res.addError("export declares pre_anchor, which the head signature does not cover; pass --allow-pre-anchor to accept an unanchored export")
			} else {
				res.Warnings = append(res.Warnings, "pre_anchor: the export declares it was written before the first anchor interval; the head is signed but never externally timestamped or witnessed")
			}
		} else {
			res.addError("the export contains no anchors, timestamps or witnesses; aaes.export supports them, so an anchorless file is incomplete unless it declares pre_anchor=true")
		}
	}
	if opts.RequireIndependent {
		if res.IndependentWitnesses == 0 && res.TimestampsIndependent == 0 {
			promoteIndependenceLimits(res)
			res.addError("independent verification was requested and this export has zero independent witnesses and zero independent timestamps; an unkeyed head commitment is not an external witness")
		}
	}
}

func promoteIndependenceLimits(res *Result) {
	var kept []string
	for _, w := range res.Warnings {
		if isIndependenceLimit(w) {
			res.addError("%s", w)
			continue
		}
		kept = append(kept, w)
	}
	res.Warnings = kept
}

func isIndependenceLimit(w string) bool {
	return strings.Contains(w, "independent") ||
		strings.Contains(w, "noop placeholder") ||
		strings.Contains(w, "zero independent") ||
		strings.Contains(w, "not a noop") ||
		strings.Contains(w, "TSA trust roots") ||
		strings.Contains(w, "external key holder")
}
