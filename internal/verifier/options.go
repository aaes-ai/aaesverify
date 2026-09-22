package verifier

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerifyOptions selects checks beyond internal consistency. Passing
// RequireIndependent is how a caller asks for independent verification: the
// independence limits this package otherwise prints as warnings become errors,
// and an export with zero independent witnesses and zero independent timestamps
// fails. It does not contact a TSA or witness; the tokens and countersignatures
// already in the file are all it uses.
type VerifyOptions struct {
	// TrustedWitnessKeys pins independent witness identities supplied out of band.
	// Exported keys and custody declarations never establish this trust.
	TrustedWitnessKeys map[string][]byte
	TSARoots           *x509.CertPool
	RequireIndependent bool
}

// VerifyExportReaderWithOptions is VerifyExportReader with trust roots and the
// independent-verification demand.
func VerifyExportReaderWithOptions(r io.Reader, pubKey []byte, opts VerifyOptions) (*Result, error) {
	exp, err := LoadExportReader(r)
	if err != nil {
		return &Result{OK: false, Errors: []string{err.Error()}}, nil
	}
	return verifyParsed(exp, pubKey, opts), nil
}

// VerifyExportWithOptions verifies a file with caller-supplied trust settings.
func VerifyExportWithOptions(path string, pubKey []byte, opts VerifyOptions) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return &Result{Path: path, OK: false, Errors: []string{err.Error()}}, fmt.Errorf("verifier: open export: %w", err)
	}
	defer f.Close()
	res, err := VerifyExportReaderWithOptions(f, pubKey, opts)
	if res != nil {
		res.Path = path
	}
	return res, err
}

// requireEvidence fails an export that claims (or is asked to prove) more than
// the file contains. aaes.export/v1 can carry anchors, timestamps and witnesses:
// an export with none of them is incomplete unless it honestly declares it was
// written before the first anchor interval (pre_anchor).
func requireEvidence(exp *ExportFile, res *Result, opts VerifyOptions) {
	if res.AnchorCount == 0 {
		if exp.Header.PreAnchor {
			res.Warnings = append(res.Warnings, "pre_anchor: the export declares it was written before the first anchor interval; the head is signed but never externally timestamped or witnessed")
		} else {
			res.addError("the export contains no anchors, timestamps or witnesses; aaes.export/v1 supports them, so an anchorless file is incomplete unless it declares pre_anchor=true")
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
