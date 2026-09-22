package verifier

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

// VerifyExport verifies an exported log file. The returned error is non-nil
// only when the file cannot be read or parsed; verification failures are
// reported in Result.Errors with Result.OK == false, so one code path can
// handle both a corrupt file and a failing check.
//
// When pubKey is nil the key embedded in the export is used and Result records
// that fact as a warning: an embedded key proves internal consistency only.
// Pass the key out of band to get the stronger claim.
//
// TimestampsIndependent is incremented only when a non-noop token verifies
// against caller-supplied TSA roots (the same property witness.VerifyWithTrust
// establishes). This function supplies no roots, so it never claims timestamp
// independence; a warning is recorded instead and OK may stay true.
func VerifyExport(path string, pubKey []byte) (*Result, error) {
	return VerifyExportWithTrust(path, pubKey, nil)
}

// ParseTSARootsPEM loads a PEM bundle of TSA trust roots. An empty or
// certificate-less bundle is refused: handing VerifyExportWithTrust a nil pool
// means "no independence claimed", and a caller that thought it supplied roots
// must not silently get that weaker reading.
func ParseTSARootsPEM(pemBytes []byte) (*x509.CertPool, error) {
	if len(bytes.TrimSpace(pemBytes)) == 0 {
		return nil, fmt.Errorf("verifier: TSA roots PEM is empty")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("verifier: TSA roots PEM contains no certificates")
	}
	return pool, nil
}

// VerifyExportWithTrust is VerifyExport with TSA trust roots. A non-noop
// timestamp is counted as independent only when the token verifies under those
// roots. A nil pool means roots were not supplied: independence is not claimed.
func VerifyExportWithTrust(path string, pubKey []byte, tsaRoots *x509.CertPool) (*Result, error) {
	return VerifyExportWithOptions(path, pubKey, VerifyOptions{TSARoots: tsaRoots})
}

// VerifyExportReader verifies an exported log from a stream.
func VerifyExportReader(r io.Reader, pubKey []byte) (*Result, error) {
	return VerifyExportReaderWithOptions(r, pubKey, VerifyOptions{})
}

// VerifyExportReaderWithTrust is VerifyExportReader with TSA trust roots.
func VerifyExportReaderWithTrust(r io.Reader, pubKey []byte, tsaRoots *x509.CertPool) (*Result, error) {
	return VerifyExportReaderWithOptions(r, pubKey, VerifyOptions{TSARoots: tsaRoots})
}

func verifyParsed(exp *ExportFile, pubKey []byte, opts VerifyOptions) *Result {
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
	}
	wantLogID := checkHeader(exp, res)

	key, keyErr := resolveKey(exp, pubKey, res)
	if keyErr != nil {
		res.addError("%v", keyErr)
	}
	res.PublicKeyHex = hex.EncodeToString(key)

	st := checkChain(exp.Entries, exp.Header.Head, key)
	res.RecomputedRoot = st.recomputed
	res.ChainOK = st.chainErr == nil
	res.RootOK = st.rootErr == nil
	// A missing or unusable key is not a passing signature check. Reporting
	// signature_ok true because no check could be run is the same class of error
	// as an unsealed receipt: the field would assert something nobody verified.
	res.SignatureOK = keyErr == nil && st.sigErr == nil
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
	// A hole in the sequence numbers is legal only when a tombstone names it.
	// This is the check that makes retention distinguishable from tampering: a
	// range removed under a tombstone verifies as OK WITH GAPS, and the same
	// range removed without one fails here.
	if st.chainErr == nil {
		checkGaps(exp, res)
		// The crypto-shredding report rides the same ordering: it interprets
		// entries, so it runs only once what the entries ARE is established. It
		// adds warnings, never errors — an unreadable-after-shredding field is a
		// recorded erasure, not a chain failure.
		checkShredding(exp, res)
	}

	res.AnchorsOK = true
	leaves := st.leaves
	ev := &verifyEvidence{}
	independentSeen := witnessIdentities{}
	for i, a := range exp.Anchors {
		checkExportAnchor(exp, res, opts, key, leaves, wantLogID, i, a, &independentSeen, ev)
	}

	appendHonestyWarnings(res, opts, ev)
	requireEvidence(exp, res, opts)

	if len(res.Errors) > 0 {
		res.OK = false
	}
	return res
}

// checkHeader verifies the header claims that need no key: the schema, the
// declared entry count, the tenant agreement and the head's log id. It returns
// the log id every signed head in this export must name.
func checkHeader(exp *ExportFile, res *Result) string {
	if exp.Header.Schema != ExportSchema {
		res.addError("unsupported export schema %q, want %q", exp.Header.Schema, ExportSchema)
	}
	if uint64(len(exp.Entries)) != exp.Header.EntryCount {
		res.addError("header declares %d entries, file contains %d", exp.Header.EntryCount, len(exp.Entries))
	}
	if len(exp.Entries) > 0 {
		res.FirstSequence = exp.Entries[0].Sequence
		res.LastSequence = exp.Entries[len(exp.Entries)-1].Sequence
	}
	// The header is NOT covered by the head signature, so it cannot be trusted on
	// its own: editing the tenant label used to relabel a signed export while
	// every hash still verified. Entry tenant ids ARE covered, because they are
	// inside the hash-chained entry, so the header must agree with them.
	for i, e := range exp.Entries {
		if e.TenantID != exp.Header.TenantID {
			res.addError("header names tenant %q and entry %d (sequence %d) belongs to tenant %q; the header is not covered by the head signature, so the disagreement is treated as a relabelled export", exp.Header.TenantID, i, e.Sequence, e.TenantID)
			break
		}
	}
	// The head's log_id is inside the signed payload, so it is the one part of
	// the head that names WHICH log signed it. Requiring it to equal the id
	// derived from the header's tenant closes the cross-log replay: a signed
	// head — with any witness countersignatures over it — taken from another
	// log run under the same signing key carries that other log's id and fails
	// here. An empty id is the legacy pre-log-id shape and fails with its own
	// named error rather than matching nothing against nothing.
	wantLogID := hash.DeriveLogID(exp.Header.TenantID)
	if err := checkHeadLogID(exp.Header.Head, wantLogID); err != nil {
		res.addError("published head: %v", err)
	}
	return wantLogID
}

// appendHonestyWarnings records what the Result does not prove. None of these
// fail an export; they exist so a PASS never asserts more than the file shows.
func appendHonestyWarnings(res *Result, opts VerifyOptions, ev *verifyEvidence) {
	if res.KeySource == "embedded" {
		res.Warnings = append(res.Warnings, "no public key was supplied; the export was verified against the key embedded in it, which proves internal consistency only")
	}
	if res.TimestampsChecked > 0 && res.TimestampsIndependent == 0 {
		switch {
		case opts.TSARoots == nil && ev.sawNonNoopTimestamp:
			res.Warnings = append(res.Warnings, "no TSA trust roots were supplied; timestamps were not counted as independent")
		case !ev.sawNonNoopTimestamp:
			res.Warnings = append(res.Warnings, "every external timestamp is a noop placeholder: no third party attested to these heads")
		default:
			res.Warnings = append(res.Warnings, "no timestamp token verified against the supplied TSA roots")
		}
	}
	if ev.earlierPrefixWitnesses > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d witness countersignature(s) cover an earlier prefix of the log rather than the final published head; they verify, but only a countersignature over the final head is independent evidence for this export", ev.earlierPrefixWitnesses))
	}
	if res.IndependentWitnesses == 0 {
		if res.WitnessesVerified > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%d witness countersignature(s) verify but none matches a trusted independent witness key supplied out of band", res.WitnessesVerified))
		} else {
			res.Warnings = append(res.Warnings, "zero independent witnesses: AAES alone holds the only signature over this history")
		}
	}
}

func resolveKey(exp *ExportFile, pubKey []byte, res *Result) ([]byte, error) {
	var embedded []byte
	if exp.Header.PublicKey != "" {
		k, err := ParsePublicKey(exp.Header.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: embedded public key: %v", ErrMalformed, err)
		}
		embedded = k
	}
	switch {
	case len(pubKey) > 0:
		res.KeySource = "supplied"
		if len(embedded) > 0 && !bytes.Equal(embedded, pubKey) {
			return pubKey, fmt.Errorf("%w: export was signed by %s, verifier was given %s",
				ErrKeyMismatch, hex.EncodeToString(embedded), hex.EncodeToString(pubKey))
		}
		return pubKey, nil
	case len(embedded) > 0:
		res.KeySource = "embedded"
		return embedded, nil
	default:
		return nil, ErrNoPublicKey
	}
}
