// Package verifytext is the human summary shared by aaesctl and aaesverify.
package verifytext

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// MaxUsageReportBytes bounds a usage-report read. Real reports are a few
// kilobytes per tenant; the cap refuses a file that would exhaust memory.
const MaxUsageReportBytes = 16 << 20

// ErrExportUnverified is a ledger export that parsed but did not verify.
var ErrExportUnverified = errors.New("export does not verify")

func Render(res *verifier.Result) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-22s %s\n", k+":", v) }
	line("export", res.Path)
	line("schema", res.Schema)
	line("log id", res.LogID)
	line("tenant", res.TenantID)
	line("entries", fmt.Sprintf("%d (sequence %d..%d, header declares %d)",
		res.EntryCount, res.FirstSequence, res.LastSequence, res.DeclaredEntryCount))
	line("head", fmt.Sprintf("tree_size=%d index=%d", res.HeadTreeSize, res.HeadIndex))
	line("head root", res.HeadRoot)
	line("head signed at", res.HeadSignedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"))
	line("recomputed root", res.RecomputedRoot)
	line("chain", Verdict(res.ChainOK))
	line("merkle root", Verdict(res.RootOK))
	line("head signature", fmt.Sprintf("%s (%s)", Verdict(res.SignatureOK), KeySource(res.KeySource)))
	line("anchors", fmt.Sprintf("%d (%d verified, %d external timestamps of which %d independent, %d independent witnesses)",
		res.AnchorCount, res.AnchorsVerified, res.TimestampsChecked, res.TimestampsIndependent, res.IndependentWitnesses))
	if len(res.Warnings) > 0 {
		for i, w := range res.Warnings {
			if i == 0 {
				line("warnings", w)
			} else {
				line("", w)
			}
		}
	}
	if len(res.Errors) > 0 {
		for i, e := range res.Errors {
			if i == 0 {
				line("errors", e)
			} else {
				line("", e)
			}
		}
	}
	// A gapped export verifies and is not complete. Rendering that as a bare
	// PASS would be the one claim this tool must never make: "I verified what
	// you gave me" is not "you gave me everything".
	var result string
	switch {
	case !res.OK:
		result = "FAIL"
	case res.Gapped || len(res.Gaps) > 0:
		result = fmt.Sprintf("OK with gaps (%d range(s) removed under retention: %s)", len(res.Gaps), gapRanges(res.Gaps))
	case len(res.ShredEvents) > 0:
		// Same honesty rule as a gapped export: the chain verified, but a
		// recorded key destruction means some identifier fields are ciphertext
		// nobody can read, and the headline must say so.
		result = fmt.Sprintf("OK with shredded fields (%d key destruction(s) recorded; %d entries carry encrypted identifiers)", len(res.ShredEvents), res.ProtectedEntries)
	default:
		result = headline(res)
	}
	line("result", result)
	return strings.TrimRight(b.String(), "\n")
}

// headline is the verifier's own verdict when it set one. A v4 result that
// verified only a scoped property carries a scoped label, and printing
// IntegrityHeadline instead would read as current evidence.
func headline(res *verifier.Result) string {
	switch res.Verdict {
	case "":
		return res.IntegrityHeadline()
	case verifier.VerdictUnpinnedV4:
		return res.Verdict + " (no freshness pin: internal consistency only, not current v4 evidence)"
	case verifier.VerdictContinuityV4:
		return res.Verdict + " (continuity from the pinned cutover head only; later leaves may be hidden)"
	case verifier.VerdictFloorV4:
		return res.Verdict + " (tree-size floor only: neither continuity nor freshness)"
	default:
		return res.Verdict
	}
}

func gapRanges(gaps []verifier.GapView) string {
	names := make([]string, 0, len(gaps))
	for _, g := range gaps {
		names = append(names, fmt.Sprintf("%d..%d", g.FromSequence, g.ToSequence))
	}
	return strings.Join(names, ", ")
}

func Verdict(ok bool) string {
	if ok {
		return "OK"
	}
	return "FAILED"
}

func KeySource(src string) string {
	switch src {
	case "supplied":
		return "against supplied public key; key provenance not verified"
	case "keyring":
		return "against the caller-pinned key or keyring; key provenance not verified"
	case "embedded":
		return "key embedded in the export: internal consistency only"
	default:
		return src
	}
}

// RenderUsage is the examiner layout for one usage-report result.
func RenderUsage(path string, res verifier.UsageResult) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-22s %s\n", k+":", v) }
	r := res.Report
	line("usage report", path)
	line("report id", r.ReportID)
	line("deployment", fmt.Sprintf("%s (%s), license %s", r.DeploymentID, r.Environment, r.LicenseID))
	line("period", fmt.Sprintf("%s..%s closed=%v", r.Period.Start.Format("2006-01-02"), r.Period.End.Format("2006-01-02"), r.Period.Closed))
	line("governed decisions", fmt.Sprintf("%d (records: %d permit, %d refusal, %d deferral)",
		r.Totals.GovernedDecisions, r.Totals.PermitRecords, r.Totals.RefusalRecords, r.Totals.DeferralRecords))
	line("tenants", fmt.Sprintf("%d", len(r.Tenants)))
	switch res.KeySource {
	case verifier.UsageKeySupplied:
		line("usage key", res.RootKeyFingerprint+" (chain starts at the supplied key)")
	default:
		line("usage key", res.RootKeyFingerprint+" (embedded key: internal consistency only)")
	}
	for i, e := range res.Errors {
		if i == 0 {
			line("errors", e)
		} else {
			line("", e)
		}
	}
	result := "OK"
	if !res.OK {
		result = "FAIL"
	}
	line("result", result)
	return strings.TrimRight(b.String(), "\n")
}

// ReadUsageReport reads a report up to MaxUsageReportBytes.
func ReadUsageReport(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxUsageReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxUsageReportBytes {
		return nil, fmt.Errorf("report exceeds %d bytes", MaxUsageReportBytes)
	}
	return raw, nil
}

// LedgerKeyFromVerifiedExport returns the ledger public key of an export that
// verified. A parsed export that is not OK is ErrExportUnverified.
func LedgerKeyFromVerifiedExport(normalized []byte) ([]byte, error) {
	export := verifier.VerifyExportReaderResult(bytes.NewReader(normalized), nil, verifier.VerifyOptions{AllowPreAnchor: true})
	key, err := hex.DecodeString(export.PublicKeyHex)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("the export names no readable ledger key")
	}
	if !export.OK {
		return nil, fmt.Errorf("%w, so its ledger key cannot be trusted: %v", ErrExportUnverified, export.Errors)
	}
	return key, nil
}
