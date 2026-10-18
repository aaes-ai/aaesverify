package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

const usageHelp = `usage: aaesverify usage [--usage-key <hex>] [--export <file>] [--json] <report>

Checks an aaes.usage-report/1 offline: schema, signature, the usage-key
rotation chain and the internal sums. --usage-key pins the deployment's
onboarded usage public key; without it the report is checked against its
embedded key, which proves internal consistency only. --export names an
export of the same deployment; a report signed by that export's ledger key
is refused.

A pinned key stays trusted after it is rotated away, because this command
checks one report and not the sequence of reports. If an old usage key may be
compromised, compare the report with the deployment's previous reports.
`

// runUsage verifies one usage report. It never recounts: a recount needs
// the records sidecar, which is aaesctl usage verify --records.
func runUsage(args []string) int {
	fs := flag.NewFlagSet("aaesverify usage", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usageHelp); fs.PrintDefaults() }
	keyHex := fs.String("usage-key", "", "hex Ed25519 usage public key recorded at onboarding")
	exportPath := fs.String("export", "", "export of the same deployment, to refuse a report signed by its ledger key")
	jsonOnly := fs.Bool("json", false, "print only the machine-readable JSON summary")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usageHelp)
		return 2
	}
	raw, err := readUsageReport(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: read usage report: %v\n", err)
		return 2
	}
	var opts verifier.UsageVerifyOptions
	if *keyHex != "" {
		pub, err := hex.DecodeString(strings.TrimSpace(*keyHex))
		if err != nil || len(pub) != 32 {
			fmt.Fprintln(os.Stderr, "aaesverify: --usage-key is not a hex Ed25519 public key")
			return 2
		}
		opts.TrustedKeyFingerprints = []string{verifier.UsageKeyFingerprint(pub)}
	}
	if *exportPath != "" {
		normalized, err := normalizeExportFile(*exportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
			return 2
		}
		export := verifier.VerifyExportReaderResult(bytes.NewReader(normalized), nil, verifier.VerifyOptions{AllowPreAnchor: true})
		ledger, err := hex.DecodeString(export.PublicKeyHex)
		if err != nil || len(ledger) == 0 {
			fmt.Fprintln(os.Stderr, "aaesverify: the export names no readable ledger key")
			return 2
		}
		if !export.OK {
			fmt.Fprintf(os.Stderr, "aaesverify: the export does not verify, so its ledger key cannot be trusted: %v\n", export.Errors)
			return 1
		}
		opts.LedgerPublicKey = ledger
	}
	res := verifier.VerifyUsageReport(raw, opts)
	if !*jsonOnly {
		fmt.Println(renderUsage(fs.Arg(0), res))
		fmt.Println("--- json ---")
	}
	// UsageResult holds only strings, booleans and a string slice, so it
	// always marshals.
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
	if !res.OK {
		return 1
	}
	return 0
}

// maxUsageReportBytes bounds the report read so a crafted file cannot exhaust
// an examiner's memory; real reports are a few kilobytes per tenant.
const maxUsageReportBytes = 16 << 20

func readUsageReport(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxUsageReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxUsageReportBytes {
		return nil, fmt.Errorf("report exceeds %d bytes", maxUsageReportBytes)
	}
	return raw, nil
}

func renderUsage(path string, res verifier.UsageResult) string {
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
