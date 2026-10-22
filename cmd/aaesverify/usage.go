package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/verifier"
	"github.com/aaes-ai/aaesverify/internal/verifytext"
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
	raw, err := verifytext.ReadUsageReport(fs.Arg(0))
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
		ledger, err := verifytext.LedgerKeyFromVerifiedExport(normalized)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
			if errors.Is(err, verifytext.ErrExportUnverified) {
				return 1
			}
			return 2
		}
		opts.LedgerPublicKey = ledger
	}
	res := verifier.VerifyUsageReport(raw, opts)
	if !*jsonOnly {
		fmt.Println(verifytext.RenderUsage(fs.Arg(0), res))
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

const maxUsageReportBytes = verifytext.MaxUsageReportBytes

func readUsageReport(path string) ([]byte, error) { return verifytext.ReadUsageReport(path) }
