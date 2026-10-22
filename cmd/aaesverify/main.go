// Command aaesverify is the slim offline verifier an examiner can run without
// the operator CLI. Export flags match aaesctl verify. Tree-specific evidence
// modes (the open verifier's --records and --evaluation) live in modes.go.
// "aaesverify usage <report>" checks a signed usage report (ADR-029).
//
// open/aaesverify/sync.sh copies this file into the open verifier verbatim
// apart from module paths; modes.go is the one file each tree keeps.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/verifier"
	"github.com/aaes-ai/aaesverify/internal/verifytext"
)

// version and revision are injected by tagged release builds.
var version = "dev"
var revision = "unknown"

func main() { os.Exit(dispatch(os.Args[1:])) }

// dispatch routes the usage subcommand; everything else is export
// verification.
func dispatch(args []string) int {
	if len(args) > 0 && args[0] == "usage" {
		return runUsage(args[1:])
	}
	return run(args)
}

func run(args []string) int { return verifyExport(args, verifier.MarshalResult) }

// exportFlags is the parsed command line of export and receipt verification.
type exportFlags struct {
	showVersion        *bool
	exportPath         *string
	receiptPath        *string
	pubPath            *string
	tsaRootsPath       *string
	witnessTrustPath   *string
	keyringPath        *string
	expectedFinalPath  *string
	requireIndependent *bool
	allowPreAnchor     *bool
	jsonOnly           *bool
	modes              *evidenceModes
}

func newExportFlags(fs *flag.FlagSet) *exportFlags {
	f := &exportFlags{}
	f.showVersion = fs.Bool("version", false, "print verifier release, source revision and supported export schema")
	f.exportPath = fs.String("export", "", "exported JSONL log to verify")
	f.receiptPath = fs.String("receipt", "", "aaes.trust-receipt/v1 JSON document to verify")
	f.pubPath = fs.String("pubkey", "", "Ed25519 public key file (hex or base64); required with --receipt; with --export it is the trust anchor and an export signed by any other key fails")
	f.tsaRootsPath = fs.String("tsa-roots", "", "PEM bundle of TSA trust roots; without this, timestamps are checked but independence is not claimed")
	f.witnessTrustPath = fs.String("witness-trust", "", "JSON object mapping trusted witness IDs to hex/base64 public keys obtained independently of the export")
	f.keyringPath = fs.String("keyring", "", "aaes.export/v4: JSON object mapping the log's authorised key ids to hex/base64 public keys obtained independently of the export")
	f.expectedFinalPath = fs.String("expected-final", "", "aaes.export/v4: JSON file with the expected final head {log_id, index, root_hash, tree_size}; the only mode that can verify a v4 export as current evidence")
	f.requireIndependent = fs.Bool("require-independent", false, "require a countersignature or timestamp verified against supplied witness keys or TSA roots")
	f.allowPreAnchor = fs.Bool("allow-pre-anchor", false, "accept an export that declares pre_anchor when the head signature does not cover that flag")
	f.jsonOnly = fs.Bool("json", false, "print only the machine-readable JSON summary")
	f.modes = registerEvidenceModes(fs)
	return f
}

// verifyExport is run with the result encoder marshal, so a test can present
// an encoder that fails and see the fallback JSON exit non-zero.
func verifyExport(args []string, marshal func(*verifier.Result) ([]byte, error)) int {
	fs := flag.NewFlagSet("aaesverify", flag.ContinueOnError)
	f := newExportFlags(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *f.showVersion {
		fmt.Printf("aaesverify %s (%s), export schema %s\n", version, revision, verifier.ExportSchema)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "aaesverify: unexpected positional arguments")
		return 2
	}
	if err := f.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 2
	}
	pubKey, err := loadCommandPublicKey(*f.pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 2
	}
	if *f.receiptPath != "" {
		return runTrustReceipt(*f.receiptPath, pubKey, *f.jsonOnly)
	}
	opts, err := f.verifyOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 2
	}
	if f.modes.standalone() {
		return f.modes.run(pubKey, opts, *f.jsonOnly)
	}
	return f.verifyExportFile(pubKey, opts, marshal)
}

// validate refuses flag combinations before any file is read.
func (f *exportFlags) validate() error {
	if err := f.modes.validate(*f.exportPath, *f.receiptPath); err != nil {
		return err
	}
	if f.modes.standalone() {
		return nil
	}
	if err := validateCommandMode(*f.exportPath, *f.receiptPath, *f.pubPath, *f.tsaRootsPath, *f.witnessTrustPath, *f.requireIndependent, *f.allowPreAnchor); err != nil {
		return err
	}
	if *f.receiptPath != "" && (*f.keyringPath != "" || *f.expectedFinalPath != "") {
		return errors.New("--keyring and --expected-final apply only to --export")
	}
	return nil
}

// verifyOptions loads every caller-supplied trust input.
func (f *exportFlags) verifyOptions() (verifier.VerifyOptions, error) {
	opts := verifier.VerifyOptions{RequireIndependent: *f.requireIndependent, AllowPreAnchor: *f.allowPreAnchor}
	var err error
	if opts.TSARoots, err = loadTSARoots(*f.tsaRootsPath); err != nil {
		return opts, err
	}
	if opts.TrustedWitnessKeys, err = loadWitnessTrust(*f.witnessTrustPath); err != nil {
		return opts, err
	}
	if opts.Keyring, err = verifytext.LoadKeyring(*f.keyringPath); err != nil {
		return opts, err
	}
	if opts.ExpectedFinal, err = verifytext.LoadHeadPin(*f.expectedFinalPath); err != nil {
		return opts, err
	}
	return opts, nil
}

func (f *exportFlags) verifyExportFile(pubKey []byte, opts verifier.VerifyOptions, marshal func(*verifier.Result) ([]byte, error)) int {
	normalized, err := normalizeExportFile(*f.exportPath)
	if err != nil {
		res := &verifier.Result{Path: *f.exportPath, OK: false, ResultSchema: verifier.ResultSchemaV2, Verdict: "FAIL", Errors: []string{err.Error()}}
		if perr := printVerifyResult(res, *f.jsonOnly, marshal); perr != nil {
			fmt.Fprintf(os.Stderr, "aaesverify: %v\n", perr)
		}
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 1
	}
	parsed, loadErr := verifier.LoadExportReader(bytes.NewReader(normalized))
	var res *verifier.Result
	if loadErr != nil {
		res = &verifier.Result{OK: false, ResultSchema: verifier.ResultSchemaV2, Verdict: "FAIL", Errors: []string{loadErr.Error()}}
	} else {
		res = verifier.VerifyParsedExport(parsed, pubKey, opts)
	}
	res.Path = *f.exportPath
	if code, bound := f.modes.bind(parsed, res, *f.jsonOnly); bound {
		return code
	}
	if err := printVerifyResult(res, *f.jsonOnly, marshal); err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 1
	}
	if !res.OK {
		return 1
	}
	return 0
}

// normalizeExportFile checks the supported format without rewriting bytes.
func normalizeExportFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open export: %w", err)
	}
	defer f.Close()
	return verifier.NormalizeExportReader(f)
}

func loadTSARoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read TSA roots: %w", err)
	}
	return verifier.ParseTSARootsPEM(raw)
}

func loadWitnessTrust(path string) (map[string][]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read witness trust: %w", err)
	}
	var encoded map[string]string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("witness trust must be a JSON object mapping witness IDs to public keys: %w", err)
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("witness trust file names no trusted keys")
	}
	keys := make(map[string][]byte, len(encoded))
	for id, text := range encoded {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(id) != id {
			return nil, fmt.Errorf("witness trust contains an empty or padded witness ID")
		}
		key, err := verifier.ParsePublicKey(text)
		if err != nil {
			return nil, fmt.Errorf("witness trust key for %q: %w", id, err)
		}
		keys[id] = key
	}
	return keys, nil
}

func printVerifyResult(res *verifier.Result, jsonOnly bool, marshal func(*verifier.Result) ([]byte, error)) error {
	if !jsonOnly {
		fmt.Println(renderVerify(res))
	}
	b, err := marshal(res)
	if !jsonOnly {
		fmt.Println("--- json ---")
	}
	fmt.Println(string(b))
	return err
}

func renderVerify(res *verifier.Result) string { return verifytext.Render(res) }

func verdict(ok bool) string { return verifytext.Verdict(ok) }

func keySourceText(src string) string { return verifytext.KeySource(src) }
