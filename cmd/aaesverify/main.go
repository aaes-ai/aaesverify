// Command aaesverify is the slim offline verifier an examiner can run without
// the operator CLI. Flags match aaesctl verify. It never takes --records:
// sidecar binding is aaesctl evidence verify.
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
)

// version and revision are injected by tagged release builds.
var version = "dev"
var revision = "unknown"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("aaesverify", flag.ContinueOnError)
	showVersion := fs.Bool("version", false, "print verifier release, source revision and supported export schema")
	exportPath := fs.String("export", "", "exported JSONL log to verify")
	pubPath := fs.String("pubkey", "", "Ed25519 public key file (hex or base64); omit to use the key embedded in the export")
	tsaRootsPath := fs.String("tsa-roots", "", "PEM bundle of TSA trust roots; without this, timestamps are checked but independence is not claimed")
	witnessTrustPath := fs.String("witness-trust", "", "JSON object mapping trusted witness IDs to hex/base64 public keys obtained independently of the export")
	requireIndependent := fs.Bool("require-independent", false, "require a countersignature or timestamp verified against supplied witness keys or TSA roots")
	allowPreAnchor := fs.Bool("allow-pre-anchor", false, "accept an export that declares pre_anchor when the head signature does not cover that flag")
	jsonOnly := fs.Bool("json", false, "print only the machine-readable JSON summary")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Printf("aaesverify %s (%s), export schema %s\n", version, revision, verifier.ExportSchema)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "aaesverify: unexpected positional arguments")
		return 2
	}
	if *exportPath == "" {
		fmt.Fprintln(os.Stderr, "aaesverify: --export is required")
		return 2
	}

	var pubKey []byte
	if *pubPath != "" {
		raw, err := os.ReadFile(*pubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aaesverify: read public key: %v\n", err)
			return 2
		}
		pubKey, err = verifier.ParsePublicKey(string(raw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
			return 2
		}
	}

	tsaRoots, err := loadTSARoots(*tsaRootsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 2
	}
	witnessKeys, err := loadWitnessTrust(*witnessTrustPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 2
	}
	normalized, err := normalizeExportFile(*exportPath)
	if err != nil {
		res := &verifier.Result{Path: *exportPath, OK: false, Errors: []string{err.Error()}}
		if perr := printVerifyResult(res, *jsonOnly); perr != nil {
			fmt.Fprintf(os.Stderr, "aaesverify: %v\n", perr)
		}
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 1
	}
	res := verifier.VerifyExportReaderResult(bytes.NewReader(normalized), pubKey, verifier.VerifyOptions{
		TSARoots: tsaRoots, TrustedWitnessKeys: witnessKeys, RequireIndependent: *requireIndependent, AllowPreAnchor: *allowPreAnchor,
	})
	res.Path = *exportPath
	if err := printVerifyResult(res, *jsonOnly); err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 1
	}
	if !res.OK {
		return 1
	}
	return 0
}

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

func printVerifyResult(res *verifier.Result, jsonOnly bool) error {
	if !jsonOnly {
		fmt.Println(renderVerify(res))
	}
	b, err := verifier.MarshalResult(res)
	if !jsonOnly {
		fmt.Println("--- json ---")
	}
	fmt.Println(string(b))
	return err
}

func renderVerify(res *verifier.Result) string {
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
	line("chain", verdict(res.ChainOK))
	line("merkle root", verdict(res.RootOK))
	line("head signature", fmt.Sprintf("%s (%s)", verdict(res.SignatureOK), keySourceText(res.KeySource)))
	line("anchors", fmt.Sprintf("%d (%d verified, %d external timestamps of which %d independent, %d independent witnesses)",
		res.AnchorCount, res.AnchorsVerified, res.TimestampsChecked, res.TimestampsIndependent, res.IndependentWitnesses))
	result := "PASS"
	switch {
	case !res.OK:
		result = "FAIL"
	case res.Gapped || len(res.Gaps) > 0:
		result = fmt.Sprintf("OK with gaps (%d range(s))", len(res.Gaps))
	}
	line("result", result)
	return strings.TrimRight(b.String(), "\n")
}

func verdict(ok bool) string {
	if ok {
		return "OK"
	}
	return "FAILED"
}

func keySourceText(src string) string {
	switch src {
	case "supplied":
		return "against supplied public key; key provenance not verified"
	case "embedded":
		return "key embedded in the export: internal consistency only"
	default:
		return src
	}
}
