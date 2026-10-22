package verifytext

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

func TestRenderPreservesVerificationLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result verifier.Result
		want   string
	}{
		{"failed", verifier.Result{OK: false, IndependentWitnesses: 1}, "FAIL"},
		{"consistent", verifier.Result{OK: true}, "CONSISTENT"},
		{"independent", verifier.Result{OK: true, IndependentWitnesses: 1}, "PASS"},
		{"gapped", verifier.Result{OK: true, Gaps: []verifier.GapView{{FromSequence: 2, ToSequence: 4}, {FromSequence: 7, ToSequence: 9}}}, "OK with gaps (2 range(s) removed under retention: 2..4, 7..9)"},
		{"gapped without ranges", verifier.Result{OK: true, Gapped: true}, "OK with gaps (0 range(s) removed under retention: )"},
		{"shredded", verifier.Result{OK: true, ShredEvents: []verifier.ShredEventView{{}}, ProtectedEntries: 3}, "OK with shredded fields (1 key destruction(s) recorded; 3 entries carry encrypted identifiers)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.result.Path = "fixture.jsonl"
			tc.result.ChainOK = true
			tc.result.KeySource = "supplied"
			tc.result.Warnings = []string{"first warning", "second warning"}
			tc.result.Errors = []string{"first error", "second error"}
			got := Render(&tc.result)
			for _, want := range []string{tc.want, "fixture.jsonl", "first warning", "second warning", "first error", "second error", "against supplied public key; key provenance not verified"} {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q in %s", want, got)
				}
			}
			if strings.HasSuffix(got, "\n") {
				t.Fatal("summary has a trailing newline")
			}
		})
	}
	if Verdict(true) != "OK" || Verdict(false) != "FAILED" {
		t.Fatal("verification verdict changed")
	}
	for _, tc := range []struct{ source, want string }{{"supplied", "against supplied public key; key provenance not verified"}, {"embedded", "key embedded in the export: internal consistency only"}, {"future", "future"}} {
		if got := KeySource(tc.source); got != tc.want {
			t.Fatalf("key source %s: %s", tc.source, got)
		}
	}
}

func TestRenderUsageKeepsKeyProvenanceAndErrors(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		result := verifier.UsageResult{OK: supplied, RootKeyFingerprint: "fixture-key", Errors: []string{"first refusal", "second refusal"}}
		result.Report = verifier.UsageReport{ReportID: "fixture-report", DeploymentID: "fixture-deployment", Environment: "test", LicenseID: "fixture-license", Period: verifier.UsageWindow{Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), Closed: true}}
		wantKey, wantResult := "embedded key: internal consistency only", "FAIL"
		if supplied {
			result.KeySource = verifier.UsageKeySupplied
			wantKey = "chain starts at the supplied key"
			wantResult = "OK"
		}
		got := RenderUsage("usage.json", result)
		for _, want := range []string{"usage.json", "fixture-report", "fixture-deployment (test), license fixture-license", "2026-01-01..2026-02-01 closed=true", wantKey, wantResult, "first refusal", "second refusal"} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q in %s", want, got)
			}
		}
	}
}

func TestUsageReportReadsAreBoundedAndRefuseIOFailures(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "report.json")
	raw := []byte(`{"fixture":true}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadUsageReport(path); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("report changed: %s %v", got, err)
	}
	if _, err := ReadUsageReport(filepath.Join(root, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing report: %v", err)
	}
	if _, err := ReadUsageReport(root); err == nil {
		t.Fatal("directory accepted as a report")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), MaxUsageReportBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUsageReport(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized report: %v", err)
	}
}

func TestLedgerKeyRequiresVerifiedExport(t *testing.T) {
	raw := readExportFixture(t)
	verified := verifier.VerifyExportReaderResult(bytes.NewReader(raw), nil, verifier.VerifyOptions{AllowPreAnchor: true})
	if !verified.OK {
		t.Fatalf("fixture does not verify: %v", verified.Errors)
	}
	want, err := hex.DecodeString(verified.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LedgerKeyFromVerifiedExport(raw)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("verified key: %x %v", got, err)
	}
	tampered := bytes.Replace(raw, []byte(`"record_hash":"`), []byte(`"record_hash":"0`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper fixture did not change")
	}
	if _, err := LedgerKeyFromVerifiedExport(tampered); !errors.Is(err, ErrExportUnverified) {
		t.Fatalf("unverified key trusted: %v", err)
	}
	if _, err := LedgerKeyFromVerifiedExport([]byte("invalid\n")); err == nil || !strings.Contains(err.Error(), "no readable ledger key") {
		t.Fatalf("keyless export: %v", err)
	}
}

// readExportFixture reads the v2 export fixture from the monorepo's
// store_versions testdata or, in the open verifier tree, from the CLI's
// testdata. A tree that has neither fails rather than skipping.
func readExportFixture(t *testing.T) []byte {
	t.Helper()
	for _, path := range []string{
		filepath.Join("..", "store_versions", "testdata", "export_v2.jsonl"),
		filepath.Join("..", "..", "cmd", "aaesverify", "testdata", "export_v2.jsonl"),
	} {
		raw, err := os.ReadFile(path)
		if err == nil {
			return raw
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	t.Fatal("no export_v2.jsonl fixture in this tree")
	return nil
}
