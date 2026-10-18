package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// rfc8032Seed1 is the RFC 8032 section 7.1 test 1 secret key.
const rfc8032Seed1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func writeUsageReport(t *testing.T, edit func(*verifier.UsageReport)) (string, ed25519.PublicKey) {
	t.Helper()
	seed, _ := hex.DecodeString(rfc8032Seed1)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := verifier.UsageReport{
		Schema: verifier.UsageReportSchema, ReportID: "usr_" + strings.Repeat("1a", 16),
		GeneratedAt: start.AddDate(0, 1, 0), SoftwareVersion: "test", DeploymentID: "dep_test",
		Environment: verifier.EnvironmentProduction,
		Period:      verifier.UsageWindow{Kind: verifier.UsagePeriodCalendarMonth, Start: start, End: start.AddDate(0, 1, 0), Closed: true},
		Totals:      verifier.UsageTotals{GovernedDecisions: 1, PermitRecords: 1},
		Tenants: []verifier.UsageTenant{{
			LogID: hash.DeriveLogID("acme"), GovernedDecisions: 1, PermitRecords: 1,
			FirstSequence: 1, LastSequence: 1, Dedupe: verifier.UsageDedupeFull,
		}},
		Key:          verifier.UsageKey{Algorithm: "ed25519", KeyID: verifier.UsageKeyFingerprint(pub), PublicKey: hex.EncodeToString(pub)},
		KeyRotations: []verifier.UsageKeyRotation{},
	}
	payload, err := verifier.UsageSigningPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	if edit != nil {
		edit(&r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func TestUsageSubcommandVerdicts(t *testing.T) {
	good, pub := writeUsageReport(t, nil)
	edited, _ := writeUsageReport(t, func(r *verifier.UsageReport) { r.Totals.GovernedDecisions = 0 })
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"pinned key", []string{"usage", "--usage-key", hex.EncodeToString(pub), good}, 0, "chain starts at the supplied key"},
		{"embedded key", []string{"usage", good}, 0, "internal consistency only"},
		{"edited report", []string{"usage", edited}, 1, "FAIL"},
		{"wrong pinned key", []string{"usage", "--usage-key", strings.Repeat("00", 32), good}, 1, "not a trusted usage key"},
		{"malformed key", []string{"usage", "--usage-key", "zz", good}, 2, "not a hex Ed25519 public key"},
		{"no report", []string{"usage"}, 2, "usage: aaesverify usage"},
		{"help", []string{"usage", "-h"}, 0, "rotation chain"},
		{"unknown flag", []string{"usage", "--records", "x", good}, 2, ""},
		{"unreadable report", []string{"usage", filepath.Join(t.TempDir(), "absent.json")}, 2, "read usage report"},
		{"beside an export", []string{"usage", "--export", exportFixturePath(t), "--json", good}, 0, `"ok": true`},
		{"unreadable export", []string{"usage", "--export", filepath.Join(t.TempDir(), "absent.jsonl"), good}, 2, "aaesverify:"},
		{"export without a key", []string{"usage", "--export", emptyExport(t), good}, 2, "no readable ledger key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := captureWith(t, tc.args, dispatch)
			if code != tc.code || !strings.Contains(out, tc.want) {
				t.Fatalf("exit %d (want %d), output:\n%s", code, tc.code, out)
			}
		})
	}
}

// emptyExport is the export fixture with every embedded public key removed:
// its format reads, and it names no ledger key.
func emptyExport(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(exportFixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatal(err)
		}
		stripPublicKeys(obj)
		b, _ := json.Marshal(obj)
		out.Write(append(b, '\n'))
	}
	path := filepath.Join(t.TempDir(), "keyless.jsonl")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func stripPublicKeys(v any) {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "public_key")
		for _, e := range x {
			stripPublicKeys(e)
		}
	case []any:
		for _, e := range x {
			stripPublicKeys(e)
		}
	}
}

func TestUsageReportReadIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), maxUsageReportBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUsageReport(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized report read: %v", err)
	}
	if _, code := captureRun(t, []string{"usage", path}); code != 2 {
		t.Fatalf("oversized report exit %d, want 2", code)
	}
}
