package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaes-dev/aaesverify/internal/verifier"
)

// TestMainEntrypointExitsWithRunCode exercises main itself in a subprocess:
// the real entrypoint must relay run's exit code to the process.
func TestMainEntrypointExitsWithRunCode(t *testing.T) {
	if os.Getenv("AAESVERIFY_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainEntrypointExitsWithRunCode$")
	cmd.Env = append(os.Environ(), "AAESVERIFY_MAIN_SUBPROCESS=1")
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("main without --export: err=%v, want exit code 2", err)
	}
}

func TestRunRequiresExport(t *testing.T) {
	out, code := captureRun(t, nil)
	if code != 2 {
		t.Fatalf("no flags exited %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "--export is required") {
		t.Fatalf("usage error not printed:\n%s", out)
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	out, code := captureRun(t, []string{"--bogus-flag"})
	if code != 2 {
		t.Fatalf("unknown flag exited %d, want 2:\n%s", code, out)
	}
}

func TestRunUnreadablePublicKey(t *testing.T) {
	out, code := captureRun(t, []string{
		"--export", fixtureExport(t),
		"--pubkey", filepath.Join(t.TempDir(), "missing.key"),
	})
	if code != 2 || !strings.Contains(out, "read public key") {
		t.Fatalf("unreadable pubkey exited %d:\n%s", code, out)
	}
}

func TestRunRejectsMalformedPublicKey(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(bad, []byte("this is not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"--export", fixtureExport(t), "--pubkey", bad})
	if code != 2 || !strings.Contains(out, "aaesverify:") {
		t.Fatalf("malformed pubkey exited %d:\n%s", code, out)
	}
}

func TestRunUnreadableTSARoots(t *testing.T) {
	out, code := captureRun(t, []string{
		"--export", fixtureExport(t),
		"--tsa-roots", filepath.Join(t.TempDir(), "missing.pem"),
	})
	if code != 2 || !strings.Contains(out, "read TSA roots") {
		t.Fatalf("unreadable TSA roots exited %d:\n%s", code, out)
	}
}

func TestRunRejectsCertificatelessTSARoots(t *testing.T) {
	pem := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(pem, []byte("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"--export", fixtureExport(t), "--tsa-roots", pem})
	if code != 2 || !strings.Contains(out, "no certificates") {
		t.Fatalf("certificateless TSA roots exited %d:\n%s", code, out)
	}
}

func TestRunUnreadableWitnessTrust(t *testing.T) {
	out, code := captureRun(t, []string{
		"--export", fixtureExport(t),
		"--witness-trust", filepath.Join(t.TempDir(), "missing.json"),
	})
	if code != 2 || !strings.Contains(out, "read witness trust") {
		t.Fatalf("unreadable witness trust exited %d:\n%s", code, out)
	}
}

func TestRunWitnessTrustMustBeAnObject(t *testing.T) {
	file := writeWitnessTrust(t, `["not", "an", "object"]`)
	out, code := captureRun(t, []string{"--export", fixtureExport(t), "--witness-trust", file})
	if code != 2 || !strings.Contains(out, "JSON object mapping witness IDs") {
		t.Fatalf("non-object witness trust exited %d:\n%s", code, out)
	}
}

func TestRunWitnessTrustMustNameAKey(t *testing.T) {
	file := writeWitnessTrust(t, `{}`)
	out, code := captureRun(t, []string{"--export", fixtureExport(t), "--witness-trust", file})
	if code != 2 || !strings.Contains(out, "names no trusted keys") {
		t.Fatalf("empty witness trust exited %d:\n%s", code, out)
	}
}

func TestRunWitnessTrustRejectsPaddedWitnessID(t *testing.T) {
	pub := fixturePubKeyHex(t)
	file := writeWitnessTrust(t, `{ " witness-1 ": "`+pub+`" }`)
	out, code := captureRun(t, []string{"--export", fixtureExport(t), "--witness-trust", file})
	if code != 2 || !strings.Contains(out, "empty or padded witness ID") {
		t.Fatalf("padded witness id exited %d:\n%s", code, out)
	}
}

func TestRunWitnessTrustRejectsMalformedKey(t *testing.T) {
	file := writeWitnessTrust(t, `{"witness-1": "definitely not a key"}`)
	out, code := captureRun(t, []string{"--export", fixtureExport(t), "--witness-trust", file})
	if code != 2 || !strings.Contains(out, `witness trust key for "witness-1"`) {
		t.Fatalf("malformed witness key exited %d:\n%s", code, out)
	}
}

// TestRunAcceptsWitnessTrustFile proves a well-formed trust file loads and the
// export still verifies: exit 0 and PASS.
func TestRunAcceptsWitnessTrustFile(t *testing.T) {
	file := writeWitnessTrust(t, `{"witness-1": "`+fixturePubKeyHex(t)+`"}`)
	out, code := captureRun(t, []string{
		"--export", fixtureExport(t),
		"--pubkey", fixturePubKeyPath(t),
		"--witness-trust", file,
	})
	if code != 0 || !strings.Contains(out, "PASS") {
		t.Fatalf("verify with witness trust exited %d:\n%s", code, out)
	}
}

// TestRunMissingExportPrintsResultAndFails is the read/parse failure path: the
// verifier still returns a Result, which must be printed before the exit-1.
func TestRunMissingExportPrintsResultAndFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.jsonl")
	out, code := captureRun(t, []string{"--export", missing})
	if code != 1 {
		t.Fatalf("missing export exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, `"ok": false`) {
		t.Fatalf("failure result not printed as JSON:\n%s", out)
	}
	if !strings.Contains(out, "open export") {
		t.Fatalf("error not reported:\n%s", out)
	}
}

// TestRunTamperedExportFailsVerification flips one hex digit of the head root
// in a copy of the fixture: the file parses, the merkle check fails, and the
// human output must say FAIL with exit 1.
func TestRunTamperedExportFailsVerification(t *testing.T) {
	raw, err := os.ReadFile(fixtureExport(t))
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"root_hash":"2`, `"root_hash":"3`, 1)
	if tampered == string(raw) {
		t.Fatal("fixture did not contain a root_hash to tamper")
	}
	copy := filepath.Join(t.TempDir(), "tampered.jsonl")
	if err := os.WriteFile(copy, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"--export", copy, "--pubkey", fixturePubKeyPath(t)})
	if code != 1 {
		t.Fatalf("tampered export exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "result:") || !strings.Contains(out, "FAIL") {
		t.Fatalf("human output does not say FAIL:\n%s", out)
	}
	if !strings.Contains(out, `"ok": false`) {
		t.Fatalf("JSON summary does not record the failure:\n%s", out)
	}
}

// TestRenderVerifyReportsGaps covers the "OK with gaps" reading: a gapped but
// otherwise valid export passes with the gap count named.
func TestRenderVerifyReportsGaps(t *testing.T) {
	res := &verifier.Result{
		OK:   true,
		Gaps: []verifier.GapView{{FromSequence: 3, ToSequence: 6}, {FromSequence: 9, ToSequence: 9}},
	}
	res.Gapped = true
	out := renderVerify(res)
	if !strings.Contains(out, "OK with gaps (2 range(s))") {
		t.Fatalf("gapped result rendered as:\n%s", out)
	}
}

func TestVerdictAndKeySourceText(t *testing.T) {
	if got := verdict(false); got != "FAILED" {
		t.Fatalf("verdict(false) = %q, want FAILED", got)
	}
	if got := keySourceText("embedded"); !strings.Contains(got, "internal consistency only") {
		t.Fatalf("embedded key source = %q", got)
	}
	if got := keySourceText("unanticipated"); got != "unanticipated" {
		t.Fatalf("unknown key source = %q, want passthrough", got)
	}
}

func fixtureExport(t *testing.T) string {
	t.Helper()
	return filepath.Join(moduleDir(t), "testdata", "export_v1.jsonl")
}

func fixturePubKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(moduleDir(t), "testdata", "public_key.hex")
}

func fixturePubKeyHex(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(fixturePubKeyPath(t))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func writeWitnessTrust(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "witness.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
