package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
	"github.com/aaes-ai/aaesverify/internal/verifier"
)

func TestRunReceiptRoundTripFromVerifiedExport(t *testing.T) {
	receiptPath := produceFixtureReceipt(t)
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t)})
	if code != 0 {
		t.Fatalf("aaesverify --receipt exited %d:\n%s", code, out)
	}
	for _, want := range []string{"inclusion proof", "head signature", "claims", "result:", "CONSISTENT"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output lacks %q:\n%s", want, out)
		}
	}
	out, code = captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t), "--json"})
	if code != 0 {
		t.Fatalf("aaesverify --receipt --json exited %d:\n%s", code, out)
	}
	var res struct {
		OK      bool   `json:"ok"`
		Schema  string `json:"schema"`
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		t.Fatalf("JSON-only output: %v\n%s", err, out)
	}
	if !res.OK || res.Schema != verifier.TrustReceiptSchema || res.Verdict != "CONSISTENT" {
		t.Fatalf("receipt result = %+v", res)
	}
}

func TestRunReceiptFlagRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		contains string
	}{
		{name: "public key required", args: []string{"--receipt", "receipt.json"}, contains: "--pubkey is required"},
		{name: "export is exclusive", args: []string{"--receipt", "receipt.json", "--export", "export.jsonl"}, contains: "mutually exclusive"},
		{name: "independence flags are export only", args: []string{"--receipt", "receipt.json", "--pubkey", "key.pub", "--require-independent"}, contains: "only to --export"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := captureRun(t, tc.args)
			if code != 2 || !strings.Contains(out, tc.contains) {
				t.Fatalf("exit %d, output:\n%s", code, out)
			}
		})
	}
}

func TestRunReceiptRejectsInjectedOutcomeInJSONMode(t *testing.T) {
	receiptPath := produceFixtureReceipt(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["class"] = "executed"
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t), "--json"})
	if code != 1 || !strings.Contains(out, `"ok":false`) || !strings.Contains(out, "unknown field") {
		t.Fatalf("injected outcome exited %d:\n%s", code, out)
	}
	if strings.Contains(out, "result:") || strings.Contains(out, "--- json ---") {
		t.Fatalf("--json emitted human output:\n%s", out)
	}
}

func TestRunReceiptRejectsDuplicateKeys(t *testing.T) {
	receiptPath := produceFixtureReceipt(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt verifier.TrustReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	targets := []struct {
		name        string
		key         string
		escaped     string
		folded      string
		conflicting string
		identical   string
	}{
		{name: "top level schema", key: "schema", escaped: `sch\u0065ma`, folded: "Schema", conflicting: "aaes.trust-receipt/v2", identical: verifier.TrustReceiptSchema},
		{name: "entry", key: "tenant_id", escaped: `tenant\u005fid`, folded: "Tenant_ID", conflicting: "other", identical: receipt.Entry.TenantID},
		{name: "head", key: "log_id", escaped: `log\u005fid`, folded: "Log_Id", conflicting: "other", identical: receipt.Head.LogID},
		{name: "proof", key: "root_hash", escaped: `root\u005fhash`, folded: "Root_Hash", conflicting: "other", identical: receipt.Proof.RootHash},
		{name: "claims", key: "proves", escaped: `pro\u0076es`, folded: "Proves", conflicting: "execution", identical: receipt.Claims.Proves},
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			tests := []struct {
				name     string
				spelling string
				value    string
				reported string
			}{
				{name: "conflicting", spelling: target.key, value: target.conflicting, reported: target.key},
				{name: "identical", spelling: target.key, value: target.identical, reported: target.key},
				{name: "conflicting escaped", spelling: target.escaped, value: target.conflicting, reported: target.key},
				{name: "identical escaped", spelling: target.escaped, value: target.identical, reported: target.key},
				{name: "conflicting fold", spelling: target.folded, value: target.conflicting, reported: target.folded},
				{name: "identical fold", spelling: target.folded, value: target.identical, reported: target.folded},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					duplicate := duplicateReceiptMember(t, raw, target.key, tc.spelling, tc.value)
					path := filepath.Join(t.TempDir(), "duplicate.json")
					if err := os.WriteFile(path, duplicate, 0o600); err != nil {
						t.Fatal(err)
					}
					out, code := captureRun(t, []string{"--receipt", path, "--pubkey", fixturePubKeyPath(t), "--json"})
					want := `duplicate object key "` + tc.reported + `"`
					if code != 1 || !strings.Contains(out, want) || strings.Contains(out, "CONSISTENT") {
						t.Fatalf("duplicate receipt exited %d or lacked %q:\n%s", code, want, out)
					}
				})
			}
		})
	}
}

func duplicateReceiptMember(t *testing.T, raw []byte, key, spelling, value string) []byte {
	t.Helper()
	marker := `"` + key + `":`
	if !strings.Contains(string(raw), marker) {
		t.Fatalf("receipt does not contain member %q", marker)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := marker + string(encoded) + `,"` + spelling + `":`
	return []byte(strings.Replace(string(raw), marker, duplicate, 1))
}

func TestRunReceiptVerifiesProducerGeneratedGolden(t *testing.T) {
	receiptPath := filepath.Join(moduleDir(t), "testdata", "producer_receipt.json")
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t)})
	if code != 0 || !strings.Contains(out, "CONSISTENT") {
		t.Fatalf("producer-generated golden receipt exited %d:\n%s", code, out)
	}
}

func TestRunReceiptRejectsForgedDecision(t *testing.T) {
	receiptPath := produceFixtureReceipt(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt verifier.TrustReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Entry.RecordHash = "forged"
	raw, err = receipt.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t), "--json"})
	if code != 1 || !strings.Contains(out, `"ok":false`) || !strings.Contains(out, "recomputed from the entry") {
		t.Fatalf("forged receipt exited %d:\n%s", code, out)
	}
}

func TestRunReceiptRefusesTombstone(t *testing.T) {
	receiptPath, pubKeyPath := produceTombstoneFixtureReceipt(t)
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", pubKeyPath, "--json"})
	if code != 1 || !strings.Contains(out, `"ok":false`) || !strings.Contains(out, "tombstone entries are not decision receipts") {
		t.Fatalf("tombstone receipt exited %d:\n%s", code, out)
	}
}

func TestRunReceiptReportsValidAnchor(t *testing.T) {
	receiptPath := produceFixtureReceipt(t)
	mutateReceiptFixture(t, receiptPath, func(r *verifier.TrustReceipt) {
		r.Anchor = &verifier.AnchorView{
			Head:      *r.Head,
			Witnesses: []verifier.WitnessView{{WitnessID: "unchecked", Signature: []byte("forged")}},
		}
	})
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t)})
	if code != 0 || !strings.Contains(out, "present, head signature OK, witnesses not checked") {
		t.Fatalf("valid anchor human output exited %d:\n%s", code, out)
	}
	out, code = captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t), "--json"})
	if code != 0 {
		t.Fatalf("valid anchor JSON output exited %d:\n%s", code, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		t.Fatal(err)
	}
	if res["anchor_present"] != true || res["anchor_head_signature_ok"] != true {
		t.Fatalf("valid anchor JSON fields = %+v", res)
	}
}

func TestRunReceiptReportsAbsentAnchor(t *testing.T) {
	receiptPath := produceFixtureReceipt(t)
	mutateReceiptFixture(t, receiptPath, func(r *verifier.TrustReceipt) { r.Anchor = nil })
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t)})
	if code != 0 || !strings.Contains(out, "anchor:") || !strings.Contains(out, "absent") {
		t.Fatalf("absent anchor human output exited %d:\n%s", code, out)
	}
	out, code = captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t), "--json"})
	if code != 0 {
		t.Fatalf("absent anchor JSON output exited %d:\n%s", code, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		t.Fatal(err)
	}
	if present, ok := res["anchor_present"]; !ok || present != false {
		t.Fatalf("absent anchor JSON fields = %+v", res)
	}
	if _, ok := res["anchor_head_signature_ok"]; ok {
		t.Fatalf("absent anchor has head signature field: %+v", res)
	}
}

func TestRunReceiptRejectsForgedAnchorHead(t *testing.T) {
	receiptPath := produceFixtureReceipt(t)
	mutateReceiptFixture(t, receiptPath, func(r *verifier.TrustReceipt) {
		r.Anchor = &verifier.AnchorView{Head: *r.Head}
		r.Anchor.Head.RootHash = strings.Repeat("0", 64)
	})
	out, code := captureRun(t, []string{"--receipt", receiptPath, "--pubkey", fixturePubKeyPath(t), "--json"})
	if code != 1 || !strings.Contains(out, "anchor head") || strings.Contains(out, "CONSISTENT") {
		t.Fatalf("forged anchor head exited %d:\n%s", code, out)
	}
}

func mutateReceiptFixture(t *testing.T, path string, edit func(*verifier.TrustReceipt)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt verifier.TrustReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	edit(&receipt)
	raw, err = receipt.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunReceiptReadFailureHasJSONResult(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	out, code := captureRun(t, []string{"--receipt", missing, "--pubkey", fixturePubKeyPath(t), "--json"})
	if code != 1 || !strings.Contains(out, `"ok":false`) || !strings.Contains(out, "read receipt") {
		t.Fatalf("missing receipt exited %d:\n%s", code, out)
	}
}

func produceFixtureReceipt(t *testing.T) string {
	t.Helper()
	exportPath := fixtureExport(t)
	pubRaw, err := os.ReadFile(fixturePubKeyPath(t))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := verifier.ParsePublicKey(string(pubRaw))
	if err != nil {
		t.Fatal(err)
	}
	res, err := verifier.VerifyExportWithOptions(exportPath, pub, verifier.VerifyOptions{AllowPreAnchor: true})
	if err != nil || !res.OK {
		t.Fatalf("source export is not verified: %v %+v", err, res)
	}
	exp, err := verifier.LoadExport(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Entries) == 0 {
		t.Fatal("source export has no entries")
	}
	leaves := make([]string, len(exp.Entries))
	for i := range exp.Entries {
		leaf, err := exp.Entries[i].RecomputeLeaf()
		if err != nil {
			t.Fatal(err)
		}
		if leaf != exp.Entries[i].Leaf {
			t.Fatalf("entry %d leaf does not match its recomputation", i)
		}
		leaves[i] = leaf
	}
	if root := hash.MerkleRoot(leaves); root != exp.Header.Head.RootHash {
		t.Fatalf("source root %s, recomputed %s", exp.Header.Head.RootHash, root)
	}
	proof, err := hash.ProveInclusion(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}
	entry := exp.Entries[0]
	receipt := verifier.TrustReceipt{
		Schema: verifier.TrustReceiptSchema,
		Entry:  &entry,
		Leaf:   entry.Leaf,
		Proof:  &proof,
		Head:   &exp.Header.Head,
		Claims: verifier.FixedTrustReceiptClaims(),
	}
	return writeReceiptFixture(t, receipt)
}

func produceTombstoneFixtureReceipt(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	entries := []verifier.EntryView{
		{
			TenantID: "tenant-a", Sequence: 1, RecordHash: "record-1", IntentID: "intent-1",
			ActorID: "agent-1", Capability: "payments.transfer", Tier: types.R3RiskTier,
			Allowed: true, GrantID: "grant-1", OccurredAt: base.Add(time.Second), LinkedAt: base.Add(time.Second),
		},
		{
			TenantID: "tenant-a", Sequence: 2, RecordHash: "record-2", IntentID: "intent-2",
			ActorID: "agent-1", Capability: "payments.transfer", Tier: types.R3RiskTier,
			Allowed: true, GrantID: "grant-2", OccurredAt: base.Add(2 * time.Second), LinkedAt: base.Add(2 * time.Second),
			Tombstone: &verifier.TombstoneView{
				FromSequence: 1, ToSequence: 1, Reason: "retention", AuthorizedBy: "operator:test", RemovedAt: base.Add(time.Hour),
			},
		},
	}
	leaves := make([]string, len(entries))
	for i := range entries {
		leaf, err := entries[i].RecomputeLeaf()
		if err != nil {
			t.Fatal(err)
		}
		entries[i].Leaf = leaf
		leaves[i] = leaf
	}
	head := hash.TreeHead{
		Algorithm: verifier.HeadSignatureAlgorithm,
		LogID:     hash.DeriveLogID("tenant-a"),
		Index:     entries[len(entries)-1].Sequence,
		RootHash:  hash.MerkleRoot(leaves),
		TreeSize:  uint64(len(entries)),
		SignedAt:  base.Add(2 * time.Hour),
	}
	head.Signature = ed25519.Sign(priv, verifier.HeadPayload(head))
	proof, err := hash.ProveInclusion(leaves, uint64(len(entries)-1))
	if err != nil {
		t.Fatal(err)
	}
	receipt := verifier.TrustReceipt{
		Schema: verifier.TrustReceiptSchema,
		Entry:  &entries[len(entries)-1],
		Leaf:   entries[len(entries)-1].Leaf,
		Proof:  &proof,
		Head:   &head,
		Claims: verifier.FixedTrustReceiptClaims(),
	}
	receiptPath := writeReceiptFixture(t, receipt)
	pubKeyPath := filepath.Join(t.TempDir(), "tombstone-pubkey.hex")
	if err := os.WriteFile(pubKeyPath, []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return receiptPath, pubKeyPath
}

func writeReceiptFixture(t *testing.T, receipt verifier.TrustReceipt) string {
	t.Helper()
	raw, err := receipt.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
