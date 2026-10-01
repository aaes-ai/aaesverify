package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

func TestSignedPreAnchorExportVerifiesWithoutOptIn(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	doc := exportJSONLCoveredPreAnchor(t, entries, head, pub)

	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("signed pre_anchor export failed without opt-in: %v", res.Errors)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "pre_anchor") {
		t.Fatalf("signed pre_anchor export did not warn: %v", res.Warnings)
	}
}

func TestForgedPreAnchorOnSignedHeadFailsClosed(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	withAnchors := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})
	stripped := stripAnchorLines(t, withAnchors)
	forged := setHeaderPreAnchor(t, stripped, true)

	res, err := VerifyExportReader(strings.NewReader(forged), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("forged pre_anchor on an uncovered head still verified: warnings=%v", res.Warnings)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "--allow-pre-anchor") {
		t.Fatalf("refusal does not name the opt-in: %v", res.Errors)
	}
}

func TestAnchoredExportStillVerifiesAfterPreAnchorCommitment(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})

	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("anchored export failed: %v", res.Errors)
	}
	if res.AnchorCount != 1 {
		t.Fatalf("AnchorCount = %d, want 1", res.AnchorCount)
	}
}

func TestSignedHeadPreAnchorWithoutHeaderFlagIsRefused(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONLCoveredPreAnchor(t, entries, head, pub)
	lines := strings.Split(strings.TrimSuffix(doc, "\n"), "\n")
	var hdr map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	delete(hdr, "pre_anchor")
	raw, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(raw)
	edited := strings.Join(lines, "\n") + "\n"

	res, err := VerifyExportReader(strings.NewReader(edited), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("head pre_anchor without header flag still verified")
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "signed head declares pre_anchor") {
		t.Fatalf("refusal does not name the disagreement: %v", res.Errors)
	}
}

func TestTamperingHeadPreAnchorBreaksTheSignature(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONLCoveredPreAnchor(t, entries, head, pub)
	lines := strings.Split(strings.TrimSuffix(doc, "\n"), "\n")
	var hdr map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	hm, ok := hdr["head"].(map[string]any)
	if !ok {
		t.Fatal("header head is not an object")
	}
	delete(hm, "pre_anchor")
	hdr["head"] = hm
	raw, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(raw)
	edited := strings.Join(lines, "\n") + "\n"

	res, err := VerifyExportReader(strings.NewReader(edited), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.SignatureOK {
		t.Fatalf("clearing signed pre_anchor still verified: OK=%v SignatureOK=%v errors=%v", res.OK, res.SignatureOK, res.Errors)
	}
}

// exportJSONLCoveredPreAnchor builds an honest new-shape export: the head is
// re-signed with pre_anchor inside the payload, matching the producer.
func exportJSONLCoveredPreAnchor(t *testing.T, entries []EntryView, head hash.TreeHead, pub ed25519.PublicKey) string {
	t.Helper()
	covered := head
	covered.PreAnchor = true
	covered.Signature = ed25519.Sign(testPriv(), HeadPayload(covered))
	return exportJSONL(t, entries, covered, pub)
}
