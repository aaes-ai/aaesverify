package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

func TestStrippingEveryAnchorFailsVerification(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	withAnchors := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})
	if !strings.Contains(withAnchors, `"type":"anchor"`) {
		t.Fatal("fixture has no anchor line to strip")
	}
	var kept []string
	for _, line := range strings.Split(withAnchors, "\n") {
		if strings.Contains(line, `"type":"anchor"`) {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, line)
	}
	stripped := strings.Join(kept, "\n") + "\n"
	res, err := VerifyExportReader(strings.NewReader(stripped), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("stripping every anchor still verified: warnings=%v", res.Warnings)
	}
	if res.AnchorCount != 0 {
		t.Fatalf("AnchorCount = %d after stripping, want 0", res.AnchorCount)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "no anchors") && !strings.Contains(joined, "pre_anchor") {
		t.Fatalf("refusal does not name the missing anchors: %v", res.Errors)
	}
}

func TestPreAnchorExportWithoutAnchorsVerifies(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("honest pre_anchor export failed: %v", res.Errors)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "pre_anchor") {
		t.Fatalf("pre_anchor export did not say so: %v", res.Warnings)
	}
}

func TestRequireIndependentFailsWithoutExternalEvidence(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{RequireIndependent: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("independent verification passed with zero witnesses and timestamps: %+v", res)
	}
	if res.IndependentWitnesses != 0 {
		t.Fatalf("IndependentWitnesses = %d, want 0 (unkeyed head is not a witness)", res.IndependentWitnesses)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "independent verification") {
		t.Fatalf("errors do not name the independent-verification demand: %v", res.Errors)
	}
}

func TestUnkeyedHeadCommitmentIsNotAnIndependentWitness(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	// A countersignature-shaped witness whose "signature" is the unkeyed SHA-256
	// of the head payload must not count as independent: that is the journal
	// seal, not an external party.
	digest := hash.SHA256Hex(HeadPayload(head))
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Witnesses: []WitnessView{{
			WitnessID: "head-commitment",
			PublicKey: pub,
			Signature: []byte(digest),
			SignedAt:  head.SignedAt,
			KeyHolder: "external",
		}},
	}})
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.IndependentWitnesses != 0 {
		t.Fatalf("unkeyed head commitment counted as %d independent witnesses", res.IndependentWitnesses)
	}
	if res.OK {
		t.Fatal("a witness whose signature is not Ed25519 over the head must not pass")
	}
}

func TestRequireIndependentCountsAConfiguredExternalWitness(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	wpub, wpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(wpriv, HeadPayload(head))
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Witnesses: []WitnessView{{
			WitnessID: "ext-1",
			PublicKey: wpub,
			Signature: sig,
			SignedAt:  time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC),
			KeyHolder: "external",
		}},
	}})
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{RequireIndependent: true, TrustedWitnessKeys: map[string][]byte{"ext-1": wpub}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("configured external witness failed independent verification: %v", res.Errors)
	}
	if res.IndependentWitnesses != 1 {
		t.Fatalf("IndependentWitnesses = %d, want 1", res.IndependentWitnesses)
	}
}

func TestExportJSONLDeclaresPreAnchor(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 1)
	doc := exportJSONL(t, entries, head, pub)
	var hdr map[string]any
	if err := json.Unmarshal([]byte(strings.Split(doc, "\n")[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["pre_anchor"] != true {
		t.Fatalf("exportJSONL header pre_anchor = %v, want true (fixtures without anchors must be honest)", hdr["pre_anchor"])
	}
}
