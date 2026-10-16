package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestV3RequiresSignedAlgorithmAndRetainsV2Evidence(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	current := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(current), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil || !res.OK || res.Schema != ExportSchemaV3 || res.ResultSchema != ResultSchemaV2 || res.Verdict != "CONSISTENT" {
		t.Fatalf("current witnessless export: %v, %+v", err, res)
	}
	head.Algorithm = ""
	head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))
	missing := exportJSONL(t, entries, head, pub)
	res, err = VerifyExportReaderWithOptions(strings.NewReader(missing), pub, VerifyOptions{AllowPreAnchor: true})
	if err == nil && res.OK {
		t.Fatal("v3 accepted an honestly signed head without its algorithm")
	}
	old := strings.Replace(missing, ExportSchemaV3, ExportSchemaV2, 1)
	res, err = VerifyExportReaderWithOptions(strings.NewReader(old), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil || !res.OK || res.Schema != ExportSchemaV2 || res.Verdict != "CONSISTENT" {
		t.Fatalf("retained witnessless v2: %v, %+v", err, res)
	}
	// Changing a header alone cannot make modern signed bytes into a legacy
	// head: deleting its algorithm still breaks its signature.
	modernAsV2 := strings.Replace(current, ExportSchemaV3, ExportSchemaV2, 1)
	modernAsV2 = strings.Replace(modernAsV2, `"algorithm":"ed25519",`, "", 1)
	res, err = VerifyExportReaderWithOptions(strings.NewReader(modernAsV2), pub, VerifyOptions{AllowPreAnchor: true})
	if err == nil && res.OK {
		t.Fatal("schema relabel allowed removal of authenticated algorithm")
	}
}

func TestV3ChecksAlgorithmOnActualAnchorLines(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	for _, algorithm := range []string{"ed25519", "", "unknown"} {
		t.Run(algorithm, func(t *testing.T) {
			anchorHead := head
			anchorHead.Algorithm = algorithm
			anchorHead.Signature = ed25519.Sign(testPriv(), HeadPayload(anchorHead))
			line, err := json.Marshal(map[string]any{"type": "anchor", "head": anchorHead})
			if err != nil {
				t.Fatal(err)
			}
			doc := exportJSONL(t, entries, head, pub) + string(line) + "\n"
			res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
			if algorithm != "ed25519" {
				if err == nil && res.OK {
					t.Fatal("actual v3 anchor accepted missing or unsupported authenticated algorithm")
				}
				return
			}
			if err != nil || !res.OK || res.AnchorsVerified != 1 || res.Verdict != "CONSISTENT" {
				t.Fatalf("valid actual anchor: %v, %+v", err, res)
			}
		})
	}
}

func TestIntegrityHeadlineNeverPassesFailedOrNilResults(t *testing.T) {
	for _, r := range []*Result{nil, {OK: false, IndependentWitnesses: 1}, {OK: false, TimestampsIndependent: 1}} {
		if got := r.IntegrityHeadline(); got != "FAIL" {
			t.Fatalf("failed result headline = %q", got)
		}
	}
}
