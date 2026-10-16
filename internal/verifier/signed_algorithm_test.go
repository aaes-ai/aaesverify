package verifier

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestActualExportChecksSignedHeadAlgorithm(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	for _, algorithm := range []string{"", "ed25519", "rsa"} {
		head.Algorithm = algorithm
		head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))
		doc := exportJSONL(t, entries, head, pub)
		if algorithm == "" {
			doc = strings.Replace(doc, ExportSchemaV3, ExportSchemaV2, 1)
		}
		res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
		if algorithm == "rsa" {
			if err == nil && res.OK {
				t.Fatal("valid Ed25519 bytes with an unsupported signed algorithm were accepted")
			}
		} else if err != nil || !res.OK || !res.SignatureOK {
			t.Fatalf("supported or legacy algorithm %q: %v, %+v", algorithm, err, res)
		}
	}
	// Relabelling the schema as v2 must not skip the signed algorithm check.
	head.Algorithm = "rsa"
	head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))
	doc := strings.Replace(exportJSONL(t, entries, head, pub), ExportSchemaV3, ExportSchemaV2, 1)
	res, _ := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if res == nil || res.OK || res.SignatureOK || !strings.Contains(strings.Join(res.Errors, "\n"), `head algorithm "rsa"`) {
		t.Fatalf("an unsupported signed algorithm on a v2-labeled export was not refused for that reason: %+v", res)
	}
	// Altering or deleting the algorithm on a modern head must break its
	// signature, including a change to the historical empty spelling.
	head.Algorithm = "ed25519"
	head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))
	head.Algorithm = ""
	if err := VerifyTreeHead(head, pub); err == nil {
		t.Fatal("removing the signed algorithm did not break the signature")
	}
}
