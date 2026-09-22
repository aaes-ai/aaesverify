package verifier

import (
	"strings"
	"testing"
)

func TestLedgerSignatureIsNotAnIndependentWitness(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head, Witnesses: []WitnessView{{WitnessID: "copied-ledger-head", PublicKey: pub, Signature: head.Signature, SignedAt: head.SignedAt, KeyHolder: "external"}}}})
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{RequireIndependent: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OK=%v IndependentWitnesses=%d Errors=%v Warnings=%v", res.OK, res.IndependentWitnesses, res.Errors, res.Warnings)
	if res.OK {
		t.Fatal("existing ledger signature accepted as independent countersignature")
	}
}
