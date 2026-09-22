package verifier

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The export header is not covered by the head signature, so a verifier must not
// trust it on its own. An earlier revision did: editing the tenant label of a
// signed export relabelled the history while every hash still verified, because
// the entries (whose tenant id IS inside the hash-chained entry) were never
// compared with the header. Reproduced before the fix; the assertion below is
// what holds it.
func TestExportHeaderMustAgreeWithTheSignedEntries(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	doc := exportJSONL(t, entries, head, pub)

	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatalf("VerifyExportReader: %v", err)
	}
	if !res.OK {
		t.Fatalf("the baseline export did not verify: %v", res.Errors)
	}

	tenant := entries[0].TenantID
	relabelled := strings.Replace(doc, `"tenant_id":"`+tenant+`"`, `"tenant_id":"somebody-else"`, 1)
	if relabelled == doc {
		t.Fatal("the fixture did not contain the expected tenant id, so this test would prove nothing")
	}
	res, err = VerifyExportReader(strings.NewReader(relabelled), pub)
	if err != nil {
		t.Fatalf("VerifyExportReader: %v", err)
	}
	if res.OK {
		t.Fatal("an export whose header was relabelled to another tenant verified")
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "relabelled") {
		t.Fatalf("the refusal does not name the relabelling: %v", res.Errors)
	}
}

// A key that cannot be resolved is not a passing signature check. Reporting
// signature_ok true because no check could be run is the same class of error as
// an unsealed receipt: the field would assert something nobody verified.
func TestNoResolvableKeyIsNotAPassingSignatureCheck(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONL(t, entries, head, pub)

	noKey := strings.Replace(doc, `"public_key":"`+hex.EncodeToString(pub)+`"`, `"public_key":""`, 1)
	if noKey == doc {
		t.Fatal("the fixture did not contain an embedded public key, so this test would prove nothing")
	}
	res, err := VerifyExportReader(strings.NewReader(noKey), nil)
	if err != nil {
		t.Fatalf("VerifyExportReader: %v", err)
	}
	if res.OK {
		t.Fatal("an export with no usable public key at all reported OK")
	}
	if res.SignatureOK {
		t.Fatal("signature_ok is true although no signature could be checked")
	}
}
