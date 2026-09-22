package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestIndependentWitnessRequiresCallerPinnedIdentity(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	wpub, wpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(HeadPayload(head))
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head:      head,
		Timestamp: &TimestampView{Noop: true, Digest: hex.EncodeToString(digest[:])},
		Witnesses: []WitnessView{{WitnessID: "auditor", PublicKey: wpub, Signature: ed25519.Sign(wpriv, HeadPayload(head)), KeyHolder: "external"}},
	}})
	for _, tc := range []struct {
		name        string
		trust       map[string][]byte
		independent bool
	}{
		{"untrusted declaration", nil, false},
		{"wrong identity", map[string][]byte{"other": wpub}, false},
		{"wrong key", map[string][]byte{"auditor": pub}, false},
		{"pinned witness despite noop TSA", map[string][]byte{"auditor": wpub}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{RequireIndependent: true, TrustedWitnessKeys: tc.trust})
			if err != nil {
				t.Fatal(err)
			}
			if res.OK != tc.independent || (res.IndependentWitnesses == 1) != tc.independent {
				t.Fatalf("independence result: %+v", res)
			}
		})
	}
}

func TestPinnedLedgerKeyStillCannotWitnessItself(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 1)
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head, Witnesses: []WitnessView{{WitnessID: "ledger", PublicKey: pub, Signature: head.Signature}}}})
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{RequireIndependent: true, TrustedWitnessKeys: map[string][]byte{"ledger": pub}})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.IndependentWitnesses != 0 {
		t.Fatalf("ledger witnessed itself: %+v", res)
	}
}
