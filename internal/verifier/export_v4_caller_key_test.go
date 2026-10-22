package verifier

import (
	"strings"
	"testing"
)

// A caller-supplied key is the trust anchor of a v4 export: it is never
// ignored in favour of the key embedded in the file. Before this, a v4 file
// signed by an attacker's embedded key passed aaesverify --pubkey genuine.pub
// as UNPINNED_CONSISTENCY with exit 0.
func TestV4CallerKeyIsTheTrustAnchor(t *testing.T) {
	genuine := newV4KeyPair("ledger-k1", 11)
	attacker := newV4KeyPair("ledger-k1", 99)

	forged := newV4Builder(t)
	forged.signing = attacker
	forgedText := forged.build().text
	if res := VerifyExportReaderResult(strings.NewReader(forgedText), nil, VerifyOptions{}); !res.OK || res.KeySource != "embedded" {
		t.Fatalf("the forged file must verify only against its own embedded key: ok=%v source=%s %v", res.OK, res.KeySource, res.Errors)
	}
	res := VerifyExportReaderResult(strings.NewReader(forgedText), genuine.pub, VerifyOptions{})
	if res.OK || res.Verdict != "FAIL" || !strings.Contains(strings.Join(res.Errors, " "), "signed by") {
		t.Fatalf("forged export with an embedded attacker key passed the genuine key: ok=%v verdict=%s %v", res.OK, res.Verdict, res.Errors)
	}

	keyless := newV4Builder(t)
	keyless.signing = attacker
	keyless.embedKey = false
	res = VerifyExportReaderResult(strings.NewReader(keyless.build().text), genuine.pub, VerifyOptions{})
	if res.OK || res.SignatureOK || res.KeySource != "keyring" {
		t.Fatalf("forged export without an embedded key passed the genuine key: ok=%v sig=%v source=%s", res.OK, res.SignatureOK, res.KeySource)
	}

	built := newV4Builder(t).build()
	res = VerifyExportReaderResult(strings.NewReader(built.text), genuine.pub, VerifyOptions{})
	if !res.OK || res.KeySource != "keyring" || res.Verdict != VerdictUnpinnedV4 {
		t.Fatalf("genuine export under the genuine key: ok=%v source=%s verdict=%s %v", res.OK, res.KeySource, res.Verdict, res.Errors)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "no public key was supplied") {
			t.Fatalf("a supplied key was reported as missing: %q", w)
		}
	}
	pin := &HeadPin{LogID: built.head.LogID, Index: built.head.Index, RootHash: built.head.RootHash, TreeSize: built.head.TreeSize}
	res = VerifyExportReaderResult(strings.NewReader(built.text), genuine.pub, VerifyOptions{ExpectedFinal: pin})
	if !res.OK || res.ExpectedFinalHead != labelVerified || res.Verdict != res.IntegrityHeadline() {
		t.Fatalf("expected-final under the supplied key: ok=%v final=%s verdict=%s %v", res.OK, res.ExpectedFinalHead, res.Verdict, res.Errors)
	}
}

func TestV4CallerKeyMustAgreeWithTheKeyring(t *testing.T) {
	genuine := newV4KeyPair("ledger-k1", 11)
	other := newV4KeyPair("ledger-k1", 42)
	text := newV4Builder(t).build().text
	res := VerifyExportReaderResult(strings.NewReader(text), genuine.pub, VerifyOptions{Keyring: genuine.keyring()})
	if !res.OK || res.KeySource != "keyring" {
		t.Fatalf("matching key and keyring: ok=%v %v", res.OK, res.Errors)
	}
	noEmbed := newV4Builder(t)
	noEmbed.embedKey = false
	res = VerifyExportReaderResult(strings.NewReader(noEmbed.build().text), other.pub, VerifyOptions{Keyring: genuine.keyring()})
	if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "not keyring entry") {
		t.Fatalf("a key outside the keyring was accepted: ok=%v %v", res.OK, res.Errors)
	}
	res = VerifyExportReaderResult(strings.NewReader(text), []byte{1, 2, 3}, VerifyOptions{})
	if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "3 bytes") {
		t.Fatalf("a short key was accepted: ok=%v %v", res.OK, res.Errors)
	}
}
