package verifier

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Standalone approval/summary error paths (design section 4.9): inclusion
// fails closed on the head, the key, the tenant binding, and the proof.

func TestStandaloneLeafV4ErrorPaths(t *testing.T) {
	doc := newV4Builder(t).build()
	exp, err := LoadExportReader(strings.NewReader(doc.text))
	if err != nil {
		t.Fatal(err)
	}
	approval := exp.Approvals[0]
	approvalProof, err := hash.ProveInclusion(doc.leaves, 3)
	if err != nil {
		t.Fatal(err)
	}
	keyring := VerifyOptions{Keyring: doc.signing.keyring()}

	t.Run("legacy head refused", func(t *testing.T) {
		head := doc.head
		head.Schema = ""
		if res := VerifyStandaloneApprovalV4(approval, approvalProof, head, doc.signing.id, keyring); res.OK {
			t.Fatal("a legacy-shaped head passed a standalone approval check")
		}
	})
	t.Run("unknown key id", func(t *testing.T) {
		if res := VerifyStandaloneApprovalV4(approval, approvalProof, doc.head, "ledger-k9", keyring); res.OK {
			t.Fatal("an unknown key id passed")
		}
	})
	t.Run("no keyring", func(t *testing.T) {
		if res := VerifyStandaloneApprovalV4(approval, approvalProof, doc.head, doc.signing.id, VerifyOptions{}); res.OK {
			t.Fatal("a standalone approval verified without the pinned keyring")
		}
	})
	t.Run("head for another log", func(t *testing.T) {
		head := doc.head
		head.LogID = hash.DeriveLogID("tenant-b")
		head.Signature = ed25519.Sign(doc.signing.priv, HeadPayload(head))
		res := VerifyStandaloneApprovalV4(approval, approvalProof, head, doc.signing.id, keyring)
		if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "does not derive from the leaf tenant") {
			t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
		}
	})
	t.Run("proof tree size mismatch", func(t *testing.T) {
		proof := approvalProof
		proof.TreeSize++
		if res := VerifyStandaloneApprovalV4(approval, proof, doc.head, doc.signing.id, keyring); res.OK {
			t.Fatal("a proof for another tree size passed")
		}
	})
	t.Run("expected-final mismatch", func(t *testing.T) {
		pin := v4Pin(doc.head)
		pin.RootHash = hash.SHA256Hex([]byte("other"))
		res := VerifyStandaloneApprovalV4(approval, approvalProof, doc.head, doc.signing.id,
			VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: pin})
		if res.OK || res.ExpectedFinalHead != labelFailed {
			t.Fatalf("ok=%v final=%q", res.OK, res.ExpectedFinalHead)
		}
	})
	t.Run("expected-final pin satisfied", func(t *testing.T) {
		res := VerifyStandaloneApprovalV4(approval, approvalProof, doc.head, doc.signing.id,
			VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(doc.head)})
		if !res.OK || res.ExpectedFinalHead != labelVerified || res.AntiRollback != labelVerified {
			t.Fatalf("ok=%v final=%q errors=%v", res.OK, res.ExpectedFinalHead, res.Errors)
		}
	})
}
