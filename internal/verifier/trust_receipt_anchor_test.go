package verifier

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

func TestTrustReceiptAnchorEvidence(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*TrustReceipt)
		resign  bool
		want    error
		matches bool
	}{
		{name: "same tree", matches: true},
		{name: "witnesses and timestamps stay unverified", matches: true, edit: func(r *TrustReceipt) {
			r.Anchor.Witnesses = []WitnessView{{WitnessID: "untrusted", Signature: []byte("not a signature")}}
			r.Anchor.Timestamp = &TimestampView{Digest: "unverified"}
		}},
		{name: "older covering prefix", resign: true, edit: func(r *TrustReceipt) {
			_, _, _, leaves := buildLog(t, 11)
			r.Anchor.Head.TreeSize = r.Proof.Index + 1
			r.Anchor.Head.Index = r.Entry.Sequence
			r.Anchor.Head.RootHash = hash.MerkleRoot(leaves[:r.Proof.Index+1])
		}},
		{name: "successor has no consistency proof", resign: true, edit: func(r *TrustReceipt) {
			r.Anchor.Head.TreeSize++
			r.Anchor.Head.Index++
			r.Anchor.Head.RootHash = hash.SHA256Hex([]byte("separately signed successor"))
		}},
		{name: "foreign log", resign: true, want: ErrLogIDMismatch, edit: func(r *TrustReceipt) {
			r.Anchor.Head.LogID = hash.DeriveLogID("other tenant")
		}},
		{name: "missing log", resign: true, want: ErrLegacyHead, edit: func(r *TrustReceipt) { r.Anchor.Head.LogID = "" }},
		{name: "prefix excludes decision index", resign: true, want: ErrReceipt, edit: func(r *TrustReceipt) {
			r.Anchor.Head.TreeSize = r.Proof.Index
		}},
		{name: "empty prefix", resign: true, want: ErrReceipt, edit: func(r *TrustReceipt) { r.Anchor.Head.TreeSize = 0 }},
		{name: "same size conflicting root", resign: true, want: ErrReceipt, edit: func(r *TrustReceipt) {
			r.Anchor.Head.RootHash = hash.SHA256Hex([]byte("signed conflict"))
		}},
		{name: "same size conflicting index", resign: true, want: ErrReceipt, edit: func(r *TrustReceipt) { r.Anchor.Head.Index++ }},
		{name: "tampered root", want: ErrSignature, edit: func(r *TrustReceipt) { r.Anchor.Head.RootHash = "tampered" }},
		{name: "unknown signed algorithm", resign: true, want: ErrSignature, edit: func(r *TrustReceipt) { r.Anchor.Head.Algorithm = "rsa" }},
		{name: "unknown wrapper algorithm", want: ErrSignature, edit: func(r *TrustReceipt) { r.Anchor.Algorithm = "rsa" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, pub := validTrustReceipt(t)
			r.Anchor = &AnchorView{Head: *r.Head}
			if tc.edit != nil {
				tc.edit(&r)
			}
			if tc.resign {
				r.Anchor.Head.Signature = ed25519.Sign(testPriv(), HeadPayload(r.Anchor.Head))
			}
			raw, err := r.MarshalIndent()
			if err != nil {
				t.Fatal(err)
			}
			got, err := VerifyTrustReceipt(raw, pub)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("error = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if matched := TrustReceiptAnchorMatchesHead(got); matched != tc.matches {
				t.Fatalf("anchor matches = %v, want %v", matched, tc.matches)
			}
		})
	}
}

func TestTrustReceiptAnchorMatchAbsent(t *testing.T) {
	r, pub := validTrustReceipt(t)
	raw, err := r.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyTrustReceipt(raw, pub)
	if err != nil {
		t.Fatal(err)
	}
	if TrustReceiptAnchorMatchesHead(verified) || TrustReceiptAnchorMatchesHead(TrustReceipt{}) {
		t.Fatal("absent anchor or receipt head reported as a binding")
	}
}

func TestTrustReceiptUnicodeMemberAliasesAreDuplicate(t *testing.T) {
	r, pub := validTrustReceipt(t)
	raw, err := r.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"ſchema", `\u017fchema`, "SCHEMA"} {
		t.Run(alias, func(t *testing.T) {
			altered := strings.Replace(string(raw), `"schema":`, `"`+alias+`":"ignored","schema":`, 1)
			if _, err := VerifyTrustReceipt([]byte(altered), pub); !errors.Is(err, ErrReceipt) || !strings.Contains(err.Error(), "duplicate object key") {
				t.Fatalf("aliased schema was not refused: %v", err)
			}
		})
	}
}
