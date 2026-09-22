package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

func TestVerifyReceiptBindsGrantIDAndRejectsOneSidedIDs(t *testing.T) {
	entries, head, pub, leaves := buildLog(t, 4)
	proof, err := hash.ProveInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[1]
	r := ReceiptView{
		ReceiptID:  "receipt-1",
		IntentID:   entry.IntentID,
		TenantID:   entry.TenantID,
		GrantID:    entry.GrantID,
		RecordHash: entry.RecordHash,
		IssuedAt:   entry.OccurredAt,
		Entry:      &entry,
		Leaf:       entry.Leaf,
		Proof:      &proof,
		Head:       &head,
	}
	if err := VerifyReceipt(r, pub); err != nil {
		t.Fatalf("valid receipt: %v", err)
	}
	wrongGrant := r
	wrongGrant.GrantID = "other-grant"
	if err := VerifyReceipt(wrongGrant, pub); err == nil {
		t.Fatal("a receipt claiming another grant must not verify")
	}
	oneSided := r
	oneSided.IntentID = ""
	if err := VerifyReceipt(oneSided, pub); err == nil {
		t.Fatal("one-sided missing intent must not skip the comparison")
	}
}

func TestIndependentWitnessCountDoesNotInflateByUnsignedID(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	wpub, wpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(wpriv, HeadPayload(head))
	w := WitnessView{WitnessID: "ext-1", PublicKey: wpub, Signature: sig, SignedAt: head.SignedAt, KeyHolder: "external"}
	copyID := w
	copyID.WitnessID = "ext-2"
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head, Witnesses: []WitnessView{w, copyID}}})
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{TrustedWitnessKeys: map[string][]byte{"ext-1": wpub, "ext-2": wpub}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("export: %v", res.Errors)
	}
	if res.IndependentWitnesses != 1 {
		t.Fatalf("IndependentWitnesses = %d, want 1 (same key, two WitnessIDs)", res.IndependentWitnesses)
	}
}

func TestTombstonedInternalGapVerifiesAsOKWithGaps(t *testing.T) {
	tomb := &TombstoneView{
		FromSequence: 3,
		ToSequence:   6,
		Reason:       "retention",
		AuthorisedBy: "operator:alice",
		RemovedAt:    time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC),
	}
	entries, head, pub := buildGappedLog(t, []uint64{1, 2, 7, 8}, tomb)
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("internal tombstoned gap did not verify: %v", res.Errors)
	}
	if !res.Gapped {
		t.Fatal("internal tombstoned gap must report Gapped")
	}
}

func TestTimestampTimeMustEqualGenTime(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	digest := sha256.Sum256(HeadPayload(head))
	_, cert, pool, key := testTSA(t)
	tok := signedTSToken(t, digest[:], cert, key)
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Timestamp: &TimestampView{
			Authority: "canary",
			Digest:    hex.EncodeToString(digest[:]),
			Time:      head.SignedAt,
			Token:     tok,
		},
	}})
	res, err := VerifyExportReaderWithTrust(strings.NewReader(doc), pub, pool)
	if err != nil {
		t.Fatal(err)
	}
	if res.TimestampsIndependent != 0 {
		t.Fatalf("backdated outer time counted as independent: %+v", res)
	}
}
