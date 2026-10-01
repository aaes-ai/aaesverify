package verifier

import (
	"errors"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// A receipt that carries a leaf and proof but no entry cannot bind intent,
// grant or record identity to that leaf: VerifyReceipt must refuse it rather
// than trust the caller's identifiers against an unbound leaf string.
func TestVerifyReceiptRefusesWhenEntryIsMissing(t *testing.T) {
	entries, head, pub, leaves := buildLog(t, 4)
	proof, err := hash.ProveInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[1]
	r := ReceiptView{
		ReceiptID:  "receipt-1",
		IntentID:   "forged-intent",
		TenantID:   entry.TenantID,
		GrantID:    entry.GrantID,
		RecordHash: entry.RecordHash,
		IssuedAt:   entry.OccurredAt,
		Entry:      nil,
		Leaf:       entry.Leaf,
		Proof:      &proof,
		Head:       &head,
	}
	err = VerifyReceipt(r, pub)
	if err == nil {
		t.Fatal("a receipt with a wrong IntentID and no entry must be refused")
	}
	if !errors.Is(err, ErrReceipt) {
		t.Fatalf("err = %v, want ErrReceipt", err)
	}
	if !strings.Contains(err.Error(), "receipt carries no entry; intent, grant and record identity cannot be bound to the leaf") {
		t.Fatalf("err = %v, want the no-entry refusal", err)
	}
}
