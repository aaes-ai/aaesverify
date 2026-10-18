package verifier

import (
	"errors"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

func TestVerifyReceiptRefusesUnsignedOutcomeFields(t *testing.T) {
	entries, head, pub, leaves := buildLog(t, 3)
	proof, err := hash.ProveInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[1]
	base := ReceiptView{
		ReceiptID: "receipt-1", IntentID: entry.IntentID, TenantID: entry.TenantID,
		GrantID: entry.GrantID, RecordHash: entry.RecordHash, IssuedAt: entry.OccurredAt,
		Entry: &entry, Leaf: entry.Leaf, Proof: &proof, Head: &head,
	}
	if err := VerifyReceipt(base, pub); err != nil {
		t.Fatalf("decision-only receipt: %v", err)
	}
	for _, tc := range []struct {
		name  string
		field string
	}{
		{name: "effect", field: "effect"},
		{name: "effect id", field: "effect_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			if tc.field == "effect" {
				r.Effect = "executed"
			} else {
				r.EffectID = "effect-1"
			}
			err := VerifyReceipt(r, pub)
			if !errors.Is(err, ErrReceipt) || !strings.Contains(err.Error(), "outcome fields") || !strings.Contains(err.Error(), "not covered by the signature") {
				t.Fatalf("unsigned %s: %v", tc.field, err)
			}
		})
	}
}
