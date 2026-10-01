package verifier

import (
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// ReceiptView is a receipt plus the log evidence that makes it checkable
// offline. Entry is required: the verifier recomputes the leaf from the
// receipt's own entry rather than trusting the leaf string, and binds intent,
// grant and record identity to that leaf.
type ReceiptView struct {
	ReceiptID  string    `json:"receipt_id"`
	IntentID   string    `json:"intent_id"`
	TenantID   string    `json:"tenant_id"`
	GrantID    string    `json:"grant_id"`
	EffectID   string    `json:"effect_id"`
	Effect     string    `json:"effect"`
	RecordHash string    `json:"record_hash"`
	IssuedAt   time.Time `json:"issued_at"`

	Entry *EntryView           `json:"entry,omitempty"`
	Leaf  string               `json:"leaf"`
	Proof *hash.InclusionProof `json:"proof,omitempty"`
	Head  *hash.TreeHead       `json:"head,omitempty"`
}

// VerifyReceipt verifies one receipt against a signed tree head and an
// inclusion proof, using only the bytes in the receipt.
//
// It checks that the head signature verifies under pubKey, that the proof
// commits the receipt's leaf to the head's root, that the head was signed at
// or after the receipt was issued, that an EntryView is attached so intent,
// grant and record identity can be bound to the leaf, that the leaf was
// recomputed from the entry rather than taken on faith, and that the entry
// agrees with the receipt's identifiers.
func VerifyReceipt(r ReceiptView, pubKey []byte) error {
	if r.ReceiptID == "" || r.TenantID == "" {
		return fmt.Errorf("%w: receipt_id and tenant_id are required", ErrReceipt)
	}
	if len(pubKey) == 0 {
		return ErrNoPublicKey
	}
	if r.Head == nil {
		return fmt.Errorf("%w: no signed tree head attached", ErrReceipt)
	}
	if r.Proof == nil {
		return fmt.Errorf("%w: no inclusion proof attached", ErrReceipt)
	}
	if r.Leaf == "" {
		return fmt.Errorf("%w: no leaf attached", ErrReceipt)
	}
	if r.Entry == nil {
		return fmt.Errorf("%w: receipt carries no entry; intent, grant and record identity cannot be bound to the leaf", ErrReceipt)
	}
	if err := VerifyTreeHead(*r.Head, pubKey); err != nil {
		return err
	}
	if err := checkHeadLogID(*r.Head, hash.DeriveLogID(r.TenantID)); err != nil {
		return err
	}
	if r.Proof.TreeSize > r.Head.TreeSize {
		return fmt.Errorf("%w: proof covers %d leaves, head covers %d", ErrReceipt, r.Proof.TreeSize, r.Head.TreeSize)
	}
	if r.Proof.RootHash != r.Head.RootHash {
		return fmt.Errorf("%w: proof root %s, head root %s", ErrReceipt, r.Proof.RootHash, r.Head.RootHash)
	}
	if !hash.VerifyInclusion(r.Leaf, *r.Proof) {
		return ErrInclusion
	}
	if r.Head.SignedAt.Before(r.IssuedAt) {
		return fmt.Errorf("%w: head signed at %s, receipt issued at %s", ErrReceipt,
			r.Head.SignedAt.UTC().Format(time.RFC3339Nano), r.IssuedAt.UTC().Format(time.RFC3339Nano))
	}
	return bindReceiptEntry(r)
}

func bindReceiptEntry(r ReceiptView) error {
	e := r.Entry
	if e.TenantID != r.TenantID {
		return fmt.Errorf("%w: entry tenant %q, receipt tenant %q", ErrReceipt, e.TenantID, r.TenantID)
	}
	if e.GrantID != r.GrantID {
		return fmt.Errorf("%w: entry grant %q, receipt grant %q", ErrReceipt, e.GrantID, r.GrantID)
	}
	if e.IntentID != r.IntentID {
		return fmt.Errorf("%w: entry intent %q, receipt intent %q", ErrReceipt, e.IntentID, r.IntentID)
	}
	if e.RecordHash != r.RecordHash {
		return fmt.Errorf("%w: entry record hash %q, receipt record hash %q", ErrReceipt, e.RecordHash, r.RecordHash)
	}
	leaf, err := e.RecomputeLeaf()
	if err != nil {
		return err
	}
	if leaf != r.Leaf {
		return fmt.Errorf("%w: leaf %s recomputed from the entry is %s", ErrReceipt, r.Leaf, leaf)
	}
	return nil
}
