package verifier

import (
	"fmt"
	"time"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

// ReceiptView is a receipt plus the log evidence that makes it checkable
// offline. Entry is optional: with it, the verifier recomputes the leaf from
// the receipt's own entry rather than trusting the leaf string.
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
// or after the receipt was issued, and — when an EntryView is attached — that
// the leaf was recomputed from the entry rather than taken on faith and that
// the entry agrees with the receipt's identifiers.
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
	if err := VerifyTreeHead(*r.Head, pubKey); err != nil {
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
	if r.Entry != nil {
		if err := bindReceiptEntry(r); err != nil {
			return err
		}
	}
	return nil
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
