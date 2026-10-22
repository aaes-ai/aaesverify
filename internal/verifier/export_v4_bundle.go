package verifier

import (
	"fmt"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// ReceiptBundleV1 is the pinned standalone receipt proof bundle (design
// section 4.9): the typed receipt leaf and its inclusion proof, the parent
// decision entry and its own proof, and one complete v4 signed head resolved
// through the caller-pinned keyring by key_id. Every member is
// required-present.
type ReceiptBundleV1 struct {
	Schema       string              `json:"schema"`
	KeyID        string              `json:"key_id"`
	Head         hash.TreeHead       `json:"head"`
	ParentLeaf   EntryView           `json:"parent_leaf"`
	ParentProof  hash.InclusionProof `json:"parent_proof"`
	ReceiptLeaf  ReceiptLeafViewV4   `json:"receipt_leaf"`
	ReceiptProof hash.InclusionProof `json:"receipt_proof"`
}

// receiptBundleWireV1 is the decode-time shape. Pointers make an omitted
// member distinguishable from a present zero; the strict proof struct does
// the same inside the proofs, because a proof's index 0 is a legal value that
// must still be written.
type receiptBundleWireV1 struct {
	Schema       string             `json:"schema"`
	KeyID        *string            `json:"key_id"`
	Head         *hash.TreeHead     `json:"head"`
	ParentLeaf   *entryLeafV4       `json:"parent_leaf"`
	ParentProof  *inclusionProofV4  `json:"parent_proof"`
	ReceiptLeaf  *ReceiptLeafViewV4 `json:"receipt_leaf"`
	ReceiptProof *inclusionProofV4  `json:"receipt_proof"`
}

// entryLeafV4 is the complete decision entry line shape a bundle carries as
// parent_leaf: the EntryView fields plus the "entry" line-type discriminator,
// which the strict decoder must see rather than refuse as unknown. The
// discriminator joins the v2/v3 line in the file but stays out of the
// preimage, exactly as on an export line.
type entryLeafV4 struct {
	Type string `json:"type"`
	EntryView
}

// inclusionProofV4 is the strict decode-time proof shape. Every
// hash.InclusionProof member is required-present in a bundle, so each is a
// pointer; siblings and self_siblings may be present-but-empty only for a
// tree of size 1.
type inclusionProofV4 struct {
	Index        *uint64   `json:"index,omitempty"`
	TreeSize     *uint64   `json:"tree_size,omitempty"`
	Siblings     *[]string `json:"siblings,omitempty"`
	SelfSiblings *[]bool   `json:"self_siblings,omitempty"`
	RootHash     *string   `json:"root_hash,omitempty"`
}

// toHashV4 converts the strict wire proof to the shared proof type after
// presence checks.
func (p *inclusionProofV4) toHashV4(member string) (hash.InclusionProof, error) {
	if err := requiredMembersV4([]presenceV4{
		{member + ".index", p.Index != nil},
		{member + ".tree_size", p.TreeSize != nil},
		{member + ".siblings", p.Siblings != nil},
		{member + ".self_siblings", p.SelfSiblings != nil},
		{member + ".root_hash", p.RootHash != nil && *p.RootHash != ""},
	}); err != nil {
		return hash.InclusionProof{}, err
	}
	return hash.InclusionProof{
		Index:        *p.Index,
		TreeSize:     *p.TreeSize,
		Siblings:     *p.Siblings,
		SelfSiblings: *p.SelfSiblings,
		RootHash:     *p.RootHash,
	}, nil
}

// DecodeReceiptBundleV1 strictly decodes and validates one receipt proof
// bundle. Proof positions, root agreement and signature checks run at
// verification time against the pinned keyring; this layer fixes the wire
// shape.
func DecodeReceiptBundleV1(raw []byte) (ReceiptBundleV1, error) {
	var wire receiptBundleWireV1
	if err := decodeStrictV4(raw, &wire); err != nil {
		return ReceiptBundleV1{}, err
	}
	bundle, err := wire.convertV4()
	if err != nil {
		return ReceiptBundleV1{}, err
	}
	if err := bundle.ValidateV4(); err != nil {
		return ReceiptBundleV1{}, err
	}
	return bundle, nil
}

// convertV4 enforces required-present on every bundle member and converts
// the strict proofs.
func (w *receiptBundleWireV1) convertV4() (ReceiptBundleV1, error) {
	if err := requiredMembersV4([]presenceV4{
		{"key_id", w.KeyID != nil},
		{"head", w.Head != nil},
		{"parent_leaf", w.ParentLeaf != nil},
		{"parent_proof", w.ParentProof != nil},
		{"receipt_leaf", w.ReceiptLeaf != nil},
		{"receipt_proof", w.ReceiptProof != nil},
	}); err != nil {
		return ReceiptBundleV1{}, err
	}
	parentProof, err := w.ParentProof.toHashV4("parent_proof")
	if err != nil {
		return ReceiptBundleV1{}, err
	}
	receiptProof, err := w.ReceiptProof.toHashV4("receipt_proof")
	if err != nil {
		return ReceiptBundleV1{}, err
	}
	if w.ParentLeaf.Type != lineEntry {
		return ReceiptBundleV1{}, fmt.Errorf("%w: parent_leaf type %q, want %q", ErrMalformed, w.ParentLeaf.Type, lineEntry)
	}
	return ReceiptBundleV1{
		Schema:       w.Schema,
		KeyID:        *w.KeyID,
		Head:         *w.Head,
		ParentLeaf:   w.ParentLeaf.EntryView,
		ParentProof:  parentProof,
		ReceiptLeaf:  *w.ReceiptLeaf,
		ReceiptProof: receiptProof,
	}, nil
}

// ValidateV4 enforces the bundle envelope: the pinned schema, a nonempty
// key_id, and a complete v4 signed head. A bundle is never historical-head
// evidence: a head without signed v4 schema, or any legacy head shape, is
// refused even when its signature could verify, because typed leaves exist
// only under v4.
func (b *ReceiptBundleV1) ValidateV4() error {
	if b.Schema != ReceiptBundleSchemaV1 {
		return fmt.Errorf("%w: bundle schema %q, want %q", ErrMalformed, b.Schema, ReceiptBundleSchemaV1)
	}
	if b.KeyID == "" {
		return fmt.Errorf("%w: bundle key_id is required and nonempty", ErrMalformed)
	}
	if err := validateHeadV4(b.Head); err != nil {
		return err
	}
	return b.ReceiptLeaf.ValidateV4()
}

// validateHeadV4 requires a complete v4 signed head: ed25519 algorithm,
// signed v4 schema, nonzero tree size, and a present signature.
func validateHeadV4(h hash.TreeHead) error {
	if h.Algorithm != HeadSignatureAlgorithm {
		return fmt.Errorf("%w: bundle head algorithm %q, want %q", ErrMalformed, h.Algorithm, HeadSignatureAlgorithm)
	}
	if h.Schema != ExportSchemaV4 {
		return fmt.Errorf("%w: bundle head must carry signed schema %q", ErrMalformed, ExportSchemaV4)
	}
	if err := requiredMembersV4([]presenceV4{
		{"head.log_id", h.LogID != ""},
		{"head.root_hash", h.RootHash != ""},
		{"head.tree_size", h.TreeSize != 0},
		{"head.signature", len(h.Signature) != 0},
	}); err != nil {
		return err
	}
	return nil
}
