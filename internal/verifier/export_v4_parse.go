package verifier

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// The v4 body of LoadExportReader: the strict per-line decoders
// and the unified leaf list. The schema is fixed by the header before any
// body line decodes (design section 6.1); under v4 every line decodes under
// the section 4.2 strict rules, typed leaves join the same file-ordered leaf
// series as decision entries (section 4.3), and anchors follow the leaves
// (section 4.1).

// LeafV4 is one leaf-bearing line of a v4 export in file order: the kind, the
// typed view, the preimage bytes the chain and Merkle tree commit to, and the
// exporter's chain_hash/leaf claims, which verification recomputes. Exactly
// one of Entry, Receipt, Approval, Summary is non-nil.
type LeafV4 struct {
	Kind     string
	Entry    *EntryView
	Receipt  *ReceiptLeafViewV4
	Approval *ApprovalLeafViewV4
	Summary  *SummaryLeafViewV4
	Preimage []byte
	// ChainHash and Leaf are the exporter's claims for this position.
	ChainHash string
	Leaf      string
}

// headerWireV4 is the closed v4 header member list (design section 4.1): the
// v3 members plus the required leaf_count and signing_key_id.
type headerWireV4 struct {
	Type               string        `json:"type"`
	Schema             string        `json:"schema"`
	LogID              string        `json:"log_id"`
	TenantID           string        `json:"tenant_id"`
	ExportedAt         time.Time     `json:"exported_at"`
	EntryCount         uint64        `json:"entry_count"`
	LeafCount          uint64        `json:"leaf_count"`
	Head               hash.TreeHead `json:"head"`
	PublicKey          string        `json:"public_key,omitempty"`
	SignatureAlgorithm string        `json:"signature_algorithm,omitempty"`
	SigningKeyID       string        `json:"signing_key_id,omitempty"`
	PreAnchor          bool          `json:"pre_anchor,omitempty"`
}

// decodeHeaderFirst decodes the first line as the header and fixes the file's
// schema before any body line is read. An unknown or retired schema fails here
// with ErrSchema; there is no content-sniffing and no fallback to an older
// parser. A v4 header is re-decoded under the strict v4 rules, so a member a
// lenient decode would ignore is refused.
func decodeHeaderFirst(raw []byte, lineNo int) (HeaderView, error) {
	hdr, err := decodeHeaderLine(raw, false, lineNo)
	if err != nil {
		return HeaderView{}, err
	}
	if _, ok := NormalizeExportSchema(hdr.Schema); !ok {
		return HeaderView{}, fmt.Errorf("%w: line %d: %q", ErrSchema, lineNo, hdr.Schema)
	}
	if hdr.Schema != ExportSchemaV4 {
		return hdr, nil
	}
	var wire headerWireV4
	if err := decodeStrictV4(raw, &wire); err != nil {
		return HeaderView{}, fmt.Errorf("line %d: %w", lineNo, err)
	}
	return HeaderView{
		SignatureAlgorithm: wire.SignatureAlgorithm,
		Schema:             wire.Schema,
		LogID:              wire.LogID,
		TenantID:           wire.TenantID,
		ExportedAt:         wire.ExportedAt,
		EntryCount:         wire.EntryCount,
		LeafCount:          wire.LeafCount,
		Head:               wire.Head,
		PublicKey:          wire.PublicKey,
		SigningKeyID:       wire.SigningKeyID,
		PreAnchor:          wire.PreAnchor,
	}, nil
}

// decodeBodyLineV4 decodes one v4 body line. sawAnchor enforces the section
// 4.1 line order — leaf lines in log order, then anchors — so a leaf after an
// anchor is misplaced.
func (exp *ExportFile) decodeBodyLineV4(raw []byte, typ string, lineNo int, sawAnchor *bool) error {
	switch typ {
	case lineEntry:
		if *sawAnchor {
			return misplacedLeafV4(lineNo, typ)
		}
		entry, err := decodeEntryLineV4(raw, lineNo)
		if err != nil {
			return err
		}
		return exp.appendEntryV4(entry, lineNo)
	case lineReceiptV4:
		if *sawAnchor {
			return misplacedLeafV4(lineNo, typ)
		}
		leaf, err := DecodeReceiptLeafV4(raw)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		return exp.appendReceiptV4(leaf, lineNo)
	case lineApprovalV4:
		if *sawAnchor {
			return misplacedLeafV4(lineNo, typ)
		}
		leaf, err := DecodeApprovalLeafV4(raw)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		return exp.appendApprovalV4(leaf, lineNo)
	case lineSummaryV4:
		if *sawAnchor {
			return misplacedLeafV4(lineNo, typ)
		}
		leaf, err := DecodeSummaryLeafV4(raw)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		return exp.appendSummaryV4(leaf, lineNo)
	case lineAnchor:
		*sawAnchor = true
		a, err := decodeAnchorLineV4(raw, lineNo)
		if err != nil {
			return err
		}
		exp.Anchors = append(exp.Anchors, a)
		return nil
	default:
		return fmt.Errorf("%w: line %d: unknown line type %q", ErrMalformed, lineNo, typ)
	}
}

func misplacedLeafV4(lineNo int, typ string) error {
	return fmt.Errorf("%w: line %d: %s leaf follows an anchor; v4 anchors come after every leaf", ErrMalformed, lineNo, typ)
}

// entryLineV4 is the strict v4 entry wrapper: the historical EntryView member
// list plus the line-type discriminator, closed to unknown members. The
// decision entry keeps its historical encoding, so presence rules stay with
// the chain check rather than this decode.
type entryLineV4 struct {
	Type string `json:"type"`
	EntryView
}

// decodeEntryLineV4 decodes one v4 entry line. The retired amount_usd field
// fails closed with ErrSchema exactly as under v2/v3 — probed before the
// strict decode so even a null amount_usd reports the retired field rather
// than a generic null refusal.
func decodeEntryLineV4(raw []byte, lineNo int) (EntryView, error) {
	var probe struct {
		AmountUSD json.RawMessage `json:"amount_usd"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && probe.AmountUSD != nil {
		return EntryView{}, fmt.Errorf("%w: line %d: legacy amount_usd is not valid in %s", ErrSchema, lineNo, ExportSchemaV4)
	}
	var line entryLineV4
	if err := decodeStrictV4(raw, &line); err != nil {
		return EntryView{}, fmt.Errorf("line %d: %w", lineNo, err)
	}
	return line.EntryView, nil
}

// anchorLineV4 is the closed v4 anchor member list; the nested head,
// timestamp and witness objects are closed as well (design section 4.2).
type anchorLineV4 struct {
	Type      string         `json:"type"`
	Head      hash.TreeHead  `json:"head"`
	KeyID     string         `json:"key_id,omitempty"`
	Algorithm string         `json:"algorithm,omitempty"`
	Timestamp *TimestampView `json:"timestamp,omitempty"`
	Witnesses []WitnessView  `json:"witnesses,omitempty"`
}

func decodeAnchorLineV4(raw []byte, lineNo int) (AnchorView, error) {
	var line anchorLineV4
	if err := decodeStrictV4(raw, &line); err != nil {
		return AnchorView{}, fmt.Errorf("line %d: %w", lineNo, err)
	}
	return AnchorView{
		Head:      line.Head,
		KeyID:     line.KeyID,
		Algorithm: line.Algorithm,
		Timestamp: line.Timestamp,
		Witnesses: line.Witnesses,
	}, nil
}

// The append helpers record each leaf in the type-specific slice AND the
// unified file-order list, computing the preimage once so verification never
// re-canonicalises. The pointer in LeafV4 is a stable heap copy: slice growth
// must not move the view a leaf points at.

func (exp *ExportFile) appendEntryV4(entry EntryView, lineNo int) error {
	pre, err := entry.preimage()
	if err != nil {
		return fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
	}
	e := entry
	exp.Entries = append(exp.Entries, e)
	exp.LeavesV4 = append(exp.LeavesV4, LeafV4{Kind: lineEntry, Entry: &e, Preimage: pre, ChainHash: e.ChainHash, Leaf: e.Leaf})
	return nil
}

func (exp *ExportFile) appendReceiptV4(leaf ReceiptLeafViewV4, lineNo int) error {
	pre, err := leaf.PreimageV4()
	if err != nil {
		return fmt.Errorf("line %d: %w", lineNo, err)
	}
	l := leaf
	exp.Receipts = append(exp.Receipts, l)
	exp.LeavesV4 = append(exp.LeavesV4, LeafV4{Kind: lineReceiptV4, Receipt: &l, Preimage: pre, ChainHash: l.ChainHash, Leaf: l.Leaf})
	return nil
}

func (exp *ExportFile) appendApprovalV4(leaf ApprovalLeafViewV4, lineNo int) error {
	pre, err := leaf.PreimageV4()
	if err != nil {
		return fmt.Errorf("line %d: %w", lineNo, err)
	}
	l := leaf
	exp.Approvals = append(exp.Approvals, l)
	exp.LeavesV4 = append(exp.LeavesV4, LeafV4{Kind: lineApprovalV4, Approval: &l, Preimage: pre, ChainHash: l.ChainHash, Leaf: l.Leaf})
	return nil
}

func (exp *ExportFile) appendSummaryV4(leaf SummaryLeafViewV4, lineNo int) error {
	pre, err := leaf.PreimageV4()
	if err != nil {
		return fmt.Errorf("line %d: %w", lineNo, err)
	}
	l := leaf
	exp.Summaries = append(exp.Summaries, l)
	exp.LeavesV4 = append(exp.LeavesV4, LeafV4{Kind: lineSummaryV4, Summary: &l, Preimage: pre, ChainHash: l.ChainHash, Leaf: l.Leaf})
	return nil
}
