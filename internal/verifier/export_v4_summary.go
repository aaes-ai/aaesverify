package verifier

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// SummaryLeafViewV4 is one v4 summary line (design section 5.1): a reserved,
// bounded typed-input summary registered in the outer tenant's log.
// ChainHash and Leaf are exporter claims, excluded from the preimage and
// recomputed by the verifier. The profile-owned Body stays raw on the
// envelope so its exact bytes re-canonicalise inside the leaf hash.
type SummaryLeafViewV4 struct {
	Type            string           `json:"type"`
	Schema          string           `json:"schema"`
	TenantID        string           `json:"tenant_id"`
	SummaryID       string           `json:"summary_id"`
	Profile         string           `json:"profile"`
	ProducerID      string           `json:"producer_id"`
	ProducerVersion string           `json:"producer_version"`
	CreatedAt       time.Time        `json:"created_at"`
	PeriodStart     *time.Time       `json:"period_start,omitempty"`
	PeriodEnd       *time.Time       `json:"period_end,omitempty"`
	Inputs          []SummaryInputV4 `json:"inputs"`
	LinkedAt        time.Time        `json:"linked_at"`
	Body            json.RawMessage  `json:"body"`
	// limitationsParsed keeps the governance-profile limitations array from
	// validateBodyV4 so summary verification does not decode the body again.
	limitationsParsed bool                 `json:"-"`
	parsedLimitations []string             `json:"-"`
	ProducerSignature *ProducerSignatureV4 `json:"producer_signature,omitempty"`
	ChainHash         string               `json:"chain_hash"`
	Leaf              string               `json:"leaf"`
}

// SummaryInputV4 is one typed input: a signed head of a referenced export
// state, named by input_id for the body's evidence references.
type SummaryInputV4 struct {
	InputID  string        `json:"input_id"`
	Schema   string        `json:"schema"`
	TenantID string        `json:"tenant_id"`
	KeyID    string        `json:"key_id"`
	Head     hash.TreeHead `json:"head"`
}

// ProducerSignatureV4 is the optional summary-producer authorship signal
// (design section 5.4). It is never a substitute for tree inclusion.
type ProducerSignatureV4 struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	// PublicKey is a hex Ed25519 key the producer embeds for internal
	// consistency only; authorship verification needs a key supplied out of
	// band, exactly as an embedded ledger key does.
	PublicKey *string `json:"public_key,omitempty"`
	Signature []byte  `json:"signature"`
}

// DecodeSummaryLeafV4 strictly decodes and validates one v4 summary line.
// The producer mirrors it, so a line the verifier accepts is a line the
// producer could have emitted.
func DecodeSummaryLeafV4(raw []byte) (SummaryLeafViewV4, error) {
	var leaf SummaryLeafViewV4
	if err := decodeStrictV4(raw, &leaf); err != nil {
		return SummaryLeafViewV4{}, err
	}
	if err := leaf.ValidateV4(); err != nil {
		return SummaryLeafViewV4{}, err
	}
	return leaf, nil
}

// ValidateV4 enforces the summary envelope: required-present members, the
// bounded and duplicate-free input list with its per-schema head rules, the
// paired period bounds, the optional producer signature, and the body shape.
// It runs on decode and is mirrored by the producer.
func (l *SummaryLeafViewV4) ValidateV4() error {
	if l.Type != lineSummaryV4 {
		return fmt.Errorf("%w: summary leaf type %q, want %q", ErrMalformed, l.Type, lineSummaryV4)
	}
	if l.Schema != ExportSchemaV4 {
		return fmt.Errorf("%w: summary leaf schema %q, want %q", ErrMalformed, l.Schema, ExportSchemaV4)
	}
	if err := requiredMembersV4([]presenceV4{
		{"tenant_id", l.TenantID != ""},
		{"summary_id", l.SummaryID != ""},
		{"profile", l.Profile != ""},
		{"producer_id", l.ProducerID != ""},
		{"producer_version", l.ProducerVersion != ""},
		{"created_at", !l.CreatedAt.IsZero()},
		{"linked_at", !l.LinkedAt.IsZero()},
		{"body", l.Body != nil},
		{"chain_hash", l.ChainHash != ""},
		{"leaf", l.Leaf != ""},
	}); err != nil {
		return err
	}
	if err := l.validatePeriodV4(); err != nil {
		return err
	}
	if err := l.validateInputsV4(); err != nil {
		return err
	}
	if err := l.validateProducerSignatureV4(); err != nil {
		return err
	}
	return l.validateBodyV4()
}

// validatePeriodV4 enforces the paired optional period bounds: they appear
// together or not at all, and start must not follow end.
func (l *SummaryLeafViewV4) validatePeriodV4() error {
	if (l.PeriodStart == nil) != (l.PeriodEnd == nil) {
		return fmt.Errorf("%w: period_start and period_end must appear together", ErrMalformed)
	}
	if l.PeriodStart == nil {
		return nil
	}
	if err := refuseZeroTimeV4("period_start", l.PeriodStart); err != nil {
		return err
	}
	if err := refuseZeroTimeV4("period_end", l.PeriodEnd); err != nil {
		return err
	}
	if l.PeriodStart.After(*l.PeriodEnd) {
		return fmt.Errorf("%w: period_start is after period_end", ErrMalformed)
	}
	return nil
}

// summaryInputStateV4 is the logical tree-state identity of an input. The
// schema selects signature-payload rules but is NOT part of evidence
// identity, so one decision-only state cannot be counted once as v3 and
// again as v4.
type summaryInputStateV4 struct {
	tenantID string
	logID    string
	index    uint64
	rootHash string
	treeSize uint64
}

// validateInputsV4 enforces the 1..64 bound, per-item rules, input_id
// uniqueness, and cross-schema logical-state de-duplication.
func (l *SummaryLeafViewV4) validateInputsV4() error {
	if len(l.Inputs) == 0 || len(l.Inputs) > maxSummaryInputsV4 {
		return fmt.Errorf("%w: inputs must contain 1..%d items, got %d", ErrMalformed, maxSummaryInputsV4, len(l.Inputs))
	}
	ids := make(map[string]struct{}, len(l.Inputs))
	states := make(map[summaryInputStateV4]struct{}, len(l.Inputs))
	for i := range l.Inputs {
		in := &l.Inputs[i]
		if err := in.validateV4(); err != nil {
			return fmt.Errorf("%w (input %d)", err, i)
		}
		if _, dup := ids[in.InputID]; dup {
			return fmt.Errorf("%w: duplicate input_id %q", ErrMalformed, in.InputID)
		}
		ids[in.InputID] = struct{}{}
		state := summaryInputStateV4{in.TenantID, in.Head.LogID, in.Head.Index, in.Head.RootHash, in.Head.TreeSize}
		if _, dup := states[state]; dup {
			return fmt.Errorf("%w: inputs %q names the same logical tree state as an earlier input", ErrMalformed, in.InputID)
		}
		states[state] = struct{}{}
	}
	return nil
}

// validateV4 enforces one input's per-schema head rules: the tenant must
// derive the head's log id (a mismatch is a refusal, never a silent
// override), tree size is nonzero, the signature is present, and the schema
// selects the head's signed field rules.
func (in *SummaryInputV4) validateV4() error {
	if err := requiredMembersV4([]presenceV4{
		{"input_id", in.InputID != ""},
		{"tenant_id", in.TenantID != ""},
		{"key_id", in.KeyID != ""},
		{"head.tree_size", in.Head.TreeSize != 0},
		{"head.root_hash", in.Head.RootHash != ""},
		{"head.signature", len(in.Head.Signature) != 0},
	}); err != nil {
		return err
	}
	if hash.DeriveLogID(in.TenantID) != in.Head.LogID {
		return fmt.Errorf("%w: input tenant_id does not derive the head log_id", ErrMalformed)
	}
	switch in.Schema {
	case ExportSchemaV4:
		if in.Head.Schema != ExportSchemaV4 {
			return fmt.Errorf("%w: a v4 input head must carry signed schema %q", ErrMalformed, ExportSchemaV4)
		}
		if in.Head.Algorithm != HeadSignatureAlgorithm {
			return fmt.Errorf("%w: a v4 input head must name algorithm %q", ErrMalformed, HeadSignatureAlgorithm)
		}
	case ExportSchemaV3:
		if in.Head.Algorithm != HeadSignatureAlgorithm {
			return fmt.Errorf("%w: a v3 input head must name algorithm %q", ErrMalformed, HeadSignatureAlgorithm)
		}
		if in.Head.Schema != "" {
			return fmt.Errorf("%w: a legacy input head does not carry schema", ErrMalformed)
		}
	case ExportSchemaV2:
		// V2 retains the historical implicit Ed25519 algorithm.
		if in.Head.Algorithm != "" {
			return fmt.Errorf("%w: a v2 input head carries no algorithm member", ErrMalformed)
		}
		if in.Head.Schema != "" {
			return fmt.Errorf("%w: a legacy input head does not carry schema", ErrMalformed)
		}
	default:
		return fmt.Errorf("%w: input schema %q, want %s, %s or %s", ErrMalformed, in.Schema, ExportSchemaV2, ExportSchemaV3, ExportSchemaV4)
	}
	return nil
}

// validateProducerSignatureV4 enforces the optional producer-signature shape
// when the object is present.
func (l *SummaryLeafViewV4) validateProducerSignatureV4() error {
	sig := l.ProducerSignature
	if sig == nil {
		return nil
	}
	if sig.Algorithm != HeadSignatureAlgorithm {
		return fmt.Errorf("%w: producer_signature.algorithm %q, want %q", ErrMalformed, sig.Algorithm, HeadSignatureAlgorithm)
	}
	if err := requiredMembersV4([]presenceV4{
		{"producer_signature.key_id", sig.KeyID != ""},
		{"producer_signature.signature", len(sig.Signature) != 0},
	}); err != nil {
		return err
	}
	if sig.PublicKey != nil {
		if err := refuseEmptyV4("producer_signature.public_key", sig.PublicKey); err != nil {
			return err
		}
		if !isHexV4(*sig.PublicKey) {
			return fmt.Errorf("%w: producer_signature.public_key is not lowercase hex", ErrMalformed)
		}
	}
	return nil
}

// isHexV4 reports whether s is a nonempty hexadecimal string, the encoding
// every embedded public key uses.
func isHexV4(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
