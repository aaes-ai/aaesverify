package verifier

import (
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// ReceiptLeafViewV4 is one v4 receipt line: a signed outcome or
// dispatch-control leaf naming its parent decision by sequence and record
// hash (design section 4.5). ChainHash and Leaf are exporter claims, excluded
// from the preimage and recomputed by the verifier.
type ReceiptLeafViewV4 struct {
	Type       string    `json:"type"`
	Schema     string    `json:"schema"`
	Sequence   *uint64   `json:"sequence,omitempty"`
	RecordHash string    `json:"record_hash"`
	LinkedAt   time.Time `json:"linked_at"`
	Receipt    ReceiptV4 `json:"receipt"`
	ChainHash  string    `json:"chain_hash"`
	Leaf       string    `json:"leaf"`
}

// ReceiptV4 is the closed nested receipt shape: the journal.Receipt JSON
// names and value encodings minus receipt_hash. Pointer fields give
// presence semantics: a required-present member is a non-nil pointer even
// when it points at a zero value (class 0, rail_confirmed false, the zero
// timestamps); an optional-empty member is nil when omitted and refused when
// present but empty. Null is never a legal value; the token walk in
// rejectDuplicateMembers refuses it before decoding.
type ReceiptV4 struct {
	ReceiptID            *string            `json:"receipt_id,omitempty"`
	ExecutionState       *string            `json:"execution_state,omitempty"`
	IntentID             *string            `json:"intent_id,omitempty"`
	TenantID             *string            `json:"tenant_id,omitempty"`
	TaskID               *string            `json:"task_id,omitempty"`
	ApprovalID           *string            `json:"approval_id,omitempty"`
	ExternalRefs         []ExternalRefV4    `json:"external_refs,omitempty"`
	Custody              *string            `json:"custody,omitempty"`
	GrantID              *string            `json:"grant_id,omitempty"`
	EffectID             *string            `json:"effect_id,omitempty"`
	Effect               *string            `json:"effect,omitempty"`
	RecordHash           *string            `json:"record_hash,omitempty"`
	IssuedAt             *time.Time         `json:"issued_at,omitempty"`
	Class                *types.EffectClass `json:"class,omitempty"`
	RailConfirmed        *bool              `json:"rail_confirmed,omitempty"`
	ConfirmedAt          *time.Time         `json:"confirmed_at,omitempty"`
	ResultMode           *string            `json:"result_mode,omitempty"`
	PayloadReturned      *bool              `json:"payload_returned,omitempty"`
	ResultBytes          *int64             `json:"result_bytes,omitempty"`
	ResultContentType    *string            `json:"result_content_type,omitempty"`
	ResultDigest         *string            `json:"result_digest,omitempty"`
	ResultResourceID     *string            `json:"result_resource_id,omitempty"`
	ReportedBy           *string            `json:"reported_by,omitempty"`
	ReportedAt           *time.Time         `json:"reported_at,omitempty"`
	ObservedAt           *time.Time         `json:"observed_at,omitempty"`
	ReportedOutcome      *string            `json:"reported_outcome,omitempty"`
	Note                 *string            `json:"note,omitempty"`
	ObservationExpiresAt *time.Time         `json:"observation_expires_at,omitempty"`
	ResolvesDeferralID   *string            `json:"resolves_deferral_id,omitempty"`
	ResolvedRecordID     *string            `json:"resolved_record_id,omitempty"`
	PolicyBundleHash     *string            `json:"policy_bundle_hash,omitempty"`
	InputHash            *string            `json:"input_hash,omitempty"`
	EngineVersion        *string            `json:"engine_version,omitempty"`
	ModelUsage           *ModelUsageV4      `json:"model_usage,omitempty"`
}

// ExternalRefV4 is one attributed external identifier; every member is
// required-present when the element appears.
type ExternalRefV4 struct {
	Registry *string `json:"registry,omitempty"`
	Kind     *string `json:"kind,omitempty"`
	Value    *string `json:"value,omitempty"`
	Source   *string `json:"source,omitempty"`
}

// ModelUsageV4 is the settled usage of one model call; when the object is
// present every member is required-present, including zero values.
type ModelUsageV4 struct {
	InputTokens  *int64  `json:"input_tokens,omitempty"`
	OutputTokens *int64  `json:"output_tokens,omitempty"`
	TotalTokens  *int64  `json:"total_tokens,omitempty"`
	SettledMinor *int64  `json:"settled_minor,omitempty"`
	Currency     *string `json:"currency,omitempty"`
	// Estimated is optional: present, and true, only on a call settled at
	// its reservation estimate.
	Estimated *bool `json:"estimated,omitempty"`
}

// DecodeReceiptLeafV4 strictly decodes and validates one v4 receipt line.
// The producer mirrors it, so a line the verifier accepts is a line the
// producer could have emitted.
func DecodeReceiptLeafV4(raw []byte) (ReceiptLeafViewV4, error) {
	var leaf ReceiptLeafViewV4
	if err := decodeStrictV4(raw, &leaf); err != nil {
		return ReceiptLeafViewV4{}, err
	}
	if err := leaf.ValidateV4(); err != nil {
		return ReceiptLeafViewV4{}, err
	}
	return leaf, nil
}

// ValidateV4 enforces the receipt envelope and the section 4.5 presence
// rules. It runs on decode and is mirrored by the producer.
func (l *ReceiptLeafViewV4) ValidateV4() error {
	if l.Type != lineReceiptV4 {
		return fmt.Errorf("%w: receipt leaf type %q, want %q", ErrMalformed, l.Type, lineReceiptV4)
	}
	if l.Schema != ExportSchemaV4 {
		return fmt.Errorf("%w: receipt leaf schema %q, want %q", ErrMalformed, l.Schema, ExportSchemaV4)
	}
	if err := requiredMembersV4([]presenceV4{
		{"sequence", l.Sequence != nil},
		{"record_hash", l.RecordHash != ""},
		{"linked_at", !l.LinkedAt.IsZero()},
		{"chain_hash", l.ChainHash != ""},
		{"leaf", l.Leaf != ""},
	}); err != nil {
		return err
	}
	return l.Receipt.validateV4()
}

// validateV4 enforces the nested receipt presence rules.
func (r *ReceiptV4) validateV4() error {
	if err := requiredMembersV4([]presenceV4{
		{"receipt.receipt_id", r.ReceiptID != nil},
		{"receipt.intent_id", r.IntentID != nil},
		{"receipt.tenant_id", r.TenantID != nil},
		{"receipt.record_hash", r.RecordHash != nil},
		{"receipt.issued_at", r.IssuedAt != nil && !r.IssuedAt.IsZero()},
		{"receipt.class", r.Class != nil},
		{"receipt.rail_confirmed", r.RailConfirmed != nil},
		// The three value timestamps keep the explicit zero-time encoding;
		// presence, not nonzeroness, is what is signed for.
		{"receipt.confirmed_at", r.ConfirmedAt != nil},
		{"receipt.reported_at", r.ReportedAt != nil},
		{"receipt.observed_at", r.ObservedAt != nil},
	}); err != nil {
		return err
	}
	if r.Class != nil && (*r.Class < types.EffectDenied || *r.Class > types.EffectDeferred) {
		return fmt.Errorf("%w: receipt.class %d is outside the closed vocabulary", ErrMalformed, int(*r.Class))
	}
	if err := r.validateResultGroupV4(); err != nil {
		return err
	}
	return r.validateOptionalV4()
}

// validateResultGroupV4 enforces the conditional pair: when result_mode is
// present, payload_returned and result_bytes are required-present (including
// false and 0); when it is absent both must be omitted. The remaining result
// members are independently optional-empty.
func (r *ReceiptV4) validateResultGroupV4() error {
	if r.ResultMode != nil {
		if r.PayloadReturned == nil {
			return missingV4("receipt.payload_returned (required when result_mode is present)")
		}
		if r.ResultBytes == nil {
			return missingV4("receipt.result_bytes (required when result_mode is present)")
		}
		return nil
	}
	if r.PayloadReturned != nil || r.ResultBytes != nil {
		return fmt.Errorf("%w: receipt.payload_returned and receipt.result_bytes must be omitted when result_mode is absent", ErrMalformed)
	}
	return nil
}

// validateOptionalV4 checks every optional-empty member and the nested
// external_refs and model_usage shapes.
func (r *ReceiptV4) validateOptionalV4() error {
	if err := optionalStringsV4([]optionalStringV4{
		{"receipt.execution_state", r.ExecutionState},
		{"receipt.task_id", r.TaskID},
		{"receipt.approval_id", r.ApprovalID},
		{"receipt.custody", r.Custody},
		{"receipt.grant_id", r.GrantID},
		{"receipt.effect_id", r.EffectID},
		{"receipt.effect", r.Effect},
		{"receipt.result_mode", r.ResultMode},
		{"receipt.result_content_type", r.ResultContentType},
		{"receipt.result_digest", r.ResultDigest},
		{"receipt.result_resource_id", r.ResultResourceID},
		{"receipt.reported_by", r.ReportedBy},
		{"receipt.reported_outcome", r.ReportedOutcome},
		{"receipt.note", r.Note},
		{"receipt.resolves_deferral_id", r.ResolvesDeferralID},
		{"receipt.resolved_record_id", r.ResolvedRecordID},
		{"receipt.policy_bundle_hash", r.PolicyBundleHash},
		{"receipt.input_hash", r.InputHash},
		{"receipt.engine_version", r.EngineVersion},
	}); err != nil {
		return err
	}
	if err := refuseZeroTimeV4("receipt.observation_expires_at", r.ObservationExpiresAt); err != nil {
		return err
	}
	if r.ExternalRefs != nil && len(r.ExternalRefs) == 0 {
		return fmt.Errorf("%w: receipt.external_refs is optional and must be omitted, not present but empty", ErrMalformed)
	}
	for i, ref := range r.ExternalRefs {
		if err := ref.validateV4(i); err != nil {
			return err
		}
	}
	if r.ModelUsage != nil {
		if err := r.ModelUsage.validateV4(); err != nil {
			return err
		}
	}
	return nil
}

// validateV4 enforces required-present on every member of one external
// reference element.
func (ref *ExternalRefV4) validateV4(i int) error {
	return requiredMembersV4([]presenceV4{
		{fmt.Sprintf("receipt.external_refs[%d].registry", i), ref.Registry != nil},
		{fmt.Sprintf("receipt.external_refs[%d].kind", i), ref.Kind != nil},
		{fmt.Sprintf("receipt.external_refs[%d].value", i), ref.Value != nil},
		{fmt.Sprintf("receipt.external_refs[%d].source", i), ref.Source != nil},
	})
}

// validateV4 enforces required-present on every model usage member, zero
// values included.
func (u *ModelUsageV4) validateV4() error {
	if u.Estimated != nil && !*u.Estimated {
		return fmt.Errorf("%w: receipt.model_usage.estimated is present only when true", ErrMalformed)
	}
	return requiredMembersV4([]presenceV4{
		{"receipt.model_usage.input_tokens", u.InputTokens != nil},
		{"receipt.model_usage.output_tokens", u.OutputTokens != nil},
		{"receipt.model_usage.total_tokens", u.TotalTokens != nil},
		{"receipt.model_usage.settled_minor", u.SettledMinor != nil},
		{"receipt.model_usage.currency", u.Currency != nil},
	})
}

// receiptLeafPreimageV4 is the signed shape: the whole line except the
// exporter-claim chain_hash and leaf.
type receiptLeafPreimageV4 struct {
	Type       string    `json:"type"`
	Schema     string    `json:"schema"`
	Sequence   uint64    `json:"sequence"`
	RecordHash string    `json:"record_hash"`
	LinkedAt   time.Time `json:"linked_at"`
	Receipt    ReceiptV4 `json:"receipt"`
}

// PreimageV4 returns the canonical bytes the leaf and chain commit to. It
// validates first, so a caller cannot canonicalise a leaf that would be
// refused on the wire.
func (l *ReceiptLeafViewV4) PreimageV4() ([]byte, error) {
	if err := l.ValidateV4(); err != nil {
		return nil, err
	}
	return hash.CanonicalJSON(receiptLeafPreimageV4{
		Type:       l.Type,
		Schema:     l.Schema,
		Sequence:   *l.Sequence,
		RecordHash: l.RecordHash,
		LinkedAt:   l.LinkedAt,
		Receipt:    l.Receipt,
	})
}

// RecomputeLeafV4 returns the leaf this receipt commits to, independent of
// the value the export claims.
func (l *ReceiptLeafViewV4) RecomputeLeafV4() (string, error) {
	pre, err := l.PreimageV4()
	if err != nil {
		return "", fmt.Errorf("verifier: canonicalise receipt leaf: %w", err)
	}
	return hash.SHA256Hex(pre), nil
}
