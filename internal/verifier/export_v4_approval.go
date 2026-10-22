package verifier

import (
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// ApprovalLeafViewV4 is one v4 approval line: a signed approval-state leaf
// correlated to the approval store by its positive, global source sequence
// (design section 4.6). ChainHash and Leaf are exporter claims, excluded from
// the preimage and recomputed by the verifier.
type ApprovalLeafViewV4 struct {
	Type           string     `json:"type"`
	Schema         string     `json:"schema"`
	SourceSequence *uint64    `json:"source_sequence,omitempty"`
	LinkedAt       time.Time  `json:"linked_at"`
	Approval       ApprovalV4 `json:"approval"`
	ChainHash      string     `json:"chain_hash"`
	Leaf           string     `json:"leaf"`
}

// ApprovalV4 is the closed nested approval shape: the current types.Approval
// member names and value types, including the historical PascalCase JSON
// names and numeric enums, so no second security-critical mapping exists.
// Pointer fields give presence semantics: every section 4.6 required-present
// member is a non-nil pointer even when it points at a zero value
// (ApproverKind 0, ApproverAuthority 0, RequesterManagersSource 0, an empty
// Reason). Presence is what the wire signs; the nonempty-identifier and
// state-dependent rules are the scoped full-export checks of section 4.8, not
// this layer.
type ApprovalV4 struct {
	ApprovalID              *string                  `json:"ApprovalID,omitempty"`
	TenantID                *string                  `json:"TenantID,omitempty"`
	TaskID                  *string                  `json:"TaskID,omitempty"`
	IntentID                *string                  `json:"IntentID,omitempty"`
	RequestRecordID         *string                  `json:"RequestRecordID,omitempty"`
	Approver                *string                  `json:"Approver,omitempty"`
	State                   *types.ApprovalState     `json:"State,omitempty"`
	Reason                  *string                  `json:"Reason,omitempty"`
	PayloadHash             *string                  `json:"PayloadHash,omitempty"`
	BundleHash              *string                  `json:"BundleHash,omitempty"`
	EngineVersion           *string                  `json:"EngineVersion,omitempty"`
	ExpiresAt               *time.Time               `json:"ExpiresAt,omitempty"`
	DecidedAt               *time.Time               `json:"DecidedAt,omitempty"`
	CreatedAt               *time.Time               `json:"CreatedAt,omitempty"`
	ApproverKind            *types.ApproverClass     `json:"ApproverKind,omitempty"`
	ApproverAuthority       *types.ApprovalAuthority `json:"ApproverAuthority,omitempty"`
	ApproverSponsor         *string                  `json:"ApproverSponsor,omitempty"`
	ApproverModelProvider   *string                  `json:"ApproverModelProvider,omitempty"`
	ApproverModelFamily     *string                  `json:"ApproverModelFamily,omitempty"`
	ApproverModel           *string                  `json:"ApproverModel,omitempty"`
	ApproverModelSource     *string                  `json:"ApproverModelSource,omitempty"`
	Requester               *string                  `json:"Requester,omitempty"`
	InitiatedBy             *string                  `json:"InitiatedBy,omitempty"`
	RequesterSponsor        *string                  `json:"RequesterSponsor,omitempty"`
	RequesterModelProvider  *string                  `json:"RequesterModelProvider,omitempty"`
	RequesterModelFamily    *string                  `json:"RequesterModelFamily,omitempty"`
	RequesterModel          *string                  `json:"RequesterModel,omitempty"`
	Sponsor                 *string                  `json:"Sponsor,omitempty"`
	RequesterManagers       []ManagerEntryV4         `json:"RequesterManagers,omitempty"`
	RequesterManagersSource *types.ManagerSource     `json:"RequesterManagersSource,omitempty"`
	Action                  *string                  `json:"Action,omitempty"`
	ApprovalPolicyID        *string                  `json:"ApprovalPolicyID,omitempty"`
}

// ManagerEntryV4 is one entry of the sealed requester manager set; every
// member is required-present when the element appears, including
// Primary:false and zero-valued kind/role.
type ManagerEntryV4 struct {
	ActorID *string            `json:"ActorID,omitempty"`
	Kind    *types.ActorKind   `json:"Kind,omitempty"`
	Role    *types.ManagerRole `json:"Role,omitempty"`
	Primary *bool              `json:"Primary,omitempty"`
}

// DecodeApprovalLeafV4 strictly decodes and validates one v4 approval line.
// The producer mirrors it, so a line the verifier accepts is a line the
// producer could have emitted.
func DecodeApprovalLeafV4(raw []byte) (ApprovalLeafViewV4, error) {
	var leaf ApprovalLeafViewV4
	if err := decodeStrictV4(raw, &leaf); err != nil {
		return ApprovalLeafViewV4{}, err
	}
	if err := leaf.ValidateV4(); err != nil {
		return ApprovalLeafViewV4{}, err
	}
	return leaf, nil
}

// ValidateV4 enforces the approval envelope and the section 4.6 presence and
// vocabulary rules. It runs on decode and is mirrored by the producer.
func (l *ApprovalLeafViewV4) ValidateV4() error {
	if l.Type != lineApprovalV4 {
		return fmt.Errorf("%w: approval leaf type %q, want %q", ErrMalformed, l.Type, lineApprovalV4)
	}
	if l.Schema != ExportSchemaV4 {
		return fmt.Errorf("%w: approval leaf schema %q, want %q", ErrMalformed, l.Schema, ExportSchemaV4)
	}
	if l.SourceSequence == nil || *l.SourceSequence == 0 {
		return fmt.Errorf("%w: source_sequence is required and must be a positive approval store position", ErrMalformed)
	}
	if err := requiredMembersV4([]presenceV4{
		{"linked_at", !l.LinkedAt.IsZero()},
		{"chain_hash", l.ChainHash != ""},
		{"leaf", l.Leaf != ""},
	}); err != nil {
		return err
	}
	return l.Approval.validateV4()
}

// validateV4 enforces required-present, the frozen numeric vocabularies, and
// optional-empty on the nested approval.
func (a *ApprovalV4) validateV4() error {
	if err := requiredMembersV4([]presenceV4{
		{"approval.ApprovalID", a.ApprovalID != nil},
		{"approval.TenantID", a.TenantID != nil},
		{"approval.TaskID", a.TaskID != nil},
		{"approval.IntentID", a.IntentID != nil},
		{"approval.Approver", a.Approver != nil},
		{"approval.State", a.State != nil},
		{"approval.Reason", a.Reason != nil},
		{"approval.PayloadHash", a.PayloadHash != nil},
		{"approval.BundleHash", a.BundleHash != nil},
		{"approval.EngineVersion", a.EngineVersion != nil},
		{"approval.ExpiresAt", a.ExpiresAt != nil},
		{"approval.DecidedAt", a.DecidedAt != nil},
		{"approval.CreatedAt", a.CreatedAt != nil},
		{"approval.ApproverKind", a.ApproverKind != nil},
		{"approval.ApproverAuthority", a.ApproverAuthority != nil},
		{"approval.RequesterManagersSource", a.RequesterManagersSource != nil},
	}); err != nil {
		return err
	}
	if err := a.validateEnumsV4(); err != nil {
		return err
	}
	return a.validateOptionalV4()
}

// validateEnumsV4 refuses values outside the frozen numeric vocabularies;
// section 4.2 forbids a zero value from acquiring a permissive default, and
// an out-of-range enum has no meaning a reader may invent.
func (a *ApprovalV4) validateEnumsV4() error {
	if *a.State < types.ApprovalNotRequired || *a.State > types.ApprovalExpired {
		return fmt.Errorf("%w: approval.State %d is outside the closed vocabulary", ErrMalformed, int(*a.State))
	}
	if err := a.ApproverKind.Validate(); err != nil {
		return fmt.Errorf("%w: approval.ApproverKind: %v", ErrMalformed, err)
	}
	if err := a.ApproverAuthority.Validate(); err != nil {
		return fmt.Errorf("%w: approval.ApproverAuthority: %v", ErrMalformed, err)
	}
	if err := a.RequesterManagersSource.Validate(); err != nil {
		return fmt.Errorf("%w: approval.RequesterManagersSource: %v", ErrMalformed, err)
	}
	if a.ApproverModelSource != nil && *a.ApproverModelSource != "unknown" && *a.ApproverModelSource != "registered" {
		return fmt.Errorf("%w: approval.ApproverModelSource %q is outside the closed vocabulary", ErrMalformed, *a.ApproverModelSource)
	}
	return nil
}

// validateOptionalV4 checks every optional-empty member and the manager-set
// element shape.
func (a *ApprovalV4) validateOptionalV4() error {
	if err := optionalStringsV4([]optionalStringV4{
		{"approval.RequestRecordID", a.RequestRecordID},
		{"approval.ApproverSponsor", a.ApproverSponsor},
		{"approval.ApproverModelProvider", a.ApproverModelProvider},
		{"approval.ApproverModelFamily", a.ApproverModelFamily},
		{"approval.ApproverModel", a.ApproverModel},
		{"approval.Requester", a.Requester},
		{"approval.InitiatedBy", a.InitiatedBy},
		{"approval.RequesterSponsor", a.RequesterSponsor},
		{"approval.RequesterModelProvider", a.RequesterModelProvider},
		{"approval.RequesterModelFamily", a.RequesterModelFamily},
		{"approval.RequesterModel", a.RequesterModel},
		{"approval.Sponsor", a.Sponsor},
		{"approval.Action", a.Action},
		{"approval.ApprovalPolicyID", a.ApprovalPolicyID},
	}); err != nil {
		return err
	}
	if a.RequesterManagers != nil && len(a.RequesterManagers) == 0 {
		return fmt.Errorf("%w: approval.RequesterManagers is optional and must be omitted, not present but empty", ErrMalformed)
	}
	for i, e := range a.RequesterManagers {
		if err := e.validateV4(i); err != nil {
			return err
		}
	}
	return nil
}

// validateV4 enforces required-present and the frozen kind/role vocabularies
// on one manager-set element.
func (e *ManagerEntryV4) validateV4(i int) error {
	if err := requiredMembersV4([]presenceV4{
		{fmt.Sprintf("approval.RequesterManagers[%d].ActorID", i), e.ActorID != nil},
		{fmt.Sprintf("approval.RequesterManagers[%d].Kind", i), e.Kind != nil},
		{fmt.Sprintf("approval.RequesterManagers[%d].Role", i), e.Role != nil},
		{fmt.Sprintf("approval.RequesterManagers[%d].Primary", i), e.Primary != nil},
	}); err != nil {
		return err
	}
	if *e.Kind != types.KindAgent && *e.Kind != types.KindHuman {
		return fmt.Errorf("%w: approval.RequesterManagers[%d].Kind %d is outside the closed vocabulary", ErrMalformed, i, int(*e.Kind))
	}
	if err := e.Role.Validate(); err != nil {
		return fmt.Errorf("%w: approval.RequesterManagers[%d].Role: %v", ErrMalformed, i, err)
	}
	return nil
}

// approvalLeafPreimageV4 is the signed shape: the whole line except the
// exporter-claim chain_hash and leaf.
type approvalLeafPreimageV4 struct {
	Type           string     `json:"type"`
	Schema         string     `json:"schema"`
	SourceSequence uint64     `json:"source_sequence"`
	LinkedAt       time.Time  `json:"linked_at"`
	Approval       ApprovalV4 `json:"approval"`
}

// PreimageV4 returns the canonical bytes the leaf and chain commit to. It
// validates first, so a caller cannot canonicalise a leaf that would be
// refused on the wire.
func (l *ApprovalLeafViewV4) PreimageV4() ([]byte, error) {
	if err := l.ValidateV4(); err != nil {
		return nil, err
	}
	return hash.CanonicalJSON(approvalLeafPreimageV4{
		Type:           l.Type,
		Schema:         l.Schema,
		SourceSequence: *l.SourceSequence,
		LinkedAt:       l.LinkedAt,
		Approval:       l.Approval,
	})
}

// RecomputeLeafV4 returns the leaf this approval commits to, independent of
// the value the export claims.
func (l *ApprovalLeafViewV4) RecomputeLeafV4() (string, error) {
	pre, err := l.PreimageV4()
	if err != nil {
		return "", fmt.Errorf("verifier: canonicalise approval leaf: %w", err)
	}
	return hash.SHA256Hex(pre), nil
}
