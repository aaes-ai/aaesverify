package verifier

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// summaryLeafPreimageV4 is the signed shape: the whole line except the
// exporter-claim chain_hash and leaf. Body re-canonicalises from the raw
// wire bytes, so an out-of-order body cannot change what the leaf commits
// to.
type summaryLeafPreimageV4 struct {
	Type              string               `json:"type"`
	Schema            string               `json:"schema"`
	TenantID          string               `json:"tenant_id"`
	SummaryID         string               `json:"summary_id"`
	Profile           string               `json:"profile"`
	ProducerID        string               `json:"producer_id"`
	ProducerVersion   string               `json:"producer_version"`
	CreatedAt         time.Time            `json:"created_at"`
	PeriodStart       *time.Time           `json:"period_start,omitempty"`
	PeriodEnd         *time.Time           `json:"period_end,omitempty"`
	Inputs            []SummaryInputV4     `json:"inputs"`
	LinkedAt          time.Time            `json:"linked_at"`
	Body              json.RawMessage      `json:"body"`
	ProducerSignature *ProducerSignatureV4 `json:"producer_signature,omitempty"`
}

// preimageShapeV4 returns the preimage object; PreimageV4 and
// SummaryProducerPayloadV4 differ only in whether the producer signature is
// removed.
func (l *SummaryLeafViewV4) preimageShapeV4() summaryLeafPreimageV4 {
	return summaryLeafPreimageV4{
		Type:              l.Type,
		Schema:            l.Schema,
		TenantID:          l.TenantID,
		SummaryID:         l.SummaryID,
		Profile:           l.Profile,
		ProducerID:        l.ProducerID,
		ProducerVersion:   l.ProducerVersion,
		CreatedAt:         l.CreatedAt,
		PeriodStart:       l.PeriodStart,
		PeriodEnd:         l.PeriodEnd,
		Inputs:            l.Inputs,
		LinkedAt:          l.LinkedAt,
		Body:              l.Body,
		ProducerSignature: l.ProducerSignature,
	}
}

// PreimageV4 returns the canonical bytes the leaf and chain commit to. It
// validates first, so a caller cannot canonicalise a leaf that would be
// refused on the wire.
func (l *SummaryLeafViewV4) PreimageV4() ([]byte, error) {
	if err := l.ValidateV4(); err != nil {
		return nil, err
	}
	return hash.CanonicalJSON(l.preimageShapeV4())
}

// RecomputeLeafV4 returns the leaf this summary commits to, independent of
// the value the export claims.
func (l *SummaryLeafViewV4) RecomputeLeafV4() (string, error) {
	pre, err := l.PreimageV4()
	if err != nil {
		return "", fmt.Errorf("verifier: canonicalise summary leaf: %w", err)
	}
	return hash.SHA256Hex(pre), nil
}

// SummaryProducerPayloadV4 is the bytes the optional producer signature
// covers (design section 5.4): the summary preimage with producer_signature
// removed, chain_hash and leaf already excluded.
func (l *SummaryLeafViewV4) SummaryProducerPayloadV4() ([]byte, error) {
	if err := l.ValidateV4(); err != nil {
		return nil, err
	}
	shape := l.preimageShapeV4()
	shape.ProducerSignature = nil
	return hash.CanonicalJSON(shape)
}
