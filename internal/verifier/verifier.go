// Package verifier checks AAES exports offline: canonical entry hashes, hash
// chains, Merkle roots, signatures, anchors, timestamps and pinned witnesses.
// It imports only the standard library, internal/hash and internal/types;
// source and transitive-closure tests enforce that restriction. Shared hash
// code still creates common-mode risk; this is not an independent second reader.
// Verification does not prove capture completeness, input truth, downstream
// success or absence of equivocation. Independent timestamps and witnesses
// provide separately reported commitment evidence under caller-supplied trust.
package verifier

import (
	"errors"
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// Errors. All verification failures wrap one of these, so callers can use
// errors.Is without parsing messages.
var (
	ErrEmptyLog    = errors.New("verifier: no entries to verify")
	ErrNoPublicKey = errors.New("verifier: no public key supplied")
	ErrChain       = errors.New("verifier: hash chain does not verify")
	ErrRoot        = errors.New("verifier: merkle root does not match the signed tree head")
	ErrSignature   = errors.New("verifier: signature does not verify under the supplied public key")
	ErrInclusion   = errors.New("verifier: inclusion proof does not verify")
	ErrReceipt     = errors.New("verifier: receipt is incomplete or inconsistent")
	ErrSchema      = errors.New("verifier: unsupported export schema")
	ErrMalformed   = errors.New("verifier: malformed export")
	ErrKeyMismatch = errors.New("verifier: supplied public key does not match the key in the export")
	// ErrLegacyHead reports a tree head whose log_id is empty: either a head
	// written before log ids became part of the signed payload, or one with
	// the field stripped. Such a head cannot name the log it belongs to, so it
	// fails closed instead of verifying against no identity at all.
	ErrLegacyHead = errors.New("verifier: tree head predates log ids (empty log_id)")
	// ErrLogIDMismatch reports a head whose log_id is not the id derived from
	// the export's tenant. The head — and every witness countersignature over
	// it — belongs to a different log, whatever its signature says.
	ErrLogIDMismatch = errors.New("verifier: tree head log_id does not match the export's tenant")
)

// EntryView is one transparency-log entry as an exporter published it. The
// preimage fields above ChainHash are sealed into the leaf; ChainHash and Leaf
// are the exporter's claims, recomputed and cross-checked here.
//
// v2 entries carry amount_minor and amount_currency (both omitempty): thirteen
// preimage fields when both amount fields are present, eleven when both are omitted.
// Only aaes.export/v2 is supported. The schema is never inferred from content.
type EntryView struct {
	TenantID       string         `json:"tenant_id"`
	Sequence       uint64         `json:"sequence"`
	RecordHash     string         `json:"record_hash"`
	IntentID       string         `json:"intent_id"`
	ActorID        string         `json:"actor_id"`
	Capability     string         `json:"capability"`
	Tier           types.RiskTier `json:"tier"`
	Allowed        bool           `json:"allowed"`
	GrantID        string         `json:"grant_id"`
	AmountMinor    int64          `json:"amount_minor,omitempty"`
	AmountCurrency string         `json:"amount_currency,omitempty"`
	OccurredAt     time.Time      `json:"occurred_at"`
	LinkedAt       time.Time      `json:"linked_at"`

	// Tombstone, when non-nil, marks this entry as the log's record of a
	// retention removal. It is part of the preimage, so the head signature
	// covers it, and the gap it names is the only thing that makes a missing
	// sequence range legal.
	Tombstone *TombstoneView `json:"tombstone,omitempty"`

	ChainHash string `json:"chain_hash"`
	Leaf      string `json:"leaf"`
}

// Amount returns the stored integer minor units and currency.
func (e EntryView) Amount() types.Money {
	return types.Money{Minor: e.AmountMinor, Currency: e.AmountCurrency}
}

// TombstoneView mirrors audit.Tombstone field for field. The verifier must not
// import the producer, so the shape is duplicated here and
// TestVerifierAgreesOnEntryPreimage fails the build if the two drift.
type TombstoneView struct {
	FromSequence uint64    `json:"from_sequence"`
	ToSequence   uint64    `json:"to_sequence"`
	Reason       string    `json:"reason"`
	AuthorizedBy string    `json:"authorised_by"`
	PolicyID     string    `json:"policy_id,omitempty"`
	RecordCount  uint64    `json:"record_count,omitempty"`
	ReceiptCount uint64    `json:"receipt_count,omitempty"`
	RemovedAt    time.Time `json:"removed_at"`
}

// entryPreimage mirrors audit.Entry field for field under aaes.export/v2. The
// two must agree byte for byte; TestVerifierAgreesOnEntryPreimage in
// internal/audit fails the build if they drift.
type entryPreimage struct {
	ActorID        string         `json:"actor_id"`
	Allowed        bool           `json:"allowed"`
	AmountMinor    int64          `json:"amount_minor,omitempty"`
	AmountCurrency string         `json:"amount_currency,omitempty"`
	Capability     string         `json:"capability"`
	GrantID        string         `json:"grant_id"`
	IntentID       string         `json:"intent_id"`
	LinkedAt       time.Time      `json:"linked_at"`
	OccurredAt     time.Time      `json:"occurred_at"`
	RecordHash     string         `json:"record_hash"`
	Sequence       uint64         `json:"sequence"`
	TenantID       string         `json:"tenant_id"`
	Tier           types.RiskTier `json:"tier"`
	Tombstone      *TombstoneView `json:"tombstone,omitempty"`
}

func (e EntryView) preimage() ([]byte, error) {
	return hash.CanonicalJSON(entryPreimage{
		ActorID:        e.ActorID,
		Allowed:        e.Allowed,
		AmountMinor:    e.AmountMinor,
		AmountCurrency: e.AmountCurrency,
		Capability:     e.Capability,
		GrantID:        e.GrantID,
		IntentID:       e.IntentID,
		LinkedAt:       e.LinkedAt,
		OccurredAt:     e.OccurredAt,
		RecordHash:     e.RecordHash,
		Sequence:       e.Sequence,
		TenantID:       e.TenantID,
		Tier:           e.Tier,
		Tombstone:      e.Tombstone,
	})
}

// RecomputeLeaf returns the leaf this entry commits to, independent of any
// value the export claims.
func (e EntryView) RecomputeLeaf() (string, error) {
	pre, err := e.preimage()
	if err != nil {
		return "", fmt.Errorf("verifier: canonicalise entry %d: %w", e.Sequence, err)
	}
	return hash.SHA256Hex(pre), nil
}
