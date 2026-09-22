// Package verifier verifies AAES audit evidence offline, with AAES out of the
// trust path.
//
// # Import constraint (deliberate and test-enforced)
//
// This package may import ONLY the Go standard library, internal/hash and
// internal/types. It must never import internal/gateway, internal/journal,
// internal/policy, internal/credentials, internal/directory, internal/audit or
// internal/connectors. TestNoForbiddenImports walks this package's source and
// TestNoForbiddenImportsInTheClosure walks the whole transitive closure, so a
// forbidden package that arrives through an intermediate one fails the build
// too.
//
// The reason is not style. A verifier that shares code with the producer
// shares its bugs and its incentives; the customer's auditor must be able to
// read this package, compile it, and run it against a JSONL export on a
// machine that has never talked to AAES. Everything it needs is in the file.
//
// # What verification establishes
//
//   - Every entry's canonical bytes hash to the leaf the export claims, the
//     chain links genesis -> ... -> head in sequence order, and the Merkle
//     root over the leaves equals the root in the signed tree head.
//   - The tree head signature verifies under the public key the auditor
//     supplied out of band.
//   - Every anchor commits to a prefix of the same tree and carries a valid
//     signature.
//
// # What verification does not establish on its own
//
// A valid signature proves that whoever holds the key signed this head. If
// that is AAES alone, AAES can still substitute a different, internally
// consistent history. Only an external timestamp from a third party and at
// least one independent witness close that gap; Result reports how many of
// each were present (TimestampOK, IndependentWitnesses) instead of implying
// more than the file proves.
package verifier

import (
	"errors"
	"fmt"
	"time"

	"github.com/aaes-dev/aaesverify/internal/hash"
	"github.com/aaes-dev/aaesverify/internal/types"
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
// twelve fields above ChainHash are the entry preimage; ChainHash and Leaf are
// the exporter's claims, recomputed and cross-checked here.
type EntryView struct {
	TenantID   string         `json:"tenant_id"`
	Sequence   uint64         `json:"sequence"`
	RecordHash string         `json:"record_hash"`
	IntentID   string         `json:"intent_id"`
	ActorID    string         `json:"actor_id"`
	Capability string         `json:"capability"`
	Tier       types.RiskTier `json:"tier"`
	Allowed    bool           `json:"allowed"`
	GrantID    string         `json:"grant_id"`
	AmountUSD  float64        `json:"amount_usd"`
	OccurredAt time.Time      `json:"occurred_at"`
	LinkedAt   time.Time      `json:"linked_at"`

	// Tombstone, when non-nil, marks this entry as the log's record of a
	// retention removal. It is part of the preimage, so the head signature
	// covers it, and the gap it names is the only thing that makes a missing
	// sequence range legal.
	Tombstone *TombstoneView `json:"tombstone,omitempty"`

	ChainHash string `json:"chain_hash"`
	Leaf      string `json:"leaf"`
}

// TombstoneView mirrors audit.Tombstone field for field. The verifier must not
// import the producer, so the shape is duplicated here and
// TestVerifierAgreesOnEntryPreimage fails the build if the two drift.
type TombstoneView struct {
	FromSequence uint64    `json:"from_sequence"`
	ToSequence   uint64    `json:"to_sequence"`
	Reason       string    `json:"reason"`
	AuthorisedBy string    `json:"authorised_by"`
	PolicyID     string    `json:"policy_id,omitempty"`
	RecordCount  uint64    `json:"record_count,omitempty"`
	ReceiptCount uint64    `json:"receipt_count,omitempty"`
	RemovedAt    time.Time `json:"removed_at"`
}

// entryPreimage mirrors audit.Entry field for field. The two must agree byte
// for byte; TestVerifierAgreesOnEntryPreimage in internal/audit fails the build
// if they drift.
type entryPreimage struct {
	ActorID    string         `json:"actor_id"`
	Allowed    bool           `json:"allowed"`
	AmountUSD  float64        `json:"amount_usd"`
	Capability string         `json:"capability"`
	GrantID    string         `json:"grant_id"`
	IntentID   string         `json:"intent_id"`
	LinkedAt   time.Time      `json:"linked_at"`
	OccurredAt time.Time      `json:"occurred_at"`
	RecordHash string         `json:"record_hash"`
	Sequence   uint64         `json:"sequence"`
	TenantID   string         `json:"tenant_id"`
	Tier       types.RiskTier `json:"tier"`
	Tombstone  *TombstoneView `json:"tombstone,omitempty"`
}

func (e EntryView) preimage() ([]byte, error) {
	return hash.CanonicalJSON(entryPreimage{
		ActorID:    e.ActorID,
		Allowed:    e.Allowed,
		AmountUSD:  e.AmountUSD,
		Capability: e.Capability,
		GrantID:    e.GrantID,
		IntentID:   e.IntentID,
		LinkedAt:   e.LinkedAt,
		OccurredAt: e.OccurredAt,
		RecordHash: e.RecordHash,
		Sequence:   e.Sequence,
		TenantID:   e.TenantID,
		Tier:       e.Tier,
		Tombstone:  e.Tombstone,
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
