package verifier

import (
	"encoding/json"
	"fmt"
	"time"
)

// Result is the machine-readable outcome of VerifyExport. It is deliberately
// verbose: an auditor should be able to see which check failed, and a
// dashboard should be able to alert on ok == false.
type Result struct {
	Path                  string    `json:"path,omitempty"`
	OK                    bool      `json:"ok"`
	Schema                string    `json:"schema"`
	LogID                 string    `json:"log_id"`
	TenantID              string    `json:"tenant_id"`
	ExportedAt            time.Time `json:"exported_at"`
	EntryCount            int       `json:"entry_count"`
	DeclaredEntryCount    uint64    `json:"declared_entry_count"`
	FirstSequence         uint64    `json:"first_sequence"`
	LastSequence          uint64    `json:"last_sequence"`
	HeadIndex             uint64    `json:"head_index"`
	HeadTreeSize          uint64    `json:"head_tree_size"`
	HeadRoot              string    `json:"head_root"`
	HeadSignedAt          time.Time `json:"head_signed_at"`
	RecomputedRoot        string    `json:"recomputed_root"`
	ChainOK               bool      `json:"chain_ok"`
	RootOK                bool      `json:"root_ok"`
	SignatureOK           bool      `json:"signature_ok"`
	KeySource             string    `json:"key_source"`
	PublicKeyHex          string    `json:"public_key_hex"`
	AnchorCount           int       `json:"anchor_count"`
	AnchorsOK             bool      `json:"anchors_ok"`
	AnchorsVerified       int       `json:"anchors_verified"`
	TimestampsChecked     int       `json:"timestamps_checked"`
	TimestampsIndependent int       `json:"timestamps_independent"`
	WitnessesVerified     int       `json:"witnesses_verified"`
	IndependentWitnesses  int       `json:"independent_witnesses"`
	// Gapped reports that the export is internally consistent but not complete:
	// one or more sequence ranges are absent, and a tombstone names each one.
	// It is a distinct result on purpose. A gapped export is never rendered as a
	// bare PASS, because "everything I was given verifies" and "I was given
	// everything" are different claims.
	Gapped            bool      `json:"gapped"`
	Gaps              []GapView `json:"gaps,omitempty"`
	TombstonesChecked int       `json:"tombstones_checked"`
	// ProtectedEntries counts entries whose actor id carries the journal
	// field-encryption marker (enc:v1:). The chain verifies over the ciphertext
	// exactly as stored; the plaintext needs the tenant's journal key, which an
	// export never contains.
	ProtectedEntries int `json:"protected_entries,omitempty"`
	// ShredEvents names every sealed record stating that a tenant destroyed its
	// journal encryption key. After one, that tenant's protected fields are
	// unreadable — reported here as recorded erasure, never as a chain failure.
	ShredEvents []ShredEventView `json:"shred_events,omitempty"`
	Warnings    []string         `json:"warnings,omitempty"`
	Errors      []string         `json:"errors,omitempty"`
	// ResultSchema names this result document. aaes.verify-result/2 is the
	// verdict vocabulary that reserves PASS for independent attestation.
	ResultSchema string `json:"result_schema,omitempty"`
	// Verdict is the same headline the text renderer prints. PASS requires an
	// independent witness or an independent timestamp. A witness-less success
	// is CONSISTENT.
	Verdict string `json:"verdict,omitempty"`
}

// ResultSchemaV2 is the verifier result document that distinguishes a
// consistency check from independent attestation.
const ResultSchemaV2 = "aaes.verify-result/2"

// IndependentAttestation reports a witness or timestamp pin that is not the
// export's own signer.
func (r *Result) IndependentAttestation() bool {
	return r != nil && (r.IndependentWitnesses > 0 || r.TimestampsIndependent > 0)
}

// IntegrityHeadline is PASS only when the check holds and an independent pin
// is present. A witness-less success is CONSISTENT. A failed or absent check
// is FAIL, even if attestation facts were recorded alongside the failure.
func (r *Result) IntegrityHeadline() string {
	if r == nil || !r.OK {
		return "FAIL"
	}
	if r.IndependentAttestation() {
		return "PASS"
	}
	return "CONSISTENT"
}

// GapView names one sequence range the export does not contain, and the
// tombstone that accounts for it. A gap with no tombstone is an error, not a
// GapView: the distinction between retention and tampering is the whole point.
type GapView struct {
	FromSequence      uint64    `json:"from_sequence"`
	ToSequence        uint64    `json:"to_sequence"`
	TombstoneSequence uint64    `json:"tombstone_sequence"`
	Reason            string    `json:"reason"`
	AuthorizedBy      string    `json:"authorised_by"`
	PolicyID          string    `json:"policy_id,omitempty"`
	RemovedAt         time.Time `json:"removed_at"`
}

const maxReportedErrors = 25

func (r *Result) addError(format string, args ...any) {
	if len(r.Errors) < maxReportedErrors {
		r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	} else if len(r.Errors) == maxReportedErrors {
		r.Errors = append(r.Errors, "... further errors truncated")
	}
}

// resultMarshalIndent is the JSON encoder MarshalResult uses. Tests replace it
// to exercise the fallback path; production always uses encoding/json.
var resultMarshalIndent = json.MarshalIndent

// MarshalResult returns r as indented JSON. Result fields are all JSON-native;
// encoding fails only when tests inject a failing marshaler. That path returns
// a closed-form refusal document together with a non-nil error so callers can
// exit non-zero.
func MarshalResult(r *Result) ([]byte, error) {
	b, err := resultMarshalIndent(r, "", "  ")
	if err != nil {
		return []byte("{\n  \"ok\": false,\n  \"errors\": [\n    \"internal: result encoding failed\"\n  ]\n}"), fmt.Errorf("verifier: result encoding failed: %w", err)
	}
	return b, nil
}
