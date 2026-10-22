package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// The aaes.usage-report/1 format (ADR-029 section 3). The verifier owns the
// format so the offline reader is the specification; the daemon builds reports
// from these types and signs the payload UsageSigningPayload returns.

// Usage report and key rotation schemas and the signature domains that keep a
// usage signature from being valid for any other AAES object.
const (
	UsageReportSchema      = "aaes.usage-report/1"
	UsageKeyRotationSchema = "aaes.usage-key-rotation/1"
	usageReportDomain      = "aaes/usage-report/1"
	usageRotationDomain    = "aaes/usage-key-rotation/1"
)

// Vocabularies a report carries.
const (
	UsagePeriodCalendarMonth = "calendar_month"
	UsagePoolLicenseTerm     = "license_term"
	UsageDedupeFull          = "full"
	UsageDedupePartial       = "partial"
	UsageWarningsActive      = "active"
	UsageWarningsSuppressed  = "suppressed"
	EnvironmentProduction    = "production"
	EnvironmentNonProduction = "non_production"

	// MaxUsageReportBytes bounds a caller-supplied usage report. The decoder
	// refuses anything larger before it allocates the parsed value.
	MaxUsageReportBytes = 16 << 20
)

// ErrUsageReport is wrapped by every usage report refusal.
var ErrUsageReport = errors.New("verifier: usage report does not verify")

// UsageReport is one signed usage report.
type UsageReport struct {
	Schema          string             `json:"schema"`
	ReportID        string             `json:"report_id"`
	GeneratedAt     time.Time          `json:"generated_at"`
	SoftwareVersion string             `json:"software_version"`
	DeploymentID    string             `json:"deployment_id"`
	LicenseID       string             `json:"license_id"`
	Environment     string             `json:"environment"`
	Period          UsageWindow        `json:"period"`
	Totals          UsageTotals        `json:"totals"`
	Capacity        *UsageCapacity     `json:"capacity"`
	Tenants         []UsageTenant      `json:"tenants"`
	Clock           UsageClock         `json:"clock"`
	PreviousReport  *UsageReportLink   `json:"previous_report"`
	Key             UsageKey           `json:"key"`
	KeyRotations    []UsageKeyRotation `json:"key_rotations"`
	Signature       string             `json:"signature,omitempty"`
}

// UsageWindow is the reported calendar month.
type UsageWindow struct {
	Kind   string    `json:"kind"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Closed bool      `json:"closed"`
}

// UsageTotals sums the tenants.
type UsageTotals struct {
	GovernedDecisions uint64 `json:"governed_decisions"`
	PermitRecords     uint64 `json:"permit_records"`
	RefusalRecords    uint64 `json:"refusal_records"`
	DeferralRecords   uint64 `json:"deferral_records"`
	// ModelRecords counts model-gateway decisions, which are reported beside
	// the governed decisions and never counted (ADR-029 §11, item 9).
	ModelRecords uint64 `json:"model_records,omitempty"`
}

// UsageCapacity is the license term pool; null on a report with no valid
// license.
type UsageCapacity struct {
	Pool               string    `json:"pool"`
	TermStart          time.Time `json:"term_start"`
	TermEnd            time.Time `json:"term_end"`
	GovernedDecisions  uint64    `json:"governed_decisions"`
	TermToDate         uint64    `json:"term_to_date"`
	UsedPercent        uint64    `json:"used_percent"`
	ProjectedTermTotal *uint64   `json:"projected_term_total"`
	Warnings           string    `json:"warnings"`
}

// UsageTenant is one tenant's count, named by log id only.
type UsageTenant struct {
	LogID                 string           `json:"log_id"`
	GovernedDecisions     uint64           `json:"governed_decisions"`
	PermitRecords         uint64           `json:"permit_records"`
	RefusalRecords        uint64           `json:"refusal_records"`
	DeferralRecords       uint64           `json:"deferral_records"`
	ModelRecords          uint64           `json:"model_records,omitempty"`
	FirstSequence         uint64           `json:"first_sequence"`
	LastSequence          uint64           `json:"last_sequence"`
	JournalHead           UsageJournalHead `json:"journal_head"`
	Dedupe                string           `json:"dedupe"`
	RetentionSummaries    uint64           `json:"retention_summaries"`
	RetentionInsidePeriod bool             `json:"retention_inside_period"`
}

// Records is the tenant's counted records of every outcome.
func (t UsageTenant) Records() uint64 { return t.PermitRecords + t.RefusalRecords + t.DeferralRecords }

// UsageJournalHead is the journal head commitment at generation time.
type UsageJournalHead struct {
	RecordCount uint64 `json:"record_count"`
	RecordHash  string `json:"record_hash"`
}

// UsageClock reports the clock evidence of the period.
type UsageClock struct {
	MaxSealedAt *time.Time `json:"max_sealed_at"`
	Regressions uint64     `json:"regressions"`
}

// UsageReportLink chains a report to the one before it.
type UsageReportLink struct {
	ReportID string `json:"report_id"`
	Digest   string `json:"digest"`
}

// UsageKey is the deployment usage key that signed the report.
type UsageKey struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// UsageKeyRotation is a statement, signed by the previous usage key, that
// names its successor.
type UsageKeyRotation struct {
	Schema            string    `json:"schema"`
	PreviousKeyID     string    `json:"previous_key_id"`
	PreviousPublicKey string    `json:"previous_public_key"`
	KeyID             string    `json:"key_id"`
	PublicKey         string    `json:"public_key"`
	RotatedAt         time.Time `json:"rotated_at"`
	Signature         string    `json:"signature,omitempty"`
}

// UsageKeyFingerprint is the SHA-256 hex of an Ed25519 usage public key. It is
// the key id a report names and the fingerprint a license binds.
func UsageKeyFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// UsageSigningPayload is the exact byte string a usage report signature
// covers: the domain, a zero byte and the canonical report without its
// signature.
func UsageSigningPayload(r UsageReport) ([]byte, error) {
	r.Signature = ""
	return domainPayload(usageReportDomain, r)
}

// UsageRotationSigningPayload is the byte string a rotation statement's
// signature covers.
func UsageRotationSigningPayload(rot UsageKeyRotation) ([]byte, error) {
	rot.Signature = ""
	return domainPayload(usageRotationDomain, rot)
}

// UsageReportDigest is the SHA-256 hex of a report's signed payload, the value
// the next report's previous_report.digest names.
func UsageReportDigest(r UsageReport) (string, error) {
	payload, err := UsageSigningPayload(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func domainPayload(domain string, v any) ([]byte, error) {
	body, err := hash.CanonicalJSON(v)
	if err != nil {
		return nil, fmt.Errorf("canonical encoding: %w", err)
	}
	out := make([]byte, 0, len(domain)+1+len(body))
	out = append(out, domain...)
	out = append(out, 0)
	return append(out, body...), nil
}

// ParseUsageReport decodes a report strictly: an unknown field is refused,
// because a field the signature check does not know is a field nobody signed,
// and so is a member repeated exactly or under case folding.
func ParseUsageReport(raw []byte) (UsageReport, error) {
	if int64(len(raw)) > MaxUsageReportBytes {
		return UsageReport{}, fmt.Errorf("%w: report exceeds the %d-byte size limit", ErrUsageReport, MaxUsageReportBytes)
	}
	if err := checkTypedJSONAliases(raw, UsageReport{}); err != nil {
		return UsageReport{}, fmt.Errorf("%w: decode: %v", ErrUsageReport, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r UsageReport
	if err := dec.Decode(&r); err != nil {
		return UsageReport{}, fmt.Errorf("%w: decode: %v", ErrUsageReport, err)
	}
	// More() reports false before a stray '}' or ']', so only a second Decode
	// reaching EOF proves nothing follows the object.
	if err := dec.Decode(&json.RawMessage{}); err != io.EOF {
		return UsageReport{}, fmt.Errorf("%w: trailing data after the report object", ErrUsageReport)
	}
	return r, nil
}
