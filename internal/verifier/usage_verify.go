package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Where the key a usage report verified under came from.
const (
	UsageKeyEmbedded = "embedded"
	UsageKeySupplied = "supplied"
)

// UsageVerifyOptions are the caller-supplied trust inputs.
type UsageVerifyOptions struct {
	// TrustedKeyFingerprints are usage-key fingerprints obtained out of band
	// (the license's usage_key_fingerprint, or a key the vendor recorded at
	// onboarding). When set, the report's rotation chain must start at one.
	TrustedKeyFingerprints []string
	// LedgerPublicKey is the head signing key of an export supplied beside the
	// report. A usage key equal to it is refused: one key may not serve two
	// purposes.
	LedgerPublicKey []byte
}

// UsageResult is the outcome of verifying one usage report.
type UsageResult struct {
	OK        bool        `json:"ok"`
	Report    UsageReport `json:"-"`
	KeySource string      `json:"key_source"`
	// RootKeyFingerprint is the key the rotation chain starts at.
	RootKeyFingerprint string   `json:"root_key_fingerprint"`
	Digest             string   `json:"digest"`
	Errors             []string `json:"errors,omitempty"`
}

// VerifyUsageReport checks a report offline: schema and shape, the rotation
// chain, the signature, and the internal sums. It never proves the counts are
// complete; that needs a recount from the journal or an export sidecar.
func VerifyUsageReport(raw []byte, opts UsageVerifyOptions) UsageResult {
	res := UsageResult{KeySource: UsageKeyEmbedded}
	r, err := ParseUsageReport(raw)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	res.Report = r
	if err := verifyUsageShape(r); err != nil {
		res.Errors = append(res.Errors, err.Error())
	}
	root, err := verifyUsageKeys(r, opts.LedgerPublicKey)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
	}
	res.RootKeyFingerprint = root
	if len(opts.TrustedKeyFingerprints) > 0 {
		res.KeySource = UsageKeySupplied
		if !containsFold(opts.TrustedKeyFingerprints, root) {
			res.Errors = append(res.Errors, fmt.Sprintf("%v: the rotation chain starts at key %s, which is not a trusted usage key", ErrUsageReport, root))
		}
	}
	if err := verifyUsageSums(r); err != nil {
		res.Errors = append(res.Errors, err.Error())
	}
	if d, err := UsageReportDigest(r); err == nil {
		res.Digest = d
	}
	res.OK = len(res.Errors) == 0
	return res
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

func usageErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUsageReport}, args...)...)
}

func verifyUsageShape(r UsageReport) error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, usageErr(format, args...))
		}
	}
	check(r.Schema == UsageReportSchema, "schema %q is not %s", r.Schema, UsageReportSchema)
	check(isPrefixedHex(r.ReportID, "usr_", 32), "report_id %q is not usr_ followed by 32 hex digits", r.ReportID)
	check(isUTC(r.GeneratedAt), "generated_at is not a UTC time")
	check(r.DeploymentID != "", "deployment_id is empty")
	check(r.Environment == EnvironmentProduction || r.Environment == EnvironmentNonProduction, "environment %q is not production or non_production", r.Environment)
	p := r.Period
	monthStart := time.Date(p.Start.Year(), p.Start.Month(), 1, 0, 0, 0, 0, time.UTC)
	check(p.Kind == UsagePeriodCalendarMonth, "period kind %q is not %s", p.Kind, UsagePeriodCalendarMonth)
	check(isUTC(p.Start) && p.Start.Equal(monthStart) && p.End.Equal(monthStart.AddDate(0, 1, 0)), "period %s..%s is not one UTC calendar month", p.Start, p.End)
	check(r.Tenants != nil && r.KeyRotations != nil, "tenants and key_rotations must be arrays")
	if l := r.PreviousReport; l != nil {
		check(isPrefixedHex(l.ReportID, "usr_", 32) && isPrefixedHex(l.Digest, "", 64), "previous_report is malformed")
	}
	for i, t := range r.Tenants {
		check(strings.HasPrefix(t.LogID, "aaes/log-id/1/") && isPrefixedHex(t.LogID, "aaes/log-id/1/", 64), "tenant %d log_id %q is malformed", i, t.LogID)
		check(i == 0 || r.Tenants[i-1].LogID < t.LogID, "tenants are not sorted by unique log_id")
		check(t.Dedupe == UsageDedupeFull || t.Dedupe == UsageDedupePartial, "tenant %s dedupe %q is not full or partial", t.LogID, t.Dedupe)
		check(t.JournalHead.RecordHash == "" || isPrefixedHex(t.JournalHead.RecordHash, "", 64), "tenant %s journal head hash is malformed", t.LogID)
	}
	return errors.Join(errs...)
}

// verifyUsageKeys checks the signing key, walks the rotation chain back to
// its root and verifies every signature on the way. It returns the root key
// fingerprint.
func verifyUsageKeys(r UsageReport, ledgerKey []byte) (string, error) {
	pub, err := usagePublicKey(r.Key.PublicKey)
	if err != nil {
		return "", usageErr("key: %v", err)
	}
	if r.Key.Algorithm != "ed25519" || r.Key.KeyID != UsageKeyFingerprint(pub) {
		return "", usageErr("key is not an ed25519 key named by its fingerprint")
	}
	chain, err := walkRotations(r.KeyRotations, r.Key.KeyID)
	if err != nil {
		return "", err
	}
	root := r.Key.KeyID
	if len(r.KeyRotations) > 0 {
		root = r.KeyRotations[0].PreviousKeyID
	}
	for _, k := range append(chain, pub) {
		if len(ledgerKey) > 0 && bytes.Equal(k, ledgerKey) {
			return root, usageErr("the usage key is the ledger key of the supplied export")
		}
	}
	// A report that cannot be encoded cannot have been signed.
	payload, err := UsageSigningPayload(r)
	if err != nil || !verifyEd25519B64(pub, payload, r.Signature) {
		return root, usageErr("signature does not verify under the report key")
	}
	return root, nil
}

// VerifyUsageKeyRotations checks a rotation chain the way a report's is
// checked: each statement signed by the key before it, each continuing the
// one before, and the chain ending at endKeyID. The deployment runs it on its
// own chain when it opens the usage key.
func VerifyUsageKeyRotations(rotations []UsageKeyRotation, endKeyID string) error {
	_, err := walkRotations(rotations, endKeyID)
	return err
}

// walkRotations verifies each rotation statement, oldest first, and that the
// chain ends at the signing key. It returns every previous key in the chain.
func walkRotations(rotations []UsageKeyRotation, signingKeyID string) ([]ed25519.PublicKey, error) {
	var chain []ed25519.PublicKey
	expectNext := ""
	for i, rot := range rotations {
		prev, err := verifyRotation(rot)
		if err != nil {
			return nil, usageErr("rotation %d: %v", i, err)
		}
		if expectNext != "" && rot.PreviousKeyID != expectNext {
			return nil, usageErr("rotation %d does not continue the chain", i)
		}
		expectNext = rot.KeyID
		chain = append(chain, prev)
	}
	if expectNext != "" && expectNext != signingKeyID {
		return nil, usageErr("the rotation chain ends at %s, not at the signing key %s", expectNext, signingKeyID)
	}
	return chain, nil
}

// verifyRotation checks one statement's shape and its signature by the
// previous key, and returns that key.
func verifyRotation(rot UsageKeyRotation) (ed25519.PublicKey, error) {
	prev, err := usagePublicKey(rot.PreviousPublicKey)
	if err != nil {
		return nil, fmt.Errorf("previous key: %w", err)
	}
	next, err := usagePublicKey(rot.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	if rot.Schema != UsageKeyRotationSchema {
		return nil, fmt.Errorf("schema %q", rot.Schema)
	}
	if rot.PreviousKeyID != UsageKeyFingerprint(prev) || rot.KeyID != UsageKeyFingerprint(next) {
		return nil, errors.New("key ids do not name its keys")
	}
	payload, err := UsageRotationSigningPayload(rot)
	if err != nil || !verifyEd25519B64(prev, payload, rot.Signature) {
		return nil, errors.New("not signed by the previous key")
	}
	return prev, nil
}

func usagePublicKey(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not a hex Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

func verifyEd25519B64(pub ed25519.PublicKey, msg []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	return err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, sig)
}

func isUTC(t time.Time) bool { return !t.IsZero() && t.Location() == time.UTC }

func isPrefixedHex(s, prefix string, n int) bool {
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+n {
		return false
	}
	return strings.Trim(s[len(prefix):], "0123456789abcdef") == ""
}
