package verifier

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// RFC 8032 section 7.1, test 1 and test 2: the seeds and the public keys they
// must derive. Using published vectors pins the key encoding to Ed25519 as
// specified rather than to whatever this package happens to produce.
const (
	rfc8032Seed1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfc8032Pub1  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	rfc8032Seed2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	rfc8032Pub2  = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)

func rfcKey(t *testing.T, seedHex, pubHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != pubHex {
		t.Fatalf("seed derives public key %s, RFC 8032 says %s", got, pubHex)
	}
	return priv
}

func signUsage(t *testing.T, r UsageReport, priv ed25519.PrivateKey) UsageReport {
	t.Helper()
	payload, err := UsageSigningPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return r
}

func rotate(t *testing.T, from, to ed25519.PrivateKey, at time.Time) UsageKeyRotation {
	t.Helper()
	prev, next := from.Public().(ed25519.PublicKey), to.Public().(ed25519.PublicKey)
	rot := UsageKeyRotation{
		Schema:            UsageKeyRotationSchema,
		PreviousKeyID:     UsageKeyFingerprint(prev),
		PreviousPublicKey: hex.EncodeToString(prev),
		KeyID:             UsageKeyFingerprint(next),
		PublicKey:         hex.EncodeToString(next),
		RotatedAt:         at,
	}
	payload, err := UsageRotationSigningPayload(rot)
	if err != nil {
		t.Fatal(err)
	}
	rot.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(from, payload))
	return rot
}

func usageFixture(priv ed25519.PrivateKey) UsageReport {
	pub := priv.Public().(ed25519.PublicKey)
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sealed := time.Date(2026, 10, 31, 23, 59, 58, 900_000_000, time.UTC)
	tenant := UsageTenant{
		LogID: hash.DeriveLogID("acme"), GovernedDecisions: 3, PermitRecords: 2, RefusalRecords: 3,
		FirstSequence: 10, LastSequence: 14, Dedupe: UsageDedupeFull,
		JournalHead: UsageJournalHead{RecordCount: 20, RecordHash: strings.Repeat("ab", 32)},
	}
	return UsageReport{
		Schema: UsageReportSchema, ReportID: "usr_" + strings.Repeat("0f", 16),
		GeneratedAt: time.Date(2026, 11, 1, 9, 12, 44, 123_000_000, time.UTC), SoftwareVersion: "test",
		DeploymentID: "dep_test", LicenseID: "lic_test", Environment: EnvironmentProduction,
		Period: UsageWindow{Kind: UsagePeriodCalendarMonth, Start: start, End: start.AddDate(0, 1, 0), Closed: true},
		Totals: UsageTotals{GovernedDecisions: 3, PermitRecords: 2, RefusalRecords: 3},
		Capacity: &UsageCapacity{
			Pool: UsagePoolLicenseTerm, TermStart: start, TermEnd: start.AddDate(1, 0, 0),
			GovernedDecisions: 100, TermToDate: 3, UsedPercent: 3, Warnings: UsageWarningsActive,
		},
		Tenants:      []UsageTenant{tenant},
		Clock:        UsageClock{MaxSealedAt: &sealed},
		Key:          UsageKey{Algorithm: "ed25519", KeyID: UsageKeyFingerprint(pub), PublicKey: hex.EncodeToString(pub)},
		KeyRotations: []UsageKeyRotation{},
	}
}

func marshalReport(t *testing.T, r UsageReport) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignedUsageReportVerifiesUnderItsOnboardedKey(t *testing.T) {
	priv := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	raw := marshalReport(t, signUsage(t, usageFixture(priv), priv))
	res := VerifyUsageReport(raw, UsageVerifyOptions{TrustedKeyFingerprints: []string{UsageKeyFingerprint(priv.Public().(ed25519.PublicKey))}})
	if !res.OK || res.KeySource != UsageKeySupplied {
		t.Fatalf("VerifyUsageReport = %+v", res)
	}
	if embedded := VerifyUsageReport(raw, UsageVerifyOptions{}); !embedded.OK || embedded.KeySource != UsageKeyEmbedded {
		t.Fatalf("embedded-key verification = %+v", embedded)
	}
}

func TestRotatedUsageKeyVerifiesThroughTheChain(t *testing.T) {
	old := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	cur := rfcKey(t, rfc8032Seed2, rfc8032Pub2)
	r := usageFixture(cur)
	r.KeyRotations = []UsageKeyRotation{rotate(t, old, cur, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))}
	raw := marshalReport(t, signUsage(t, r, cur))
	oldFP := UsageKeyFingerprint(old.Public().(ed25519.PublicKey))
	if res := VerifyUsageReport(raw, UsageVerifyOptions{TrustedKeyFingerprints: []string{oldFP}}); !res.OK || res.RootKeyFingerprint != oldFP {
		t.Fatalf("rotated report = %+v", res)
	}
	// Every statement verifies, but the chain roots at a key nobody trusted.
	curFP := UsageKeyFingerprint(cur.Public().(ed25519.PublicKey))
	if res := VerifyUsageReport(raw, UsageVerifyOptions{TrustedKeyFingerprints: []string{curFP}}); res.OK {
		t.Fatalf("a valid chain rooted at an untrusted key verified: %+v", res)
	}
}

// FALSIFICATION TEST 5 (ADR-029), report half: no edited report verifies.
func TestEditedUsageReportsDoNotVerify(t *testing.T) {
	priv := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	other := rfcKey(t, rfc8032Seed2, rfc8032Pub2)
	trusted := UsageKeyFingerprint(priv.Public().(ed25519.PublicKey))
	signed := signUsage(t, usageFixture(priv), priv)
	resign := func(r UsageReport) UsageReport { return signUsage(t, r, priv) }
	cases := []struct {
		name string
		edit func(UsageReport) UsageReport
	}{
		{"total decisions", func(r UsageReport) UsageReport { r.Totals.GovernedDecisions--; return r }},
		{"tenant decisions", func(r UsageReport) UsageReport { r.Tenants[0].GovernedDecisions = 1; return r }},
		{"refusal records", func(r UsageReport) UsageReport { r.Tenants[0].RefusalRecords = 0; return r }},
		{"period start", func(r UsageReport) UsageReport { r.Period.Start = r.Period.Start.AddDate(0, -1, 0); return r }},
		{"period closed flag", func(r UsageReport) UsageReport { r.Period.Closed = false; return r }},
		{"journal head hash", func(r UsageReport) UsageReport {
			r.Tenants[0].JournalHead.RecordHash = strings.Repeat("cd", 32)
			return r
		}},
		{"journal head count", func(r UsageReport) UsageReport { r.Tenants[0].JournalHead.RecordCount++; return r }},
		{"sequence range", func(r UsageReport) UsageReport { r.Tenants[0].LastSequence = 13; return r }},
		{"log id", func(r UsageReport) UsageReport { r.Tenants[0].LogID = hash.DeriveLogID("other"); return r }},
		{"license id", func(r UsageReport) UsageReport { r.LicenseID = "lic_other"; return r }},
		{"environment", func(r UsageReport) UsageReport { r.Environment = EnvironmentNonProduction; return r }},
		{"term to date", func(r UsageReport) UsageReport { r.Capacity.TermToDate = 1; return r }},
		{"capacity pool", func(r UsageReport) UsageReport { r.Capacity.GovernedDecisions = 1000; return r }},
		{"previous report", func(r UsageReport) UsageReport {
			r.PreviousReport = &UsageReportLink{ReportID: r.ReportID, Digest: strings.Repeat("00", 32)}
			return r
		}},
		{"key swapped, signature kept", func(r UsageReport) UsageReport {
			pub := other.Public().(ed25519.PublicKey)
			r.Key = UsageKey{Algorithm: "ed25519", KeyID: UsageKeyFingerprint(pub), PublicKey: hex.EncodeToString(pub)}
			return r
		}},
		{"re-signed by an untrusted key", func(r UsageReport) UsageReport {
			pub := other.Public().(ed25519.PublicKey)
			r.Key = UsageKey{Algorithm: "ed25519", KeyID: UsageKeyFingerprint(pub), PublicKey: hex.EncodeToString(pub)}
			return signUsage(t, r, other)
		}},
		{"rotation chain forged by the new key", func(r UsageReport) UsageReport {
			rot := rotate(t, other, other, r.GeneratedAt)
			rot.PreviousKeyID, rot.PreviousPublicKey = r.Key.KeyID, r.Key.PublicKey
			pub := other.Public().(ed25519.PublicKey)
			r.Key = UsageKey{Algorithm: "ed25519", KeyID: UsageKeyFingerprint(pub), PublicKey: hex.EncodeToString(pub)}
			r.KeyRotations = []UsageKeyRotation{rot}
			return signUsage(t, r, other)
		}},
		{"rotation chain ending elsewhere", func(r UsageReport) UsageReport {
			r.KeyRotations = []UsageKeyRotation{rotate(t, priv, other, r.GeneratedAt)}
			return resign(r)
		}},
		{"re-signed with sums broken", func(r UsageReport) UsageReport { r.Totals.PermitRecords = 7; return resign(r) }},
		{"re-signed with decisions above records", func(r UsageReport) UsageReport {
			r.Tenants[0].GovernedDecisions, r.Totals.GovernedDecisions = 9, 9
			r.Capacity.TermToDate, r.Capacity.UsedPercent = 9, 9
			return resign(r)
		}},
		{"re-signed with suppressed warnings in production", func(r UsageReport) UsageReport { r.Capacity.Warnings = UsageWarningsSuppressed; return resign(r) }},
		{"signature truncated", func(r UsageReport) UsageReport { r.Signature = r.Signature[:20]; return r }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edited := signed
			edited.Tenants = append([]UsageTenant(nil), signed.Tenants...)
			c := *signed.Capacity
			edited.Capacity = &c
			raw := marshalReport(t, tc.edit(edited))
			res := VerifyUsageReport(raw, UsageVerifyOptions{TrustedKeyFingerprints: []string{trusted}})
			if res.OK {
				t.Fatal("an edited report verified")
			}
		})
	}
}

func TestUsageReportRefusesUnknownFieldsAndTheLedgerKey(t *testing.T) {
	priv := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	raw := marshalReport(t, signUsage(t, usageFixture(priv), priv))
	extended := append(raw[:len(raw)-1:len(raw)-1], []byte(`,"unsigned":1}`)...)
	if res := VerifyUsageReport(extended, UsageVerifyOptions{}); res.OK {
		t.Fatal("a report with an unsigned field verified")
	}
	res := VerifyUsageReport(raw, UsageVerifyOptions{LedgerPublicKey: priv.Public().(ed25519.PublicKey)})
	if res.OK || !strings.Contains(strings.Join(res.Errors, "\n"), "ledger key") {
		t.Fatalf("a usage key equal to the ledger key verified: %+v", res)
	}
	for _, trailing := range []string{"{}", "}", "]"} {
		if _, err := ParseUsageReport(append(append([]byte(nil), raw...), trailing...)); !errors.Is(err, ErrUsageReport) {
			t.Fatalf("ParseUsageReport(trailing %q) = %v", trailing, err)
		}
	}
	if _, err := ParseUsageReport(append(append([]byte(nil), raw...), '\n')); err != nil {
		t.Fatalf("trailing whitespace refused: %v", err)
	}
}

func TestUsageReportDigestCoversTheSignedPayload(t *testing.T) {
	priv := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	a := signUsage(t, usageFixture(priv), priv)
	b := a
	b.Totals.PermitRecords++
	da, _ := UsageReportDigest(a)
	db, _ := UsageReportDigest(b)
	if len(da) != 64 || da == db {
		t.Fatalf("digests %q and %q", da, db)
	}
	payload, _ := UsageSigningPayload(a)
	if !strings.HasPrefix(string(payload), "aaes/usage-report/1\x00{") || strings.Contains(string(payload), `"signature"`) {
		t.Fatalf("signing payload %q does not carry the domain or still carries the signature", payload[:40])
	}
}

func TestUsageReportRefusesMalformedKeysChainsAndSums(t *testing.T) {
	priv := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	other := rfcKey(t, rfc8032Seed2, rfc8032Pub2)
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	signedBy := func(k ed25519.PrivateKey, edit func(*UsageReport)) UsageReport {
		r := usageFixture(k)
		edit(&r)
		return signUsage(t, r, k)
	}
	rotated := func(edit func(*UsageKeyRotation)) UsageReport {
		return signedBy(other, func(r *UsageReport) {
			rot := rotate(t, priv, other, at)
			edit(&rot)
			r.KeyRotations = []UsageKeyRotation{rot}
		})
	}
	cases := []struct {
		name   string
		report UsageReport
		want   string
	}{
		{"public key not hex", signedBy(priv, func(r *UsageReport) { r.Key.PublicKey = "zz" }), "key: not a hex Ed25519 public key"},
		{"public key too short", signedBy(priv, func(r *UsageReport) { r.Key.PublicKey = "abcd" }), "key: not a hex Ed25519 public key"},
		{"algorithm", signedBy(priv, func(r *UsageReport) { r.Key.Algorithm = "rsa" }), "named by its fingerprint"},
		{"report id", signedBy(priv, func(r *UsageReport) { r.ReportID = "usx_" + strings.Repeat("0f", 16) }), "report_id"},
		{"rotation previous key", rotated(func(r *UsageKeyRotation) { r.PreviousPublicKey = "zz" }), "previous key"},
		{"rotation key", rotated(func(r *UsageKeyRotation) { r.PublicKey = "zz" }), "rotation 0: key"},
		{"rotation schema", rotated(func(r *UsageKeyRotation) { r.Schema = "aaes.usage-key-rotation/2" }), "schema"},
		{"rotation key ids", rotated(func(r *UsageKeyRotation) { r.KeyID = strings.Repeat("00", 32) }), "key ids do not name"},
		{"rotation not signed", rotated(func(r *UsageKeyRotation) { r.RotatedAt = r.RotatedAt.Add(time.Second) }), "not signed by the previous key"},
		{"broken chain", signedBy(other, func(r *UsageReport) {
			r.KeyRotations = []UsageKeyRotation{rotate(t, priv, other, at), rotate(t, priv, other, at)}
		}), "does not continue the chain"},
		{"inverted sequence range", signedBy(priv, func(r *UsageReport) { r.Tenants[0].FirstSequence = 20 }), "sequence range"},
		{"no pool", signedBy(priv, func(r *UsageReport) { r.Capacity.Pool = "monthly" }), "no license term pool"},
		{"used percent", signedBy(priv, func(r *UsageReport) { r.Capacity.UsedPercent = 50 }), "used_percent"},
		{"term below the period", signedBy(priv, func(r *UsageReport) { r.Capacity.TermToDate, r.Capacity.UsedPercent = 2, 2 }), "below the period's own count"},
		{"projection below usage", signedBy(priv, func(r *UsageReport) { p := uint64(1); r.Capacity.ProjectedTermTotal = &p }), "projection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := VerifyUsageReport(marshalReport(t, tc.report), UsageVerifyOptions{})
			if res.OK || !strings.Contains(strings.Join(res.Errors, "\n"), tc.want) {
				t.Fatalf("errors %q, want one containing %q", res.Errors, tc.want)
			}
		})
	}
}

// Go's JSON encoding refuses years past 9999, so a report built with one has
// no signing payload and no digest.
func TestAnUnencodableReportHasNoDigest(t *testing.T) {
	r := usageFixture(rfcKey(t, rfc8032Seed1, rfc8032Pub1))
	r.GeneratedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := UsageReportDigest(r); err == nil {
		t.Fatal("a report with a five-digit year produced a digest")
	}
}
