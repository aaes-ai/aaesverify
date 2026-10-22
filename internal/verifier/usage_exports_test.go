package verifier

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// VerifyUsageKeyRotations is the check the deployment runs on its own chain
// when it opens the usage key: it accepts a chain ending at the active key and
// refuses one that ends elsewhere or does not verify.
func TestVerifyUsageKeyRotationsChecksTheDeploymentChain(t *testing.T) {
	old := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	cur := rfcKey(t, rfc8032Seed2, rfc8032Pub2)
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	chain := []UsageKeyRotation{rotate(t, old, cur, at)}
	curID := UsageKeyFingerprint(cur.Public().(ed25519.PublicKey))
	oldID := UsageKeyFingerprint(old.Public().(ed25519.PublicKey))

	if err := VerifyUsageKeyRotations(nil, curID); err != nil {
		t.Fatalf("an empty chain = %v", err)
	}
	if err := VerifyUsageKeyRotations(chain, curID); err != nil {
		t.Fatalf("a chain ending at the active key = %v", err)
	}
	if err := VerifyUsageKeyRotations(chain, oldID); err == nil || !strings.Contains(err.Error(), "not at the signing key") {
		t.Fatalf("a chain ending before the active key = %v", err)
	}
	chain[0].RotatedAt = at.Add(time.Second)
	if err := VerifyUsageKeyRotations(chain, curID); err == nil || !strings.Contains(err.Error(), "not signed by the previous key") {
		t.Fatalf("an edited rotation statement = %v", err)
	}
}

func TestUsageTenantRecordsSumsEveryOutcome(t *testing.T) {
	tenant := UsageTenant{PermitRecords: 5, RefusalRecords: 3, DeferralRecords: 2, ModelRecords: 7, GovernedDecisions: 9}
	if got := tenant.Records(); got != 10 {
		t.Fatalf("Records() = %d, want permit+refusal+deferral = 10", got)
	}
}

// CheckJSONMembers is the exported alias check other packages run on the
// evidence they parse into their own shapes.
func TestCheckJSONMembersRefusesFoldedAliasesOfTheShape(t *testing.T) {
	type shape struct {
		LogID string `json:"log_id"`
	}
	if err := CheckJSONMembers([]byte(`{"log_id":"a"}`), shape{}); err != nil {
		t.Fatalf("a single member = %v", err)
	}
	if err := CheckJSONMembers([]byte(`{"log_id":"a","LOG_ID":"b"}`), shape{}); err == nil {
		t.Fatal("CheckJSONMembers accepted one field spelled twice")
	}
	if err := CheckJSONMembers([]byte(`{"log_id":`), shape{}); err == nil {
		t.Fatal("CheckJSONMembers accepted truncated JSON")
	}
}
