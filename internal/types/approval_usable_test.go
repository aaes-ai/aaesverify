package types

import (
	"strings"
	"testing"
	"time"
)

func grantedApproval(intentID string, expires time.Time) Approval {
	return Approval{
		ApprovalID: "apr-1", TenantID: "t1", WorkID: "w1",
		IntentID: intentID, Approver: "human-1", State: ApprovalGranted,
		ExpiresAt: expires, DecidedAt: time.Now().UTC(),
	}
}

// An approval authorises exactly one action. The dangerous failure is leniency:
// an approval that satisfies more than it should is worse than one that
// satisfies nothing, because nothing about the system looks wrong afterwards.
func TestUsableIsExactAboutTheIntent(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)

	if err := grantedApproval("int-1", future).Usable("int-1", now); err != nil {
		t.Fatalf("a matching approval was refused: %v", err)
	}
	for _, tc := range []struct {
		name     string
		approval Approval
		intent   string
	}{
		{"approval for another intent", grantedApproval("int-1", future), "int-2"},
		{"approval with no intent bound", grantedApproval("", future), "int-1"},
		{"no intent requested", grantedApproval("int-1", future), ""},
		{"neither side bound", grantedApproval("", future), ""},
	} {
		if err := tc.approval.Usable(tc.intent, now); err == nil {
			t.Fatalf("%s: Usable returned nil; an approval must authorise one action or none", tc.name)
		}
	}
}

func TestUsableRefusesUnboundedAndExpired(t *testing.T) {
	now := time.Now().UTC()
	if err := grantedApproval("int-1", time.Time{}).Usable("int-1", now); err == nil {
		t.Fatal("an approval with no expiry was accepted; an unbounded approval is not an approval")
	}
	if err := grantedApproval("int-1", now.Add(-time.Second)).Usable("int-1", now); err == nil {
		t.Fatal("an expired approval was accepted")
	}
}

func TestUsableRefusesEveryNonGrantedState(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	for _, st := range []ApprovalState{ApprovalNotRequired, ApprovalPending, ApprovalRejected, ApprovalExpired} {
		a := grantedApproval("int-1", future)
		a.State = st
		if err := a.Usable("int-1", now); err == nil {
			t.Fatalf("state %s was accepted as usable", st)
		}
	}
}

// A granted approval naming no approver is unattributable, and an
// unattributable approval is the thing this layer exists to prevent.
func TestUsableRefusesAnUnattributedGrant(t *testing.T) {
	now := time.Now().UTC()
	a := grantedApproval("int-1", now.Add(time.Hour))
	a.Approver = ""
	err := a.Usable("int-1", now)
	if err == nil {
		t.Fatal("a granted approval with no approver was accepted")
	}
	if !strings.Contains(err.Error(), "no approver") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// An approval is raised under one policy bundle. A bundle is editable, so an
// approval that outlives the rules it was granted under must not authorise the
// same intent after those rules changed, and an approval that records no bundle
// at all must not be read as bound to whatever bundle happens to be current.
func TestBoundToBundleRefusesEveryUnboundAndMismatchedApproval(t *testing.T) {
	now := time.Now().UTC()
	a := grantedApproval("int-1", now.Add(time.Hour))
	a.BundleHash = "bundle-permissive"

	if err := a.BoundToBundle("bundle-permissive"); err != nil {
		t.Fatalf("an approval under the current bundle was refused: %v", err)
	}

	err := a.BoundToBundle("bundle-tightened")
	if err == nil {
		t.Fatal("an approval raised under one bundle authorised a decision under another")
	}
	for _, want := range []string{"bundle-permissive", "bundle-tightened"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not name %q: %v", want, err)
		}
	}

	unbound := a
	unbound.BundleHash = ""
	if err := unbound.BoundToBundle("bundle-permissive"); err == nil {
		t.Fatal("an approval recording no bundle was treated as bound to the current one")
	} else if !strings.Contains(err.Error(), "no policy bundle") {
		t.Fatalf("the refusal does not say the approval is unbound: %v", err)
	}

	// A decision that cannot name its own bundle cannot check the approval
	// against one, so it refuses rather than comparing two empty strings.
	if err := a.BoundToBundle(""); err == nil {
		t.Fatal("a bundle-less decision accepted a bundled approval")
	}
}

// Pass-through custody is observation. If it ever reports as enforcement, the
// coverage number silently becomes a lie.
func TestPassThroughIsNotEnforcement(t *testing.T) {
	if CustodyPassThrough.Enforcement() {
		t.Fatal("pass-through custody reports as enforcement, so observation would be counted as control")
	}
	for _, k := range []CustodyKind{CustodyInline, CustodyCustomerVault, CustodyIdentityFederation, CustodyCustomerBroker} {
		if !k.Enforcement() {
			t.Fatalf("custody %s reports as non-enforcement", k)
		}
	}
}
