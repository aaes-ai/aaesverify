package types

import "testing"

// The label mapping is the whole product claim: a permission plane that calls
// observation enforcement is worse than no plane at all. The table pins every
// custody model in both wiring states, because a mapping that silently flips is
// exactly the defect the platform audit found.
func TestEnforcementForMapsCustodyAndWiringHonestly(t *testing.T) {
	if got := CustodyPassThrough.String(); got != "pass_through" {
		t.Fatalf("pass_through renders as %q; this test depends on the spelling", got)
	}
	cases := []struct {
		name    string
		custody CustodyKind
		live    bool
		want    Enforcement
	}{
		{"inline, wired", CustodyInline, true, Enforced},
		{"client vault, wired", CustodyCustomerVault, true, Enforced},
		{"identity federation, wired", CustodyIdentityFederation, true, Enforced},
		{"client broker, wired", CustodyCustomerBroker, true, Enforced},
		{"inline, not wired", CustodyInline, false, Inventory},
		{"client vault, not wired", CustodyCustomerVault, false, Inventory},
		{"identity federation, not wired", CustodyIdentityFederation, false, Inventory},
		{"client broker, not wired", CustodyCustomerBroker, false, Inventory},
		// Observation first: a live path does not manufacture a credential AAES
		// does not hold.
		{"pass through, a path is claimed", CustodyPassThrough, true, Observed},
		{"pass through, no path", CustodyPassThrough, false, Observed},
		// A custody value off the end of the vocabulary is not proof of
		// enforcement either: understating coverage is the safe direction.
		{"unknown custody, wired", CustodyKind(99), true, Inventory},
		{"unknown custody, not wired", CustodyKind(99), false, Inventory},
	}
	for _, tc := range cases {
		if got := EnforcementFor(tc.custody, tc.live); got != tc.want {
			t.Errorf("%s: EnforcementFor(%s, %v) = %s, want %s", tc.name, tc.custody, tc.live, got, tc.want)
		}
	}
}

// The three labels are the words the console, the API and every report must
// print, and an unrecognised label must not render as one of them.
func TestEnforcementLabelsAreTheThreeWords(t *testing.T) {
	want := map[Enforcement]string{
		Enforced:  "enforced",
		Observed:  "observed",
		Inventory: "inventory",
	}
	for e, word := range want {
		if got := e.String(); got != word {
			t.Errorf("Enforcement(%d).String() = %q, want %q", int(e), got, word)
		}
	}
	if got := Enforcement(99).String(); got != "unknown(99)" {
		t.Errorf("Enforcement(99).String() = %q, want unknown(99)", got)
	}
}
