package types

import "testing"

func TestEffectClassStrings(t *testing.T) {
	for c, want := range map[EffectClass]string{
		EffectDenied:       "denied",
		EffectMintedUnused: "minted_unused",
		EffectExecuted:     "executed",
		EffectAuthorized:   "authorized",
	} {
		if got := c.String(); got != want {
			t.Fatalf("EffectClass(%d).String() = %q, want %q", int(c), got, want)
		}
	}
}

// The new class was appended precisely so the existing wire values keep their
// meaning: a persisted receipt that carries class 0 still means denied, and a
// receipt that carries the new class never counts toward coverage.
func TestEffectAuthorizedIsAppendedAndNeverCountsAsCoverage(t *testing.T) {
	if EffectDenied != 0 {
		t.Fatalf("EffectDenied = %d, want 0; renumbering it rewrites the meaning of every stored receipt", int(EffectDenied))
	}
	if EffectMintedUnused != 1 || EffectExecuted != 2 {
		t.Fatalf("the existing classes were renumbered: minted_unused = %d, executed = %d", int(EffectMintedUnused), int(EffectExecuted))
	}
	if EffectAuthorized == EffectDenied || EffectAuthorized == EffectMintedUnused || EffectAuthorized == EffectExecuted {
		t.Fatal("the new class collides with an existing one")
	}
	if EffectAuthorized.CountsTowardCoverage() {
		t.Fatal("EffectAuthorized counts toward coverage; only a rail-confirmed execution may")
	}
	// The zero value must stay denied: a struct built without a class (every
	// receipt before this field existed) reads as a refusal, the fail-closed
	// direction, and the gateway must set the class explicitly on the allowed
	// path rather than relying on a default.
	if (EffectClass(0)).String() != "denied" {
		t.Fatalf("the zero EffectClass reads as %q, want denied", EffectClass(0).String())
	}
}
