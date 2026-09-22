package types

import (
	"math"
	"strings"
	"testing"
)

// A parser must never hand back a usable value beside an error. The old
// ParseRiskTier returned R0 -- the free, auto-executable tier -- together with
// its error, so a caller that logged the error and used the tier authorised at
// the most permissive level available for a string it could not parse.
func TestParseRiskTierRefusesRatherThanReturningR0(t *testing.T) {
	for _, raw := range []string{"", "R5", "R-1", "r3", "tier3", "3"} {
		tier, err := ParseRiskTier(raw)
		if err == nil {
			t.Fatalf("ParseRiskTier(%q) returned %s with no error", raw, tier)
		}
		if tier != RiskTierUnspecified {
			t.Fatalf("ParseRiskTier(%q) returned tier %d beside its error; want RiskTierUnspecified", raw, int(tier))
		}
		if tier.AutoExecutable() {
			t.Fatalf("the value returned beside a parse error reports itself as auto-executable (tier %d)", int(tier))
		}
	}
	for raw, want := range map[string]RiskTier{"R0": R0RiskTier, "R1": R1RiskTier, "R2": R2RiskTier, "R3": R3RiskTier, "R4": R4RiskTier} {
		got, err := ParseRiskTier(raw)
		if err != nil || got != want {
			t.Fatalf("ParseRiskTier(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
}

// The zero value of DataClassification is public, the class with the fewest
// handling requirements, so an out-of-range value must not be folded into it at
// registration.
func TestCapabilityRefusesAnUnknownDataClassification(t *testing.T) {
	base := Capability{
		CapabilityID: "pay", Version: "1.0.0", Kind: CapSkill, RiskTier: R0RiskTier, Owner: "ops",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("a public capability was refused: %v", err)
	}
	for _, bad := range []DataClassification{DataClassification(-1), DataFinancial + 1, DataClassification(99)} {
		c := base
		c.DataClass = bad
		err := c.Validate()
		if err == nil {
			t.Fatalf("data classification %d was accepted", int(bad))
		}
		if !strings.Contains(err.Error(), "data classification") {
			t.Fatalf("the refusal does not name the data classification: %v", err)
		}
	}
	for _, ok := range []DataClassification{DataPublic, DataInternal, DataPII, DataPHI, DataFinancial} {
		if !ok.Valid() {
			t.Fatalf("DataClassification(%d).Valid() = false, want true", int(ok))
		}
	}
}

// A scope's spend cap is a bound. Zero means "no cap declared" deliberately;
// a negative or non-finite cap compares false against every bound, so the old
// "> 0" check read it as unlimited, which is the opposite of what it looks like.
func TestScopeRefusesCapsThatCannotBound(t *testing.T) {
	for _, cap := range []float64{-0.01, -100, math.NaN(), math.Inf(1), math.Inf(-1)} {
		s := Scope{Capability: "spend", MaxTier: R3RiskTier, SpendCapUSD: cap}
		if err := s.Validate(); err == nil {
			t.Fatalf("scope with spend cap %v was accepted", cap)
		}
	}
	zero := Scope{Capability: "spend", MaxTier: R3RiskTier}
	if err := zero.Validate(); err != nil {
		t.Fatalf("a scope that declares no cap was refused: %v", err)
	}
	if err := (Scope{Capability: "", MaxTier: R3RiskTier}).Validate(); err == nil {
		t.Fatal("a scope with no capability was accepted")
	}
	if err := (Scope{Capability: "x", MaxTier: RiskTier(9)}).Validate(); err == nil {
		t.Fatal("a scope with an unknown tier was accepted")
	}
}

// The contract is the accountable half of a hand-off: a target that sponsors
// itself, a depth below zero or a budget that cannot be compared to a bound are
// all states nobody can reason about afterwards.
func TestDelegationContractRefusesAbsurdHandoffs(t *testing.T) {
	ok := DelegationContract{
		ContractID: "c1", TenantID: "t1", FromActor: "human-1", ToActor: "agent-1",
		TaskID: "task", Sponsor: "human-1", BudgetUSD: 10, Depth: 1,
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid contract was refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(c *DelegationContract)
	}{
		{"negative depth", func(c *DelegationContract) { c.Depth = -1 }},
		{"NaN budget", func(c *DelegationContract) { c.BudgetUSD = math.NaN() }},
		{"infinite budget", func(c *DelegationContract) { c.BudgetUSD = math.Inf(1) }},
		{"negative budget", func(c *DelegationContract) { c.BudgetUSD = -5 }},
		{"self-sponsor", func(c *DelegationContract) { c.ToActor = c.Sponsor }},
	} {
		c := ok
		tc.mut(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: an absurd contract was accepted", tc.name)
		}
	}
}
