package types

import (
	"strings"
	"testing"
)

// A capability that declares verbs is bound by the highest floor among them.
// The rule is the ADR's falsification test: a capability registered below the
// floor of a verb it DECLARES must fail registration, naming the verb and the
// tiers, because RiskTier is what policy and the approval gate compare against.
func TestCapabilityRefusesATierBelowTheFloorOfADeclaredVerb(t *testing.T) {
	base := Capability{
		CapabilityID: "files", Version: "1.0.0", Kind: CapSkill,
		RiskTier: R2RiskTier, Owner: "ops",
	}
	cases := []struct {
		name   string
		mut    func(*Capability)
		want   []string
		refuse bool
	}{
		{"read at R0 is at its floor", func(c *Capability) {
			c.RiskTier = R0RiskTier
			c.Actions = []Action{ActionRead}
		}, nil, false},
		{"write at R2 is at its floor", func(c *Capability) {
			c.Actions = []Action{ActionWrite}
		}, nil, false},
		{"delete at R3 is at its floor", func(c *Capability) {
			c.RiskTier = R3RiskTier
			c.Actions = []Action{ActionDelete}
		}, nil, false},
		{"write at R1 is below its floor", func(c *Capability) {
			c.RiskTier = R1RiskTier
			c.Actions = []Action{ActionWrite}
		}, []string{"write", "R2", "R1"}, true},
		{"delete at R2 is below its floor", func(c *Capability) {
			c.Actions = []Action{ActionDelete}
		}, []string{"delete", "R3", "R2"}, true},
		{"one buried delete still binds", func(c *Capability) {
			c.RiskTier = R2RiskTier
			c.Actions = []Action{ActionRead, ActionDelete}
		}, []string{"delete", "R3"}, true},
		// A capability that declares no verbs keeps its registered tier: the
		// invoke default is applied where a decision names a verb, and it does
		// not retroactively refuse every pre-existing R0/R1 registration.
		{"no declared verbs keeps the registered tier", func(c *Capability) {
			c.RiskTier = R0RiskTier
			c.Actions = nil
		}, nil, false},
		// The list itself is validated: an unnameable verb and a repeated verb
		// are both registration mistakes, not inputs to a floor computation.
		{"an unnameable verb is refused", func(c *Capability) {
			c.RiskTier = R3RiskTier
			c.Actions = []Action{Action(99)}
		}, []string{"unknown action 99"}, true},
		{"a repeated verb is refused", func(c *Capability) {
			c.Actions = []Action{ActionRead, ActionRead}
		}, []string{"twice", "read"}, true},
	}
	for _, tc := range cases {
		c := base
		tc.mut(&c)
		err := c.Validate()
		if !tc.refuse {
			if err != nil {
				t.Fatalf("%s: a valid capability was refused: %v", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: a capability registered below the floor of a declared verb was accepted", tc.name)
		}
		for _, want := range tc.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: refusal %q does not name %q", tc.name, err, want)
			}
		}
	}
}

// A capability that touches regulated data must name the resource it touches.
// Without it a sealed intent records "pii" with no object, and the register of
// record cannot answer which data an actor can reach.
func TestCapabilityRefusesRegulatedDataWithNoResource(t *testing.T) {
	for _, class := range []DataClassification{DataPII, DataPHI, DataFinancial} {
		c := Capability{
			CapabilityID: "customers", Version: "1.0.0", Kind: CapSkill,
			RiskTier: R2RiskTier, Owner: "ops", DataClass: class,
		}
		err := c.Validate()
		if err == nil {
			t.Fatalf("a capability for %s data with no ResourceID was accepted", class)
		}
		if !strings.Contains(err.Error(), class.String()) || !strings.Contains(err.Error(), "resource") {
			t.Errorf("%s: refusal %q does not name the class and the missing resource", class, err)
		}
		c.ResourceID = "res-customers"
		if err := c.Validate(); err != nil {
			t.Errorf("%s: naming the resource did not satisfy the rule: %v", class, err)
		}
	}
	// Below PII no resource is required: a public or internal capability keeps
	// registering exactly as it did before the field existed.
	for _, class := range []DataClassification{DataPublic, DataInternal} {
		c := Capability{
			CapabilityID: "docs", Version: "1.0.0", Kind: CapSkill,
			RiskTier: R2RiskTier, Owner: "ops", DataClass: class,
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: a capability with no resource was refused: %v", class, err)
		}
	}
}

// EffectiveActions is where the legacy default lives: no declared verbs means
// invoke, the narrowest verb, not the union of everything the capability might
// do. The returned slice is a copy, so a caller cannot widen a registration
// through a getter.
func TestEffectiveActionsDefaultsToInvokeAndHandsBackACopy(t *testing.T) {
	legacy := Capability{CapabilityID: "legacy", Version: "1.0.0", Kind: CapTool, RiskTier: R2RiskTier, Owner: "ops"}
	got := legacy.EffectiveActions()
	if len(got) != 1 || got[0] != ActionInvoke {
		t.Fatalf("a capability that declares no verbs effective actions = %v, want [invoke]", got)
	}
	declared := Capability{
		CapabilityID: "files", Version: "1.0.0", Kind: CapSkill, RiskTier: R2RiskTier, Owner: "ops",
		Actions: []Action{ActionRead, ActionWrite},
	}
	got = declared.EffectiveActions()
	if len(got) != 2 || got[0] != ActionRead || got[1] != ActionWrite {
		t.Fatalf("declared effective actions = %v, want [read write]", got)
	}
	got[0] = ActionDelete
	if declared.Actions[0] != ActionRead {
		t.Fatal("mutating the slice EffectiveActions returned changed the capability")
	}
}

// Scope restriction lists are additive: an empty list keeps today's behaviour
// for every existing registration, and a list that is present is a restriction
// and is validated as one.
func TestScopeValidatesRestrictionLists(t *testing.T) {
	base := Scope{Capability: "spend", MaxTier: R3RiskTier}
	if err := base.Validate(); err != nil {
		t.Fatalf("a scope with no restriction lists was refused: %v", err)
	}
	ok := []Scope{
		{Capability: "spend", MaxTier: R3RiskTier, Actions: []Action{ActionRead, ActionPay}},
		{Capability: "spend", MaxTier: R3RiskTier, ResourceIDs: []string{"res-a", "res-b"}},
		{Capability: "spend", MaxTier: R3RiskTier, DataClasses: []DataClassification{DataInternal, DataPII}},
	}
	for i, s := range ok {
		if err := s.Validate(); err != nil {
			t.Fatalf("valid scope %d was refused: %v", i, err)
		}
	}
	bad := []struct {
		name string
		s    Scope
		want string
	}{
		{"invalid action", Scope{Capability: "spend", MaxTier: R3RiskTier, Actions: []Action{Action(42)}}, "unknown action"},
		{"duplicate action", Scope{Capability: "spend", MaxTier: R3RiskTier, Actions: []Action{ActionRead, ActionRead}}, "twice"},
		{"empty resource id", Scope{Capability: "spend", MaxTier: R3RiskTier, ResourceIDs: []string{""}}, "empty resource id"},
		{"whitespace resource id", Scope{Capability: "spend", MaxTier: R3RiskTier, ResourceIDs: []string{"res-a", "   "}}, "empty resource id"},
		{"invalid data class", Scope{Capability: "spend", MaxTier: R3RiskTier, DataClasses: []DataClassification{DataClassification(9)}}, "unknown data classification"},
	}
	for _, tc := range bad {
		err := tc.s.Validate()
		if err == nil {
			t.Fatalf("%s: the scope was accepted", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: refusal %q does not contain %q", tc.name, err, tc.want)
		}
	}
}
