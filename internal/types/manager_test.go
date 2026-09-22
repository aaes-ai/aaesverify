package types

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestManagerSetRefusesByItsOwnName(t *testing.T) {
	cases := []struct {
		name string
		set  ManagerSet
		want error
	}{
		{
			name: "no accountable manager",
			set: ManagerSet{
				{ActorID: "risk-1", Kind: KindHuman, Role: ManagerApprover},
				{ActorID: "audit-1", Kind: KindHuman, Role: ManagerInformed},
			},
			want: ErrManagerNoAccountable,
		},
		{
			name: "self management",
			set: ManagerSet{
				{ActorID: "agent-1", Kind: KindAgent, Role: ManagerAccountable, Primary: true},
			},
			want: ErrManagerSelf,
		},
		{
			name: "duplicate entry",
			set: ManagerSet{
				{ActorID: "lead-1", Kind: KindHuman, Role: ManagerAccountable, Primary: true},
				{ActorID: "lead-1", Kind: KindHuman, Role: ManagerApprover},
			},
			want: ErrManagerDuplicate,
		},
		{
			name: "unknown role",
			set: ManagerSet{
				{ActorID: "lead-1", Kind: KindHuman, Role: ManagerRole(99), Primary: true},
			},
			want: ErrManagerRole,
		},
		{
			name: "primary that is not accountable",
			set: ManagerSet{
				{ActorID: "lead-1", Kind: KindHuman, Role: ManagerAccountable},
				{ActorID: "risk-1", Kind: KindHuman, Role: ManagerApprover, Primary: true},
			},
			want: ErrManagerRole,
		},
		{
			name: "more than one primary",
			set: ManagerSet{
				{ActorID: "lead-1", Kind: KindHuman, Role: ManagerAccountable, Primary: true},
				{ActorID: "lead-2", Kind: KindHuman, Role: ManagerAccountable, Primary: true},
			},
			want: ErrManagerMultiplePrimary,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.set.Validate("agent-1")
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate(%s) = %v, want %v", tc.set.Describe(), err, tc.want)
			}
		})
	}
}

func TestManagerSetRoutedOrderIsPrimaryThenRestThenApprovers(t *testing.T) {
	set := ManagerSet{
		{ActorID: "risk-1", Kind: KindHuman, Role: ManagerApprover},
		{ActorID: "lead-2", Kind: KindHuman, Role: ManagerAccountable},
		{ActorID: "watch-1", Kind: KindHuman, Role: ManagerInformed},
		{ActorID: "lead-1", Kind: KindHuman, Role: ManagerAccountable, Primary: true},
		{ActorID: "supervisor-agent", Kind: KindAgent, Role: ManagerAccountable},
	}
	got := strings.Join(set.Routed().IDs(), ",")
	want := "lead-1,lead-2,supervisor-agent,risk-1,watch-1"
	if got != want {
		t.Fatalf("routing order = %s, want %s", got, want)
	}
	if got := strings.Join(set.Deciding().IDs(), ","); got != "risk-1,lead-2,lead-1,supervisor-agent" {
		t.Fatalf("deciding entries = %s, want every entry except the informed one", got)
	}
	if got := strings.Join(set.Accountable().IDs(), ","); got != "lead-2,lead-1,supervisor-agent" {
		t.Fatalf("accountable entries = %s", got)
	}
}

func TestPrimaryFallsBackToTheFirstAccountableEntry(t *testing.T) {
	set := ManagerSet{
		{ActorID: "risk-1", Kind: KindHuman, Role: ManagerApprover},
		{ActorID: "lead-1", Kind: KindHuman, Role: ManagerAccountable},
	}
	primary, ok := set.Primary()
	if !ok || primary.ActorID != "lead-1" {
		t.Fatalf("Primary() = %+v, %t; want lead-1", primary, ok)
	}
}

func TestLegacySingleManagerReadsAsAOneEntrySet(t *testing.T) {
	legacy := ActorRef{ActorID: "agent-1", TenantID: "t1", Kind: KindAgent, Sponsor: "human-1"}
	set := legacy.EffectiveManagers()
	if len(set) != 1 {
		t.Fatalf("a legacy single manager read as %d entries, want 1", len(set))
	}
	entry := set[0]
	if entry.ActorID != "human-1" || entry.Kind != KindHuman || entry.Role != ManagerAccountable || !entry.Primary {
		t.Fatalf("legacy entry = %+v, want human-1/accountable/human/primary", entry)
	}
	if got := legacy.EffectiveManagerSource(); got != ManagerSourceLegacy {
		t.Fatalf("source = %s, want %s", got, ManagerSourceLegacy)
	}
	if !legacy.ManagedBy("human-1") || legacy.ManagedBy("someone-else") {
		t.Fatalf("ManagedBy disagrees with the effective set")
	}
}

func TestActorValidateNamesTheMissingAccountableManager(t *testing.T) {
	a := ActorRef{ActorID: "agent-1", TenantID: "t1", Kind: KindAgent}
	if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "accountable manager") {
		t.Fatalf("an agent with no manager was accepted: %v", err)
	}
	// A declared set with only approvers is refused through the same named rule.
	a.Managers = ManagerSet{{ActorID: "risk-1", Kind: KindHuman, Role: ManagerApprover}}
	if err := a.Validate(); !errors.Is(err, ErrManagerNoAccountable) {
		t.Fatalf("an agent with no accountable manager = %v, want %v", err, ErrManagerNoAccountable)
	}
}

func TestManagerGateResolvesInheritFromTheSetSize(t *testing.T) {
	single := SingleManagerSet("human-1", KindHuman)
	two := ManagerSet{
		{ActorID: "lead-1", Kind: KindHuman, Role: ManagerAccountable, Primary: true},
		{ActorID: "risk-1", Kind: KindHuman, Role: ManagerApprover},
	}
	inherit := ApprovalPolicy{}
	if got := inherit.EffectiveManagerGate(len(single)); got != ManagerGateOff {
		t.Fatalf("a one-manager agent resolved to gate %s, want %s: an agent with one manager must behave exactly as it did",
			got, ManagerGateOff)
	}
	if got := inherit.EffectiveManagerGate(len(two)); got != ManagerGateAny {
		t.Fatalf("a two-manager agent resolved to gate %s, want %s", got, ManagerGateAny)
	}
	if got := inherit.ManagerRequirement(len(two)); got != 1 {
		t.Fatalf("ManagerRequirement(two) = %d, want 1", got)
	}
	all := ApprovalPolicy{ManagerGate: ManagerGateAll}
	if got := all.ManagerRequirement(len(two)); got != 2 {
		t.Fatalf("ManagerRequirement(all, two) = %d, want 2", got)
	}
	// An explicit gate over an actor with no set is unsatisfiable rather than
	// silently switched off.
	if got := all.ManagerRequirement(0); got < 1 {
		t.Fatalf("ManagerRequirement(all, none) = %d; an explicit gate with no set must be unsatisfiable", got)
	}
	quorum := ApprovalPolicy{ManagerGate: ManagerGateQuorum, ManagerQuorum: 2}
	if got := quorum.ManagerRequirement(len(two)); got != 2 {
		t.Fatalf("ManagerRequirement(quorum 2) = %d, want 2", got)
	}
}

func TestPolicyValidationRefusesAQuorumNothingReads(t *testing.T) {
	bad := []ApprovalPolicy{
		{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateQuorum},
		{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateQuorum, ManagerQuorum: -1},
		{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateAny, ManagerQuorum: 3},
		{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGate(42)},
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Fatalf("policy %s was accepted", p.Describe())
		}
	}
	good := []ApprovalPolicy{
		{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateQuorum, ManagerQuorum: 1},
		{Required: 2, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateAll},
		{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateOff},
	}
	for _, p := range good {
		if err := p.Validate(); err != nil {
			t.Fatalf("policy %s was refused: %v", p.Describe(), err)
		}
	}
}

// TestAPolicyWithNoManagerGateEncodesAsItDidBefore is the sealed-record
// guarantee: a deployment that declares no gate must keep the SAME policy
// identifier, because every approval already raised names it.
func TestAPolicyWithNoManagerGateEncodesAsItDidBefore(t *testing.T) {
	p := ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman}, MinHumans: 1}
	raw, err := json.Marshal(p.CanonicalEncoding())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{"ManagerGate", "ManagerQuorum"} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("an ungated policy encodes %s, which would change the identifier of every policy already sealed: %s", field, raw)
		}
	}
	if strings.Contains(p.Describe(), "manager_gate") {
		t.Fatalf("an ungated policy describes a manager gate: %s", p.Describe())
	}
	gated := ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateAll}
	if !strings.Contains(gated.Describe(), "manager_gate=all") {
		t.Fatalf("a gated policy does not describe its gate: %s", gated.Describe())
	}
	raw, err = json.Marshal(gated.CanonicalEncoding())
	if err != nil {
		t.Fatalf("marshal gated: %v", err)
	}
	if !strings.Contains(string(raw), "ManagerGate") {
		t.Fatalf("a gated policy does not encode its gate, so two different rules would share one identifier: %s", raw)
	}
}

func TestManagerSetEqualComparesEveryField(t *testing.T) {
	a := SingleManagerSet("human-1", KindHuman)
	if !a.Equal(a.Copy()) {
		t.Fatal("a copied set is not equal to its source")
	}
	b := SingleManagerSet("human-1", KindAgent)
	if a.Equal(b) {
		t.Fatal("two sets that disagree about the manager's KIND compare equal")
	}
	c := ManagerSet{{ActorID: "human-1", Kind: KindHuman, Role: ManagerApprover, Primary: true}}
	if a.Equal(c) {
		t.Fatal("two sets that disagree about the ROLE compare equal")
	}
	if a.Equal(nil) {
		t.Fatal("a one-entry set compares equal to no set")
	}
}
