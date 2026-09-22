package types

import (
	"strings"
	"testing"
	"time"
)

// policyTestTime is a fixed instant, not a clock reading.
var policyTestTime = time.Date(2026, time.September, 12, 9, 0, 0, 0, time.UTC)

// ADR-009: an approval requirement is a quorum over approver classes with a
// human floor. These tests hold the vocabulary's own rules.

// TestZeroApprovalPolicyIsTodaysBehaviour is the compatibility rule the ADR
// states first: a deployment that configures no approval policy must keep
// exactly the behaviour it had, which is one granted approval from a registered
// human.
func TestZeroApprovalPolicyIsTodaysBehaviour(t *testing.T) {
	var zero ApprovalPolicy
	if !zero.IsZero() {
		t.Fatal("the zero policy does not report itself as zero")
	}
	eff := zero.Effective()
	if eff.Required != 1 || eff.MinHumans != 1 || len(eff.Classes) != 1 || eff.Classes[0] != ApproverHuman {
		t.Fatalf("the zero policy reads as %s, want one required approval from one person", eff.Describe())
	}
	if eff.Authority != AuthorityGranted {
		t.Fatalf("the zero policy's authority is %s, want granted", eff.Authority)
	}
	if !zero.Permits(ApproverHuman) {
		t.Fatal("the zero policy does not permit a authorized approver; today's behaviour is exactly a authorized approver")
	}
	if zero.Permits(ApproverAgent) || zero.Permits(ApproverService) {
		t.Fatal("the zero policy permits an agent or service approver; today's behaviour refuses both")
	}
	if zero.HumanFloor(ActionRead) != 1 {
		t.Fatalf("the zero policy's minimum number of authorized persons for read is %d, want 1", zero.HumanFloor(ActionRead))
	}
	if err := zero.Validate(); err != nil {
		t.Fatalf("the zero policy fails validation: %v", err)
	}
}

// TestDefaultApprovalPolicyIsValidAndExplicit pins the documented default. The
// zero value and DefaultApprovalPolicy must mean the same thing, or a deployment
// that configures nothing and one that writes the default down would enforce
// different rules.
func TestDefaultApprovalPolicyIsValidAndExplicit(t *testing.T) {
	def := DefaultApprovalPolicy()
	if def.IsZero() {
		t.Fatal("DefaultApprovalPolicy is the zero value; the explicit default and the unconfigured default must both be valid and comparable")
	}
	if err := def.Validate(); err != nil {
		t.Fatalf("DefaultApprovalPolicy fails validation: %v", err)
	}
	if def.Describe() != (ApprovalPolicy{}).Describe() {
		t.Fatalf("the explicit default describes as %q and the zero policy as %q; they are the same rule",
			def.Describe(), (ApprovalPolicy{}).Describe())
	}
}

func TestApprovalPolicyValidate(t *testing.T) {
	human := []ApproverClass{ApproverHuman}
	for _, tc := range []struct {
		name   string
		policy ApprovalPolicy
		want   string
	}{
		{"a negative total", ApprovalPolicy{Required: -1, Classes: human, MinHumans: -1}, "non-negative count"},
		{"a negative minimum number of authorized persons", ApprovalPolicy{Required: 1, Classes: human, MinHumans: -1}, "non-negative minimum number of authorized persons"},
		{"a minimum number of authorized persons above the total", ApprovalPolicy{Required: 1, Classes: human, MinHumans: 2}, "above its total requirement"},
		{"an empty class list", ApprovalPolicy{Required: 1}, "names no approver class"},
		{"an unknown class", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman, ApproverClass(9)}}, "unknown approver class"},
		{"a duplicated class", ApprovalPolicy{Required: 2, Classes: []ApproverClass{ApproverHuman, ApproverHuman}}, "twice"},
		{"an unknown independence role", ApprovalPolicy{Required: 1, Classes: human, IndependentOf: []string{"whoever"}}, "unknown independence role"},
		{"a duplicated independence role", ApprovalPolicy{Required: 1, Classes: human, IndependentOf: []string{"requester", "requester"}}, "twice"},
		{"an unknown authority", ApprovalPolicy{Required: 1, Classes: human, Authority: ApprovalAuthority(7)}, "unknown approval authority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal = %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}

	valid := []ApprovalPolicy{
		{},
		DefaultApprovalPolicy(),
		{Required: 2, Classes: []ApproverClass{ApproverHuman}, MinHumans: 1, DistinctPrincipals: true, IndependentOf: []string{IndependenceRequester, IndependenceSponsor}},
		{Required: 2, Classes: []ApproverClass{ApproverHuman, ApproverAgent}, MinHumans: 1},
		{Required: 1, Classes: []ApproverClass{ApproverAgent}},
		{Required: 0, Classes: []ApproverClass{ApproverAgent}, Authority: AuthorityRecommended},
	}
	for _, p := range valid {
		if err := p.Validate(); err != nil {
			t.Fatalf("%q was refused: %v", p.Describe(), err)
		}
	}
}

// TestHumanFloorSurvivesAPolicyThatRemovesIt is ADR-008's rule at the type
// level: for delete, send, pay, deploy and approve the floor is at least one
// regardless of what the policy says, and a policy may only raise it.
func TestHumanFloorSurvivesAPolicyThatRemovesIt(t *testing.T) {
	agentOnly := ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}
	for _, action := range []Action{ActionDelete, ActionSend, ActionPay, ActionDeploy, ActionApprove, ActionShare, ActionTransfer} {
		if got := agentOnly.HumanFloor(action); got != 1 {
			t.Fatalf("the minimum number of authorized persons for %s under an agent-only policy is %d, want 1", action, got)
		}
	}
	for _, action := range []Action{ActionRead, ActionWrite, ActionCreate, ActionUpdate, ActionExecute, ActionInvoke} {
		if got := agentOnly.HumanFloor(action); got != 0 {
			t.Fatalf("the minimum number of authorized persons for the reversible verb %s is %d, want the configured 0", action, got)
		}
	}
	// An unspecified verb is strict: a caller that skipped verb validation gets
	// the irreversible answer, not the cheap one.
	if got := agentOnly.HumanFloor(ActionUnspecified); got != 1 {
		t.Fatalf("the minimum number of authorized persons for an unspecified verb is %d, want 1", got)
	}
	// The floor only rises.
	two := ApprovalPolicy{Required: 2, Classes: []ApproverClass{ApproverHuman}, MinHumans: 2}
	if got := two.HumanFloor(ActionRead); got != 2 {
		t.Fatalf("a policy demanding two authorized persons reports a floor of %d", got)
	}
}

// TestApprovalPolicyDescribeIsStableAndOrderInsensitive holds the rendering a
// refusal and a sealed reason print: same rule, same sentence, whatever order
// the classes and roles were declared in.
func TestApprovalPolicyDescribeIsStableAndOrderInsensitive(t *testing.T) {
	a := ApprovalPolicy{Required: 2, Classes: []ApproverClass{ApproverHuman, ApproverAgent}, MinHumans: 1,
		DistinctPrincipals: true, IndependentOf: []string{IndependenceRequester, IndependenceSponsor}}
	b := ApprovalPolicy{Required: 2, Classes: []ApproverClass{ApproverAgent, ApproverHuman}, MinHumans: 1,
		DistinctPrincipals: true, IndependentOf: []string{IndependenceSponsor, IndependenceRequester}}
	if a.Describe() != b.Describe() {
		t.Fatalf("the same rule renders two ways: %s / %s", a.Describe(), b.Describe())
	}
	want := "required=2 classes=[agent,person] min_person_approvals=1 distinct_principals=true independent_of=[requester,sponsor] authority=granted"
	if got := a.Describe(); got != want {
		t.Fatalf("Describe() = %q, want %q", got, want)
	}
	if !strings.Contains((ApprovalPolicy{}).Describe(), "authority=granted") {
		t.Fatal("the zero policy's rendering does not name its authority")
	}
}

func TestParseApproverClassAndAuthority(t *testing.T) {
	for _, s := range []string{"human", "Human", " agent ", "service"} {
		if _, ok := ParseApproverClass(s); !ok {
			t.Fatalf("ParseApproverClass(%q) failed", s)
		}
	}
	if _, ok := ParseApproverClass("robot"); ok {
		t.Fatal("ParseApproverClass accepted an unknown class, and the zero answer must not read as permission")
	}
	for _, s := range []string{"granted", "Granted", " recommended "} {
		if _, ok := ParseApprovalAuthority(s); !ok {
			t.Fatalf("ParseApprovalAuthority(%q) failed", s)
		}
	}
	if _, ok := ParseApprovalAuthority("maybe"); ok {
		t.Fatal("ParseApprovalAuthority accepted an unknown authority")
	}
	if ApproverClass(9).String() != "unknown(9)" {
		t.Fatalf("an off-vocabulary class renders as %q, want unknown(9)", ApproverClass(9).String())
	}
	if ApprovalAuthority(9).String() != "unknown(9)" {
		t.Fatalf("an off-vocabulary authority renders as %q, want unknown(9)", ApprovalAuthority(9).String())
	}
	if !AuthorityGranted.Decisive() || AuthorityRecommended.Decisive() {
		t.Fatal("Decisive does not separate granted from recommended")
	}
}

// TestApprovalValidateHoldsTheQuorumFields checks that a record claiming an
// agent approver without a model identity, or an unknown class, is refused by
// the type's own validation rather than accepted somewhere downstream.
func TestApprovalValidateHoldsTheQuorumFields(t *testing.T) {
	base := func() Approval {
		return Approval{
			ApprovalID: "apr_1", TenantID: "t1", WorkID: "w1", IntentID: "i1",
			Approver: "human-1", State: ApprovalGranted, ExpiresAt: policyTestTime.Add(time.Hour),
			DecidedAt: policyTestTime,
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("an approval by a person with zero-value quorum fields was refused: %v", err)
	}
	agent := base()
	agent.ApproverKind = ApproverAgent
	if err := agent.Validate(); err == nil || !strings.Contains(err.Error(), "no registered model identity") {
		t.Fatalf("an agent approval with no model identity was accepted: %v", err)
	}
	agent.ApproverModelProvider, agent.ApproverModelFamily, agent.ApproverModel = "p", "f", "m"
	if err := agent.Validate(); err != nil {
		t.Fatalf("an attributed agent approval was refused: %v", err)
	}
	bad := base()
	bad.ApproverKind = ApproverClass(9)
	if err := bad.Validate(); err == nil {
		t.Fatal("an approval with an unknown approver class was accepted")
	}
	badVerb := base()
	badVerb.Action = "frobnicate"
	if err := badVerb.Validate(); err == nil {
		t.Fatal("an approval recording an unknown verb was accepted")
	}
}
