package types

import "testing"

// TestServiceOnlyPolicyKeepsAPersonOnIrreversibleVerbs: the service class exists
// in the vocabulary so a policy can name it, but for delete, send, pay, deploy,
// approve, share and transfer the human floor is one regardless of what the
// policy says -- a service-only policy can never be satisfied for those verbs,
// and an unspecified verb answers as irreversible. For a reversible verb the
// same policy reads as human-free: the floor belongs to the verb, and that
// contrast is what proves the floor -- not the class vocabulary -- carries the
// invariant.
func TestServiceOnlyPolicyKeepsAPersonOnIrreversibleVerbs(t *testing.T) {
	policy := ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverService}}
	for _, action := range []Action{
		ActionDelete, ActionSend, ActionPay, ActionDeploy, ActionApprove,
		ActionShare, ActionTransfer, ActionUnspecified,
	} {
		if got := policy.HumanFloor(action); got != 1 {
			t.Fatalf("HumanFloor(%v) = %d, want 1", action, got)
		}
		if policy.AllowsHumanFreePath(action) {
			t.Fatalf("AllowsHumanFreePath(%v) = true for a service-only policy on an irreversible verb", action)
		}
	}
	if !policy.AllowsHumanFreePath(ActionWrite) {
		t.Fatal("a service-only policy on a reversible verb does not read as human-free; the contrast is what proves the floor carries the invariant")
	}
}
