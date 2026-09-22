package types

// Permits reports whether an approver of this class may contribute under the
// policy. The zero-value policy is read as the default, so a deployment that
// configured nothing permits exactly a human.
func (p ApprovalPolicy) Permits(c ApproverClass) bool {
	for _, permitted := range p.Effective().Classes {
		if permitted == c {
			return true
		}
	}
	return false
}

// HumanFloor returns the least number of human approvals the policy must
// actually see for a decision under this verb.
//
// For delete, send, pay, deploy and approve the floor is at least one,
// regardless of what the policy says (ADR-008). The floor only ever rises: a
// policy may demand more humans, never fewer, and a policy that names no human
// class at all can therefore never satisfy an irreversible verb -- which is the
// refusal ADR-009 requires, not an oversight.
//
// An unspecified verb answers as irreversible, because a caller that skipped
// verb validation gets the strict answer rather than the cheap one.
func (p ApprovalPolicy) HumanFloor(action Action) int {
	floor := p.Effective().MinHumans
	if action.Irreversible() && floor < 1 {
		floor = 1
	}
	return floor
}

// AllowsHumanFreePath reports whether a requirement under this policy COULD be
// satisfied with no human approval at all for this verb.
//
// It is the question ADR-009 invariant 1 asks before a decision is taken: a
// policy whose human floor is zero for the verb and which either requires
// nothing or permits a non-human class can be met by agents alone. That is
// expressible on purpose -- autonomy is a legitimate configuration -- but it is
// only usable when the work's sponsor has opted in, which is why the gateway
// consults this and then the work record.
//
// The verb matters. For delete, send, pay, deploy and approve HumanFloor is at
// least one (ADR-008), so this reports false and no opt-in can remove the
// human. An unspecified verb answers as irreversible through the same floor, so
// a caller that skipped verb validation gets the strict answer.
func (p ApprovalPolicy) AllowsHumanFreePath(action Action) bool {
	eff := p.Effective()
	if eff.HumanFloor(action) > 0 {
		return false
	}
	// A requirement of zero is satisfied by no approvals at all: the human-free
	// case in its strongest form.
	if eff.Required == 0 {
		return true
	}
	for _, c := range eff.Classes {
		if c != ApproverHuman {
			return true
		}
	}
	return false
}

// RequiresIndependence reports whether the policy names the given role.
func (p ApprovalPolicy) RequiresIndependence(role string) bool {
	for _, r := range p.Effective().IndependentOf {
		if r == role {
			return true
		}
	}
	return false
}
