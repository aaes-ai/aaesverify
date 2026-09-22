package types

import (
	"fmt"
	"strings"
)

// This file is ADR-009: an approval requirement is a quorum over approver
// classes with a human floor.
//
// Before it, a requirement was satisfied by exactly one granted approval and
// only a registered human could be an approver. That made dual control a label
// rather than a control, and it made every combination a customer might want --
// an agent that triages and a human who signs, two humans from different
// functions, a quorum that includes a service identity -- inexpressible.
//
// The vocabulary here separates two questions that were previously fused:
// PARTICIPATION (which class of actor may contribute an approval, and how many
// approvals are needed) and AUTHORITY (whether an approval decides, or is
// recorded evidence that never does). A policy that names a class and a count
// is what makes "an agent may approve here" an explicit, reviewable declaration
// rather than an accident.

// The independence roles a policy may name. They are a closed vocabulary: an
// unrecognised role reading as "no requirement" would silently weaken the
// policy, so Validate refuses it.
const (
	// IndependenceRequester means the approver must not be the actor that made
	// the request, must not be an agent under the requester's principal, and --
	// when the approver is an agent -- must not be registered with the same model
	// family as the requester.
	IndependenceRequester = "requester"
	// IndependenceSponsor means the approver must not be the accountable human
	// of the work the action is committed against, nor an agent under that
	// human's principal.
	IndependenceSponsor = "sponsor"
)

// IndependenceRoles lists every independence role in declaration order.
func IndependenceRoles() []string { return []string{IndependenceRequester, IndependenceSponsor} }

// ApprovalPolicy is the requirement an approval must meet: how many decisive
// approvals, from which classes, with what human floor, under what
// independence rule, at what authority.
//
// The ZERO VALUE means today's behaviour exactly: one granted approval from a
// registered human satisfies the requirement. It is not an empty requirement --
// it is the documented default -- which is why IsZero and Effective exist and
// why Validate accepts it while refusing an explicitly empty class list.
type ApprovalPolicy struct {
	// Required is how many decisive approvals the quorum needs in total.
	Required int
	// Classes names the approver classes that may contribute. It must not be
	// empty: a policy that names no class can be satisfied by nothing.
	Classes []ApproverClass
	// MinHumans is the human floor: at least this many of the decisive approvals
	// must come from human approvers. It may not exceed Required. For the
	// irreversible verbs ADR-008 keeps a floor of at least one regardless of
	// this field (see HumanFloor).
	MinHumans int
	// DistinctPrincipals refuses to let one principal fill two slots. The
	// principal of an agent is its accountable human; the principal of a human
	// is the human.
	DistinctPrincipals bool
	// IndependentOf names the actors an approver must be independent of. The
	// vocabulary is closed: "requester" and "sponsor".
	IndependentOf []string
	// Authority is what an approval under this policy decides. Recommended is
	// recorded evidence that never satisfies the requirement.
	Authority ApprovalAuthority
	// ManagerGate says how the manager SET of the actor an approval is raised for
	// participates in the requirement. The zero value INHERITS: the set is
	// authoritative only when it holds more than one entry, so every actor with
	// one manager -- every actor registered before the set existed -- keeps
	// exactly the behaviour it had.
	//
	// It is omitempty so a policy that declares no gate encodes, and therefore
	// hashes, exactly as it did before this field existed: an approval raised
	// under the old rules must keep resolving to the same policy identifier.
	ManagerGate ManagerGate `json:",omitempty"`
	// ManagerQuorum is how many deciding managers the requirement needs when
	// ManagerGate is ManagerGateQuorum. It is refused on any other gate: a count
	// that nothing reads is a configuration that looks like a control.
	ManagerQuorum int `json:",omitempty"`
}

// DefaultApprovalPolicy is the policy a deployment that configures none gets,
// and the reading of the zero value: one granted approval from a registered
// human. It is today's behaviour written down, and every deployment that
// predates ADR-009 keeps exactly this.
func DefaultApprovalPolicy() ApprovalPolicy {
	return ApprovalPolicy{
		Required:  1,
		Classes:   []ApproverClass{ApproverHuman},
		MinHumans: 1,
	}
}

// IsZero reports whether the policy is the zero value. The zero value is not an
// empty requirement: it is shorthand for DefaultApprovalPolicy.
func (p ApprovalPolicy) IsZero() bool {
	return p.Required == 0 && len(p.Classes) == 0 && p.MinHumans == 0 &&
		!p.DistinctPrincipals && len(p.IndependentOf) == 0 && p.Authority == AuthorityGranted &&
		p.ManagerGate == ManagerGateInherit && p.ManagerQuorum == 0
}

// Effective returns the policy as it is to be applied: the zero value becomes
// the documented default, and every other value is returned as declared. The
// slices are copied so a caller cannot edit a policy through the value it was
// handed.
func (p ApprovalPolicy) Effective() ApprovalPolicy {
	if p.IsZero() {
		return DefaultApprovalPolicy()
	}
	out := p
	out.Classes = append([]ApproverClass(nil), p.Classes...)
	out.IndependentOf = append([]string(nil), p.IndependentOf...)
	return out
}

// Validate refuses a policy AAES cannot apply or could apply in a way its
// author did not intend. The rules:
//
//   - a negative count is refused: a requirement cannot be negative, and a
//     negative count compared against a running total would silently pass;
//   - MinHumans above Required is refused: a human floor higher than the total
//     quorum can never be met, so the policy would refuse every action while
//     reading as a requirement;
//   - an empty class list is refused on any policy that declares anything at
//     all, because a requirement no class can fill is not a requirement. The
//     zero value is the one exception: it is not an empty policy, it is the
//     documented default (see IsZero);
//   - an unknown class, an unknown authority and an unknown independence role
//     are refused: a value AAES cannot name reading as "no requirement" is how
//     a policy is weakened by a typo.
func (p ApprovalPolicy) Validate() error {
	if p.IsZero() {
		// The zero value is the documented default, and DefaultApprovalPolicy is
		// valid by construction.
		return nil
	}
	if p.Required < 0 {
		return fmt.Errorf("types: approval policy requires a non-negative count, got %d", p.Required)
	}
	if p.MinHumans < 0 {
		return fmt.Errorf("types: approval policy requires a non-negative minimum number of authorized persons, got %d", p.MinHumans)
	}
	if p.MinHumans > p.Required {
		return fmt.Errorf("types: approval policy has a minimum number of authorized persons of %d above its total requirement of %d; no quorum could ever meet it",
			p.MinHumans, p.Required)
	}
	if err := p.validateApproverClasses(); err != nil {
		return err
	}
	if err := p.Authority.Validate(); err != nil {
		return err
	}
	if err := p.validateManagerGate(); err != nil {
		return err
	}
	return p.validateIndependenceRoles()
}

// validateApproverClasses refuses an empty class list and any class AAES cannot
// name or names twice.
func (p ApprovalPolicy) validateApproverClasses() error {
	if len(p.Classes) == 0 {
		return fmt.Errorf("types: approval policy names no approver class, and a requirement no class can fill is not a requirement (want one of %s)",
			approverClassVocabulary())
	}
	seenClass := make(map[ApproverClass]bool, len(p.Classes))
	for _, c := range p.Classes {
		if err := c.Validate(); err != nil {
			return err
		}
		if seenClass[c] {
			return fmt.Errorf("types: approval policy names the approver class %q twice; a duplicated class tells a reader the list was reviewed when it was not", c)
		}
		seenClass[c] = true
	}
	return nil
}

// validateManagerGate refuses an unknown gate and a quorum count the declared
// gate does not read.
func (p ApprovalPolicy) validateManagerGate() error {
	if err := p.ManagerGate.Validate(); err != nil {
		return err
	}
	// A quorum count on a gate that does not read it is refused rather than
	// ignored: a configuration that looks like a control and is not one is
	// worse than no configuration, because a reviewer reads it as a bound.
	if p.ManagerGate == ManagerGateQuorum {
		if p.ManagerQuorum <= 0 {
			return fmt.Errorf("types: approval policy names the %q manager gate with a quorum of %d; a quorum gate with no positive count can never be met",
				ManagerGateQuorum, p.ManagerQuorum)
		}
	} else if p.ManagerQuorum != 0 {
		return fmt.Errorf("types: approval policy names a manager quorum of %d under the %q gate, which does not read it",
			p.ManagerQuorum, p.ManagerGate)
	}
	return nil
}

// validateIndependenceRoles refuses a role outside the closed vocabulary and a
// role named twice.
func (p ApprovalPolicy) validateIndependenceRoles() error {
	seenRole := make(map[string]bool, len(p.IndependentOf))
	for _, role := range p.IndependentOf {
		if !isIndependenceRole(role) {
			return fmt.Errorf("types: approval policy names an unknown independence role %q (want one of %s); an unrecognised role must not read as no requirement",
				role, strings.Join(IndependenceRoles(), ", "))
		}
		if seenRole[role] {
			return fmt.Errorf("types: approval policy names the independence role %q twice", role)
		}
		seenRole[role] = true
	}
	return nil
}

// isIndependenceRole reports whether role is in the closed vocabulary.
func isIndependenceRole(role string) bool {
	for _, r := range IndependenceRoles() {
		if r == role {
			return true
		}
	}
	return false
}
