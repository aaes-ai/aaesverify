package types

import (
	"fmt"
	"sort"
	"strings"
)

// Describe renders the policy canonically for a refusal message and for the
// sealed reason of the decision it applied to. The rendering is stable: two
// policies that differ in content render differently, and the order the classes
// and roles were declared in does not change the rendering.
func (p ApprovalPolicy) Describe() string {
	eff := p.Effective()
	classes := make([]string, 0, len(eff.Classes))
	for _, c := range eff.Classes {
		classes = append(classes, strings.ReplaceAll(c.String(), "human", "person"))
	}
	classes = sortedStrings(classes)
	roles := append([]string(nil), eff.IndependentOf...)
	roles = sortedStrings(roles)
	out := fmt.Sprintf("required=%d classes=[%s] min_person_approvals=%d distinct_principals=%t independent_of=[%s] authority=%s",
		eff.Required, strings.Join(classes, ","), eff.MinHumans, eff.DistinctPrincipals,
		strings.Join(roles, ","), eff.Authority)
	// The manager gate is appended only when it was declared, so the rendering of
	// every policy that names none is byte-for-byte what it always was.
	if eff.ManagerGate != ManagerGateInherit || eff.ManagerQuorum != 0 {
		out += fmt.Sprintf(" manager_gate=%s", eff.ManagerGate)
		if eff.ManagerGate == ManagerGateQuorum {
			out += fmt.Sprintf(" manager_quorum=%d", eff.ManagerQuorum)
		}
	}
	return out
}

// CanonicalEncoding returns the policy in the canonical form the policy's
// identifier is derived from: the effective policy with classes and
// independence roles sorted, so reordering a configuration file does not mint a
// new identifier for the same rule.
func (p ApprovalPolicy) CanonicalEncoding() ApprovalPolicy {
	eff := p.Effective()
	classes := make([]string, 0, len(eff.Classes))
	for _, c := range eff.Classes {
		classes = append(classes, c.String())
	}
	sorted := sortedStrings(classes)
	out := ApprovalPolicy{
		Required:           eff.Required,
		Classes:            make([]ApproverClass, 0, len(sorted)),
		MinHumans:          eff.MinHumans,
		DistinctPrincipals: eff.DistinctPrincipals,
		IndependentOf:      sortedStrings(append([]string(nil), eff.IndependentOf...)),
		Authority:          eff.Authority,
		ManagerGate:        eff.ManagerGate,
		ManagerQuorum:      eff.ManagerQuorum,
	}
	for _, s := range sorted {
		c, _ := ParseApproverClass(s)
		out.Classes = append(out.Classes, c)
	}
	return out
}

// sortedStrings returns a sorted copy with duplicates removed.
func sortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	deduped := out[:1]
	for _, s := range out[1:] {
		if s != deduped[len(deduped)-1] {
			deduped = append(deduped, s)
		}
	}
	return deduped
}
