package types

import (
	"fmt"
	"strings"
)

// ManagerGate says how an actor's manager set constrains who may approve.
//
// The vocabulary exists because the set answers a question the approver-class
// quorum cannot: WHICH managers, not merely which class. A deployment that
// names no gate keeps the class rule alone; one that names a gate adds the
// membership rule, and the two are counted together.
type ManagerGate int

const (
	// ManagerGateInherit (the zero value) means the set is authoritative exactly
	// when it holds more than one entry. One manager is today's behaviour
	// unchanged; two or more managers mean any deciding manager may approve,
	// because a set that several people answer for must not be approvable by a
	// stranger.
	ManagerGateInherit ManagerGate = iota
	// ManagerGateAny means any deciding manager may fill the manager half of the
	// requirement.
	ManagerGateAny
	// ManagerGateAll means EVERY deciding manager must approve.
	ManagerGateAll
	// ManagerGateQuorum means ManagerQuorum deciding managers must approve.
	ManagerGateQuorum
	// ManagerGateOff means the set never constrains who may approve. It is an
	// explicit declaration, distinct from Inherit, because an operator who wants
	// class-only approval over a multi-manager agent should have to say so.
	ManagerGateOff
)

// ManagerGates lists every gate in declaration order.
func ManagerGates() []ManagerGate {
	return []ManagerGate{ManagerGateInherit, ManagerGateAny, ManagerGateAll, ManagerGateQuorum, ManagerGateOff}
}

// managerGateVocabulary renders the closed vocabulary for an error message.
func managerGateVocabulary() string {
	names := make([]string, 0, len(ManagerGates()))
	for _, g := range ManagerGates() {
		names = append(names, g.String())
	}
	return strings.Join(names, ", ")
}

// EffectiveManagerGate returns the gate as it applies to a subject whose manager
// set holds setSize entries.
//
// Inherit is resolved here rather than at each caller, so the gateway, the
// console and the store cannot disagree about whether a one-manager agent is
// gated. An explicit gate is returned as declared, including when the set is
// empty: an operator who declared a manager requirement and left the agent with
// no managers has a requirement nothing can satisfy, and that must refuse
// rather than quietly switch itself off.
func (p ApprovalPolicy) EffectiveManagerGate(setSize int) ManagerGate {
	switch p.Effective().ManagerGate {
	case ManagerGateInherit:
		if setSize > 1 {
			return ManagerGateAny
		}
		return ManagerGateOff
	default:
		return p.Effective().ManagerGate
	}
}

// ManagerRequirement returns the number of DECIDING managers the gate needs for
// a set of setSize entries. All needs every deciding entry, Quorum needs its
// declared count, and the other gates need at most one. An explicit gate over
// an empty set returns a requirement ABOVE zero, so it can never be satisfied
// by nobody.
func (p ApprovalPolicy) ManagerRequirement(setSize int) int {
	switch p.EffectiveManagerGate(setSize) {
	case ManagerGateAll:
		if setSize == 0 {
			return 1
		}
		return setSize
	case ManagerGateQuorum:
		return p.Effective().ManagerQuorum
	case ManagerGateAny:
		return 1
	}
	return 0
}

// String renders the gate as the lowercase token configuration and the console
// print. An off-vocabulary value renders as "unknown(N)".
func (g ManagerGate) String() string {
	switch g {
	case ManagerGateInherit:
		return "inherit"
	case ManagerGateAny:
		return "any"
	case ManagerGateAll:
		return "all"
	case ManagerGateQuorum:
		return "quorum"
	case ManagerGateOff:
		return "off"
	}
	return fmt.Sprintf("unknown(%d)", int(g))
}

// Validate reports whether the gate is one AAES can name.
func (g ManagerGate) Validate() error {
	switch g {
	case ManagerGateInherit, ManagerGateAny, ManagerGateAll, ManagerGateQuorum, ManagerGateOff:
		return nil
	}
	return fmt.Errorf("types: unknown manager gate %d (want one of %s)", int(g), managerGateVocabulary())
}
