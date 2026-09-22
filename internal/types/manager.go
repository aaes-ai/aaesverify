package types

import (
	"errors"
	"fmt"
	"strings"
)

// The named refusals of the manager set. Each one is a distinct condition an
// operator has to be able to act on, so each is a sentinel rather than prose
// inside a formatted string: a console or a test can ask WHICH refusal it got
// without matching on the wording of the message.
var (
	// ErrManagerNoAccountable means the set names nobody who answers for the
	// actor.
	ErrManagerNoAccountable = errors.New("manager set has no accountable manager")
	// ErrManagerSelf means the actor is one of its own managers.
	ErrManagerSelf = errors.New("an actor cannot manage itself")
	// ErrManagerDuplicate means the same manager is named twice.
	ErrManagerDuplicate = errors.New("manager set names a duplicate entry")
	// ErrManagerRole means a role outside the vocabulary, or a primary entry
	// that is not accountable.
	ErrManagerRole = errors.New("manager role is not one AAES can apply")
	// ErrManagerKind means a kind outside the vocabulary.
	ErrManagerKind = errors.New("manager kind is not one AAES can name")
	// ErrManagerMultiplePrimary means more than one entry claims the routing
	// head.
	ErrManagerMultiplePrimary = errors.New("manager set names more than one primary manager")
	// ErrManagerSource means a manager source outside the vocabulary.
	ErrManagerSource = errors.New("manager source is not one AAES can name")
)

// This file is the manager SET: several humans, several other agents, or a mix
// answer for one agent.
//
// Before it, an agent named exactly one accountable human in a single Sponsor
// field. That is the wrong shape for a real organisation: an agent deployed in
// a regulated function answers to a team lead AND to a risk officer, and an
// agent supervising other agents is an accountable manager in its own right.
// The set is ordered because the order is the routing order, and every entry
// carries the actor's kind (which the reader cannot infer from an id), the role
// the entry plays, and whether it is the primary manager.
//
// Nothing here reinterprets the single field. Sponsor is still readable, a
// record that carries only Sponsor still reads as a one-entry set, and the
// derived set is LABELLED as derived (ManagerSourceSingle) so a reader of a
// sealed record can tell an operator's explicit set from a value AAES migrated
// on the operator's behalf.

// ManagerSet is the ordered manager set of one actor. The order is meaningful:
// it is the order in which AAES asks, and the primary accountable manager is
// asked first.
type ManagerSet []ManagerEntry

// Copy returns a deep copy that shares no backing array with the receiver.
func (s ManagerSet) Copy() ManagerSet {
	if s == nil {
		return nil
	}
	out := make(ManagerSet, len(s))
	copy(out, s)
	return out
}

// Validate checks the shape of a set: at least one accountable manager, no
// duplicate entry, at most one primary, and every entry individually valid.
//
// It does NOT check the manager CHAIN -- whether an agent manager is registered
// with a model identity, whether the chain cycles, or whether it terminates at
// a human. Those are questions about the rest of the directory, and they are
// answered by the directory at registration time (see directory.Registry).
func (s ManagerSet) Validate(subject string) error {
	if len(s) == 0 {
		return fmt.Errorf("%w: actor %q has no manager entry", ErrManagerNoAccountable, subject)
	}
	seen := make(map[string]bool, len(s))
	accountable := 0
	primaries := 0
	for i, e := range s {
		if err := e.Validate(subject); err != nil {
			return fmt.Errorf("%w (entry %d)", err, i)
		}
		id := strings.TrimSpace(e.ActorID)
		if seen[id] {
			return fmt.Errorf("%w: actor %q names manager %q twice; a duplicate entry tells a reader the set was reviewed when it was not", ErrManagerDuplicate, subject, id)
		}
		seen[id] = true
		if e.Role == ManagerAccountable {
			accountable++
		}
		if e.Primary {
			primaries++
		}
	}
	if accountable == 0 {
		return fmt.Errorf("%w: actor %q names no accountable manager; approvers and informed managers cannot answer for the agent", ErrManagerNoAccountable, subject)
	}
	if primaries > 1 {
		return fmt.Errorf("%w: actor %q names %d primary managers; at most one entry may head the routing order", ErrManagerMultiplePrimary, subject, primaries)
	}
	return nil
}

// Deciding returns the entries that may fill a quorum slot: every entry except
// an informed one. The order is preserved.
func (s ManagerSet) Deciding() ManagerSet {
	out := make(ManagerSet, 0, len(s))
	for _, e := range s {
		if e.Deciding() {
			out = append(out, e)
		}
	}
	return out
}

// Accountable returns the accountable entries, in order.
func (s ManagerSet) Accountable() ManagerSet {
	out := make(ManagerSet, 0, len(s))
	for _, e := range s {
		if e.Role == ManagerAccountable {
			out = append(out, e)
		}
	}
	return out
}

// Informed returns the informed entries, in order: the managers who are told
// and never decide.
func (s ManagerSet) Informed() ManagerSet {
	out := make(ManagerSet, 0, len(s))
	for _, e := range s {
		if e.Role == ManagerInformed {
			out = append(out, e)
		}
	}
	return out
}

// Primary returns the primary manager. When no entry carries the flag the FIRST
// accountable entry is the primary, which is what makes a one-entry legacy set
// (and a set whose author never set the flag) behave exactly as the single
// manager always did.
func (s ManagerSet) Primary() (ManagerEntry, bool) {
	for _, e := range s {
		if e.Primary {
			return e, true
		}
	}
	for _, e := range s {
		if e.Role == ManagerAccountable {
			return e, true
		}
	}
	return ManagerEntry{}, false
}

// Find returns the entry naming actorID, if the set holds one.
func (s ManagerSet) Find(actorID string) (ManagerEntry, bool) {
	for _, e := range s {
		if e.ActorID == actorID {
			return e, true
		}
	}
	return ManagerEntry{}, false
}

// Routed returns the set in the routing order: the primary accountable manager
// first, then the remaining accountable managers, then the approvers, then the
// informed. The order within each group is the declared order, so two routings
// over an unchanged set ask the same people in the same sequence.
func (s ManagerSet) Routed() ManagerSet {
	out := make(ManagerSet, 0, len(s))
	primary, hasPrimary := s.Primary()
	if hasPrimary {
		out = append(out, primary)
	}
	for _, e := range s {
		if e.Role != ManagerAccountable {
			continue
		}
		if hasPrimary && e.ActorID == primary.ActorID {
			continue
		}
		out = append(out, e)
	}
	for _, e := range s {
		if e.Role == ManagerApprover {
			out = append(out, e)
		}
	}
	for _, e := range s {
		if e.Role == ManagerInformed {
			out = append(out, e)
		}
	}
	return out
}

// Equal reports whether two sets hold the same entries in the same order. It
// exists because a set is a slice and a slice cannot be compared with ==, and
// the approval store has to ask the question when it verifies that a stored
// successor did not move a raise-time fact.
func (s ManagerSet) Equal(other ManagerSet) bool {
	if len(s) != len(other) {
		return false
	}
	for i := range s {
		if s[i] != other[i] {
			return false
		}
	}
	return true
}

// IDs returns the entry ids in declared order.
func (s ManagerSet) IDs() []string {
	out := make([]string, 0, len(s))
	for _, e := range s {
		out = append(out, e.ActorID)
	}
	return out
}

// Describe renders the set for a refusal message and for the console. It is
// stable and names every entry's order, kind, role and primary flag, because a
// rendering that dropped any of them would make "who manages this agent" a
// question the reader has to ask elsewhere.
func (s ManagerSet) Describe() string {
	if len(s) == 0 {
		return "no managers"
	}
	parts := make([]string, 0, len(s))
	for i, e := range s {
		role := e.Role.String()
		if e.Primary {
			role += ",primary"
		}
		parts = append(parts, fmt.Sprintf("%d:%s(%s,%s)", i+1, e.ActorID, e.Kind, role))
	}
	return strings.Join(parts, " ")
}

// SingleManagerSet returns the one-entry set a single manager materialises
// into: accountable, primary, and of the stated kind. It is the shape every
// existing agent gets on its next write, and the shape a reader derives when
// only the legacy field is recorded.
func SingleManagerSet(actorID string, kind ActorKind) ManagerSet {
	id := strings.TrimSpace(actorID)
	if id == "" {
		return nil
	}
	return ManagerSet{{ActorID: id, Kind: kind, Role: ManagerAccountable, Primary: true}}
}
