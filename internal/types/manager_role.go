package types

import (
	"fmt"
	"strings"
)

// ManagerRole is what a manager may do about the agent it manages. It is a
// closed vocabulary: an unrecognised role reading as "may approve" would widen
// authority, and reading as "informed" would silently remove a decider, so
// Validate refuses it instead of folding it into either.
type ManagerRole int

const (
	// ManagerAccountable answers for the agent. An accountable manager may
	// approve the agent's actions and may fill a quorum slot.
	ManagerAccountable ManagerRole = iota
	// ManagerApprover may approve the agent's actions and may fill a quorum
	// slot, but does not answer for the agent the way an accountable manager
	// does. A risk officer who signs but does not own the agent is this role.
	ManagerApprover
	// ManagerInformed is told about the agent's actions and NEVER decides. An
	// informed manager fills no quorum slot under any policy: the role exists so
	// an organisation can record a stakeholder without turning them into an
	// approver by accident.
	ManagerInformed
)

// ManagerRoles lists every role in declaration order, so a parser, a renderer
// or a configuration validator cannot silently omit one.
func ManagerRoles() []ManagerRole {
	return []ManagerRole{ManagerAccountable, ManagerApprover, ManagerInformed}
}

// ParseManagerRole maps a configured or recorded spelling back to its role.
// Matching is case-insensitive and trims surrounding whitespace, because the
// value arrives from a configuration file or an operator's console and neither
// is a good reason to refuse "Accountable". The boolean is the contract: on
// failure the returned role is ManagerAccountable, the zero value, so a caller
// that ignores the boolean must not read it as permission -- Validate still
// refuses the string it was built from only if the caller checks the boolean,
// which is why every caller in this build does.
func ParseManagerRole(s string) (ManagerRole, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	for _, r := range ManagerRoles() {
		if r.String() == trimmed {
			return r, true
		}
	}
	return ManagerAccountable, false
}

// managerRoleVocabulary renders the closed vocabulary for an error message.
func managerRoleVocabulary() string {
	names := make([]string, 0, len(ManagerRoles()))
	for _, r := range ManagerRoles() {
		names = append(names, r.String())
	}
	return strings.Join(names, ", ")
}

// ManagerEntry is one manager of one actor.
type ManagerEntry struct {
	// ActorID is the directory id of the manager. It is required.
	ActorID string
	// Kind is the manager's actor kind. It is REQUIRED rather than inferred
	// from ActorID because "is this manager a person or another agent" is the
	// question the approval rule, the routing rule and the console all ask, and
	// an id is not an answer. A zero value reads as KindAgent, so an explicitly
	// human manager must say so.
	Kind ActorKind
	// Role is what the manager may do (see ManagerRole).
	Role ManagerRole
	// Primary marks the ONE manager who heads the routing order for this actor.
	// At most one entry may carry it, and it must be an accountable manager:
	// routing to "the primary" is meaningless when the primary is not the one
	// who answers for the agent.
	Primary bool
}

// String renders the role as the lowercase token configuration, the console and
// every refusal message print. An off-vocabulary value renders as "unknown(N)"
// rather than being folded into a role AAES can name.
func (r ManagerRole) String() string {
	switch r {
	case ManagerAccountable:
		return "accountable"
	case ManagerApprover:
		return "approver"
	case ManagerInformed:
		return "informed"
	}
	return fmt.Sprintf("unknown(%d)", int(r))
}

// Validate reports whether the role is one AAES can name.
func (r ManagerRole) Validate() error {
	switch r {
	case ManagerAccountable, ManagerApprover, ManagerInformed:
		return nil
	}
	return fmt.Errorf("%w: unknown manager role %d (want one of %s)", ErrManagerRole, int(r), managerRoleVocabulary())
}

// Deciding reports whether an entry may fill a quorum slot. An informed manager
// never decides, under every policy.
func (e ManagerEntry) Deciding() bool { return e.Role != ManagerInformed }

// Validate checks one entry against the actor it manages. subject is the id of
// the managed actor; an entry that names it is self-management and is refused,
// because an actor that manages itself is an actor whose failures have no
// owner.
func (e ManagerEntry) Validate(subject string) error {
	id := strings.TrimSpace(e.ActorID)
	if id == "" {
		return fmt.Errorf("%w: actor %q has a manager entry with no actor id", ErrManagerKind, subject)
	}
	if subject != "" && id == subject {
		return fmt.Errorf("%w: actor %q names itself as its own manager", ErrManagerSelf, subject)
	}
	if err := e.Role.Validate(); err != nil {
		return fmt.Errorf("types: actor %q manager %q: %w", subject, id, err)
	}
	if e.Kind != KindHuman && e.Kind != KindAgent {
		return fmt.Errorf("%w: actor %q manager %q has unknown kind %d (want %s or %s)",
			ErrManagerKind, subject, id, int(e.Kind), KindHuman, KindAgent)
	}
	if e.Primary && e.Role != ManagerAccountable {
		return fmt.Errorf("%w: actor %q names %q as its primary manager with role %q; the primary manager is the one who answers for the actor, so only an accountable manager may be primary",
			ErrManagerRole, subject, id, e.Role)
	}
	return nil
}
