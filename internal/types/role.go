package types

import (
	"fmt"
	"sort"
	"strings"
)

// Role is an operator role: what a registered human may do on the operator
// surfaces, as opposed to what an agent may do through a scope.
//
// Roles are deliberately few and flat. The directory already answers "which
// actor is this" and scopes already answer "what may it do to a capability";
// a role answers the third question, "what may this human do to AAES itself" --
// approve, own, sponsor, audit or administer. A role is granted by the
// operator's own identity provider through a group mapping (internal/identity),
// never by the actor asserting it: an actor record carries roles only because
// an import or an admin put them there.
type Role string

const (
	// RoleApprover may decide approvals. An actor without it cannot approve,
	// whatever its sponsor relationship to the work.
	RoleApprover Role = "approver"
	// RoleOwner is accountable for a capability or resource. It may end a live
	// entitlement but may not decide approvals.
	RoleOwner Role = "owner"
	// RoleSponsor is the accountable human named on an agent. It may read and
	// revoke entitlements for its own agents; it is not an approver by virtue
	// of sponsoring.
	RoleSponsor Role = "sponsor"
	// RoleAuditor reads everything the operator surface shows and writes
	// nothing: an audit that can approve is not an audit.
	RoleAuditor Role = "auditor"
	// RoleAdmin administers the deployment: it holds every other role plus the
	// power to change the identity policy (the group/actor role mapping), which
	// no other role may do.
	RoleAdmin Role = "admin"
)

// rolesInOrder is the vocabulary in a stable order. It is the single list a
// parser, a form and the runbook must agree on.
func rolesInOrder() []Role {
	return []Role{RoleApprover, RoleOwner, RoleSponsor, RoleAuditor, RoleAdmin}
}

// Roles returns the role vocabulary in a deterministic order.
func Roles() []Role {
	out := rolesInOrder()
	return append([]Role(nil), out...)
}

// String renders the role. The zero role renders as the empty string so a
// record that carries no role reads as "none" rather than as a role named "".
func (r Role) String() string { return string(r) }

// Valid reports whether the value is a role AAES can name. It is
// case-sensitive on purpose: a deployment that wrote "Admin" and meant it
// should be told its spelling is not in the vocabulary rather than silently
// accepted, because the role decides what a human may do.
func (r Role) Valid() bool {
	for _, known := range rolesInOrder() {
		if r == known {
			return true
		}
	}
	return false
}

// ParseRole maps a configured or recorded spelling back to its role. Surrounding
// whitespace and case are tolerated because the value arrives from an identity
// provider's group name, where "Approver" and "approver" are the same
// intention; anything else is refused with the vocabulary in the error.
func ParseRole(s string) (Role, error) {
	trimmed := strings.TrimSpace(strings.ToLower(s))
	for _, known := range rolesInOrder() {
		if trimmed == string(known) {
			return known, nil
		}
	}
	return "", fmt.Errorf("types: %q is not an operator role; the vocabulary is %s",
		s, roleVocabulary())
}

// ParseRoleList parses a list of role spellings. A duplicate is collapsed, not
// refused: "approver,approver" is one role, and refusing it would make an
// identity provider's group list order-sensitive.
func ParseRoleList(values []string) ([]Role, error) {
	seen := map[Role]bool{}
	out := make([]Role, 0, len(values))
	for _, raw := range values {
		r, err := ParseRole(raw)
		if err != nil {
			return nil, err
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	SortRoles(out)
	return out, nil
}

// roleVocabulary is the human-readable list used in refusals.
func roleVocabulary() string {
	names := make([]string, 0, len(rolesInOrder()))
	for _, r := range rolesInOrder() {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}

// SortRoles orders a role list by the vocabulary order, so two lists that carry
// the same roles render identically. Order is not authority: a caller must ask
// HasRole, never compare the first element.
func SortRoles(roles []Role) {
	rank := map[Role]int{}
	for i, r := range rolesInOrder() {
		rank[r] = i
	}
	sort.SliceStable(roles, func(i, j int) bool {
		ri, iOK := rank[roles[i]]
		rj, jOK := rank[roles[j]]
		switch {
		case iOK && jOK:
			return ri < rj
		case iOK:
			return true
		case jOK:
			return false
		default:
			return roles[i] < roles[j]
		}
	})
}

// HasRole reports whether the list carries the role. A zero role is never
// carried: "no role required" is expressed by not asking, not by granting "".
func HasRole(roles []Role, want Role) bool {
	if !want.Valid() {
		return false
	}
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// CopyRoles returns a copy that shares no backing array with the input. The
// directory stores role lists and hands them out; without this, a caller could
// grant itself a role with an append.
func CopyRoles(roles []Role) []Role {
	if roles == nil {
		return nil
	}
	out := make([]Role, len(roles))
	copy(out, roles)
	return out
}

// RolesText renders a role list for a page, a log line or a record summary.
func RolesText(roles []Role) string {
	if len(roles) == 0 {
		return "none"
	}
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, string(r))
	}
	return strings.Join(names, ",")
}

// RoleDisplayText renders one role the way a person reads it. RoleSponsor is
// the one role whose RECORD value is still spelled the historical way
// ("sponsor"); the user-facing term is manager. The record value is unchanged,
// so every existing configuration and sealed record keeps working.
func RoleDisplayText(r Role) string {
	if r == RoleSponsor {
		return "manager"
	}
	return string(r)
}

// RolesDisplayText renders a role list for a page, a refusal or CLI output. It
// is RolesText with each role passed through RoleDisplayText; use RolesText
// where the wire spelling is what the reader must see (a record summary, a log
// field, the identity-policy mapping an operator edits).
func RolesDisplayText(roles []Role) string {
	if len(roles) == 0 {
		return "none"
	}
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, RoleDisplayText(r))
	}
	return strings.Join(names, ",")
}

// RoleListDisplayText translates a comma-separated wire list -- the spelling
// types.RolesText and the directory store -- into the page spelling. An unknown
// token is passed through rather than dropped, because a page that hid a role
// it did not recognise would under-report what an identity carries.
func RoleListDisplayText(wire string) string {
	if wire == "" {
		return wire
	}
	parts := strings.Split(wire, ",")
	for i, part := range parts {
		if Role(strings.TrimSpace(part)) == RoleSponsor {
			parts[i] = "manager"
		}
	}
	return strings.Join(parts, ",")
}

// Role permissions. Each rule lives on the type so the console, an adapter and
// a test cannot disagree about what a role means; a second copy of the rule in
// a handler is how an "auditor cannot approve" claim stops being true.

// CanApprove reports whether the role may decide an approval. Admin holds every
// role; owner and sponsor do not approve by virtue of owning or sponsoring, and
// an auditor never does.
func (r Role) CanApprove() bool { return r == RoleApprover || r == RoleAdmin }

// CanEndEntitlement reports whether the role may revoke a live entitlement. An
// owner is accountable for what it owns, an approver decided it and may end it,
// an admin may do anything; an auditor reads.
func (r Role) CanEndEntitlement() bool {
	return r == RoleOwner || r == RoleApprover || r == RoleAdmin
}

// CanChangeIdentityPolicy reports whether the role may change the group-to-role
// mapping or an actor's roles. Only admin may: the mapping is what grants every
// other power, so a role that could edit it would be able to grant itself
// anything.
func (r Role) CanChangeIdentityPolicy() bool { return r == RoleAdmin }

// ReadOnly reports whether the role may only read the operator surface. The
// console refuses every write an auditor attempts and names the role it would
// have needed.
func (r Role) ReadOnly() bool { return r == RoleAuditor }

// RoleRefusalError is the refusal a role gate returns. It is a type rather than
// a formatted string so a handler can render the missing role, log it, and a
// test can assert on the role without matching prose.
type RoleRefusalError struct {
	// Role is the role the operation required.
	Role Role
	// Carried is what the identity actually holds, copied, for the message.
	Carried []Role
	// Operation names what was attempted, for the message and the log.
	Operation string
}

func (e RoleRefusalError) Error() string {
	return fmt.Sprintf("types: %s requires the %q role; the identity carries %s",
		e.Operation, RoleDisplayText(e.Role), RolesDisplayText(e.Carried))
}
