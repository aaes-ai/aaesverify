package types

import (
	"fmt"
	"strings"
)

// ApproverClass names the workforce an approver belongs to.
//
// The ZERO value is Human, deliberately. Every approval record written before
// this vocabulary existed was decided by a registered human, and a reader of
// such a record must see that without having to know the history of the field.
type ApproverClass int

const (
	// ApproverHuman is an actor the directory registers as a human. It is the
	// only class that existed before ADR-009, and it remains the class every
	// zero-valued record reads as.
	ApproverHuman ApproverClass = iota
	// ApproverAgent is an actor the directory registers as an agent. An agent
	// approver must carry a registered model identity, because correlated model
	// failure is the risk an agent approval brings and the family is what makes
	// it computable.
	ApproverAgent
	// ApproverService is a machine identity that is neither a human nor a model
	// actor: a scheduler, a broker, a CI principal. The vocabulary defines it so
	// a policy can name it and a reader can see it was considered. This build's
	// directory has no service actor kind, so the approval store refuses a
	// service approver and says so rather than folding it into "agent".
	ApproverService
)

// ApproverClasses lists every class in declaration order, so a parser, a
// renderer or a configuration validator cannot silently omit one.
func ApproverClasses() []ApproverClass {
	return []ApproverClass{ApproverHuman, ApproverAgent, ApproverService}
}

// ParseApproverClass maps a configured or recorded spelling back to its class.
// Matching is case-insensitive and trims surrounding whitespace, because the
// value arrives from a configuration file or an operator's console and neither
// is a good reason to refuse "Human". The boolean is the contract: on failure
// the returned class is ApproverHuman, the zero value, so a caller that ignores
// the boolean must not read it as permission -- Validate still refuses it.
func ParseApproverClass(s string) (ApproverClass, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	for _, c := range ApproverClasses() {
		if c.String() == trimmed {
			return c, true
		}
	}
	return ApproverHuman, false
}

// approverClassVocabulary renders the closed vocabulary for an error message.
func approverClassVocabulary() string {
	names := make([]string, 0, len(ApproverClasses()))
	for _, c := range ApproverClasses() {
		names = append(names, c.String())
	}
	return strings.Join(names, ", ")
}

// ApprovalAuthority says what an approval decides.
//
// The ZERO value is Granted, because that is what a granted approval has always
// meant: it authorises the intent it names. Recommended is the new and weaker
// value: the approval is recorded evidence -- an agent's triage, a reviewer's
// note -- and it never fills a requirement slot.
type ApprovalAuthority int

const (
	// AuthorityGranted is a decisive approval. It counts toward Required and
	// toward the human floor.
	AuthorityGranted ApprovalAuthority = iota
	// AuthorityRecommended is a recorded recommendation. It appears in the
	// evidence and in the quorum's state, and it never unlocks an action.
	AuthorityRecommended
)

// Decisive reports whether an approval with this authority may satisfy a
// requirement. It is the single place the rule "recommended never unlocks"
// lives, so no caller can spell it differently.
func (a ApprovalAuthority) Decisive() bool { return a == AuthorityGranted }

// ApprovalAuthorities lists every authority in declaration order.
func ApprovalAuthorities() []ApprovalAuthority {
	return []ApprovalAuthority{AuthorityGranted, AuthorityRecommended}
}

// ParseApprovalAuthority maps a configured spelling back to its authority.
func ParseApprovalAuthority(s string) (ApprovalAuthority, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	for _, a := range ApprovalAuthorities() {
		if a.String() == trimmed {
			return a, true
		}
	}
	return AuthorityGranted, false
}

// String renders the class as the lowercase token configuration, the console
// and every refusal message print. An off-vocabulary value is rendered as
// "unknown(N)" rather than folded into a class AAES can name: a refusal that
// said "human" about a value nobody defined would be a lie in the one place a
// reader checks what was permitted.
func (c ApproverClass) String() string {
	switch c {
	case ApproverHuman:
		return "human"
	case ApproverAgent:
		return "agent"
	case ApproverService:
		return "service"
	}
	return fmt.Sprintf("unknown(%d)", int(c))
}

// Validate reports whether the value is a class AAES can name.
func (c ApproverClass) Validate() error {
	switch c {
	case ApproverHuman, ApproverAgent, ApproverService:
		return nil
	}
	return fmt.Errorf("types: unknown approver class %d (want one of %s)", int(c), approverClassVocabulary())
}

// String renders the authority as the lowercase token every surface prints.
func (a ApprovalAuthority) String() string {
	switch a {
	case AuthorityGranted:
		return "granted"
	case AuthorityRecommended:
		return "recommended"
	}
	return fmt.Sprintf("unknown(%d)", int(a))
}

// Validate reports whether the value is an authority AAES can name.
func (a ApprovalAuthority) Validate() error {
	switch a {
	case AuthorityGranted, AuthorityRecommended:
		return nil
	}
	return fmt.Errorf("types: unknown approval authority %d (want %q or %q)",
		int(a), AuthorityGranted, AuthorityRecommended)
}
