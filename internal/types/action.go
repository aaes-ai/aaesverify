package types

import (
	"fmt"
	"strings"
)

// Action is the verb of a permission: what an actor asks to DO, as distinct
// from the capability it asks to do it through and the resource it touches.
//
// The permission model is the tuple (actor, verb, resource, data class,
// context) -> decision. A capability is the HOW -- the registered tool, its
// endpoint, its credential. The verb is the WHAT, and it is a dimension of its
// own because one capability is harmless at one verb and irreversible at
// another: a bucket tool that may read a bucket must not therefore be able to
// delete it. A record that names only the capability leaves a later reader to
// infer the verb from a registration that may since have changed, and an
// inferred permission is not evidence of the permission that was exercised.
//
// # MinTier is a FLOOR, never a ceiling
//
// MinTier reports the least tier a verb may ever be governed at. Policy may
// raise the tier of an action -- an internal write against production data is
// still an R2 verb, and an operator is free to require R4 for it -- and no
// caller may lower it. The registered capability tier, the scope tier and the
// policy tier are all compared against this floor rather than replacing it, so
// a request that names a cheap tier for an expensive verb is refused instead of
// believed.
type Action int

const (
	// ActionRead observes state without changing it. The one free verb.
	ActionRead Action = iota
	// ActionWrite changes the contents of an existing thing.
	ActionWrite
	// ActionCreate brings a new thing into existence.
	ActionCreate
	// ActionUpdate changes the properties of an existing thing, as distinct
	// from its contents.
	ActionUpdate
	// ActionDelete removes a thing. Irreversible.
	ActionDelete
	// ActionSend transmits data to a destination outside AAES's control, which
	// is why it is irreversible: a message cannot be unsent.
	ActionSend
	// ActionExecute runs a command or a program.
	ActionExecute
	// ActionPay moves money. Irreversible.
	ActionPay
	// ActionDeploy publishes a change to a live environment. Irreversible.
	ActionDeploy
	// ActionInvoke calls a registered tool or MCP server without naming a
	// narrower verb. It is the default for a capability that declares no verbs.
	ActionInvoke
	// ActionApprove records a named person's judgement that authorises someone
	// else's action. Irreversible.
	ActionApprove
	// ActionShare grants another party a copy of access or of the object.
	// Irreversible: a share cannot be unsent once the other party has it.
	ActionShare
	// ActionTransfer moves ownership or custody to another party. Irreversible:
	// the previous holder no longer has the thing.
	ActionTransfer
)

// ActionUnspecified is what ParseAction returns BESIDE a failed parse. It is
// not a verb: it is outside the vocabulary, String renders it as "unknown(-1)"
// and Validate refuses it.
//
// It exists for the same reason RiskTierUnspecified does. The zero value of the
// vocabulary is ActionRead, the one free verb, so a parser that returned the
// zero value beside its boolean would hand the most permissive answer available
// to a question that had no answer. MinTier and Irreversible answer for this
// value as if it were irreversible at the highest tier, so a caller that
// ignored the boolean still fails closed.
const ActionUnspecified Action = -1

// String renders the verb as the lowercase token the CLI, the console and every
// error message print. A value off the end of the vocabulary is rendered as
// "unknown(N)" rather than folded into a real verb: a reader must never see a
// permission described as "read" when the number meant nothing of the kind.
func (a Action) String() string {
	switch a {
	case ActionRead:
		return "read"
	case ActionWrite:
		return "write"
	case ActionCreate:
		return "create"
	case ActionUpdate:
		return "update"
	case ActionDelete:
		return "delete"
	case ActionSend:
		return "send"
	case ActionExecute:
		return "execute"
	case ActionPay:
		return "pay"
	case ActionDeploy:
		return "deploy"
	case ActionInvoke:
		return "invoke"
	case ActionApprove:
		return "approve"
	case ActionShare:
		return "share"
	case ActionTransfer:
		return "transfer"
	}
	return fmt.Sprintf("unknown(%d)", int(a))
}

// ParseAction maps a recorded verb back to its Action. Matching is
// case-insensitive and surrounding whitespace is ignored, because the value
// arrives from a configuration file, a CLI argument or a request body and none
// of those is a good reason to refuse "Read".
//
// On failure the returned Action is ActionUnspecified, NOT ActionRead: the
// boolean is the contract, and a valid verb must never travel beside it.
func ParseAction(s string) (Action, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	for _, a := range ActionVocabulary() {
		if a.String() == trimmed {
			return a, true
		}
	}
	return ActionUnspecified, false
}

// Validate reports whether the value is a verb AAES can name. A registration
// that carries a verb off the end of the vocabulary is refused rather than
// defaulted: every later comparison against the floor assumes a real verb.
func (a Action) Validate() error {
	switch a {
	case ActionRead, ActionWrite, ActionCreate, ActionUpdate, ActionDelete,
		ActionSend, ActionExecute, ActionPay, ActionDeploy, ActionInvoke, ActionApprove,
		ActionShare, ActionTransfer:
		return nil
	}
	return errf("unknown action %d; AAES refuses to name an action it does not define (want one of %s)",
		int(a), actionVocabulary())
}

// Irreversible reports whether the verb cannot be taken back: a delete, a send,
// a pay, a deploy or an approve.
//
// The list is closed on purpose. These are the actions after which "stop" is
// no longer available -- the row is gone, the message is delivered, the money
// has moved, the release is live, the approval is on the record, the share
// has a copy, the transfer has a new owner -- so the decision path must raise
// a named-approver gate for them even when policy and amount would not.
//
// A value off the end of the vocabulary reports TRUE. Validate refuses such a
// value, and this is what a caller that skipped Validate sees: the strict
// answer, not the cheap one.
func (a Action) Irreversible() bool {
	switch a {
	case ActionDelete, ActionSend, ActionPay, ActionDeploy, ActionApprove, ActionShare, ActionTransfer:
		return true
	case ActionRead, ActionWrite, ActionCreate, ActionUpdate, ActionExecute, ActionInvoke:
		return false
	}
	return true
}

// MinTier is the FLOOR of the verb: the least risk tier at which it may ever be
// governed, never a ceiling. read is free; a write, create, update, execute or
// invoke is at least R2 because it changes state or runs code; delete, send,
// pay, deploy and approve are at least R3 because they cannot be taken back.
//
// Policy may raise this floor, the registered capability tier may sit above it,
// and a scope may cap the tier -- but nothing may lower it, and a registration
// whose tier sits below the floor of a verb it declares is refused at
// registration (see Capability.Validate).
//
// A value off the end of the vocabulary reports the HIGHEST tier. Validate
// refuses such a value; a caller that skipped Validate gets the strict answer
// rather than a free verb.
func (a Action) MinTier() RiskTier {
	switch a {
	case ActionRead:
		return R0RiskTier
	case ActionWrite, ActionCreate, ActionUpdate, ActionExecute, ActionInvoke:
		return R2RiskTier
	case ActionDelete, ActionSend, ActionPay, ActionDeploy, ActionApprove, ActionShare, ActionTransfer:
		return R3RiskTier
	}
	return MaxRiskTier
}

// ActionVocabulary lists every verb, in declaration order. It exists so a
// parser, a renderer or a help text cannot silently omit one: a verb left out
// of this list becomes unparseable, which reads as "not recorded" and is
// therefore treated as nothing declared.
func ActionVocabulary() []Action {
	return []Action{
		ActionRead,
		ActionWrite,
		ActionCreate,
		ActionUpdate,
		ActionDelete,
		ActionSend,
		ActionExecute,
		ActionPay,
		ActionDeploy,
		ActionInvoke,
		ActionApprove,
		ActionShare,
		ActionTransfer,
	}
}

// ValidActions is the same list under the name a caller may reach for first.
// There is exactly one list in the system and this function delegates to it, so
// two names cannot drift into two answers.
func ValidActions() []Action { return ActionVocabulary() }

// actionVocabulary renders the closed vocabulary for an error message.
func actionVocabulary() string {
	names := make([]string, 0, len(ActionVocabulary()))
	for _, a := range ActionVocabulary() {
		names = append(names, a.String())
	}
	return strings.Join(names, ", ")
}

// checkActions validates a verb list carried by a registration. Capability and
// Scope both call it, because two registration paths that disagree about what a
// verb list may contain is how a control stops controlling.
func checkActions(what string, actions []Action) error {
	seen := make(map[Action]bool, len(actions))
	for _, a := range actions {
		if err := a.Validate(); err != nil {
			return errf("%s names an unusable action: %v", what, err)
		}
		if seen[a] {
			return errf("%s names the action %q twice; a duplicated action tells a reader the list was reviewed when it was not", what, a)
		}
		seen[a] = true
	}
	return nil
}

// actionFloor returns the highest MinTier among a verb list, with the verb that
// carries it. The boolean is false for an empty list, which has no floor: a
// registration that declares no verbs keeps its registered tier, and the invoke
// default is applied where the decision is taken rather than retroactively
// raising a tier an operator already reviewed.
func actionFloor(actions []Action) (Action, RiskTier, bool) {
	var (
		carrier Action
		floor   RiskTier
		found   bool
	)
	for _, a := range actions {
		t := a.MinTier()
		if !found || t > floor {
			carrier, floor, found = a, t, true
		}
	}
	return carrier, floor, found
}
