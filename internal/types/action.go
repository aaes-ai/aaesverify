package types

import (
	"fmt"
	"strings"
)

// Action is what an actor asks to do, distinct from the capability (how) and
// the resource it touches. The permission tuple is (actor, action, resource,
// data class, context) -> decision.
//
// MinTier is a floor, never a ceiling: policy may raise the tier, and no
// caller may lower it. Capability, scope and policy tiers are compared against
// this floor rather than replacing it.
type Action int

const (
	// ActionRead observes state without changing it. The one free action.
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
	// narrower action. It is the default for a capability that declares no actions.
	ActionInvoke
	// ActionApprove records a named person's judgement that authorizes someone
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
// not an action: it is outside the vocabulary, String renders it as "unknown(-1)"
// and Validate refuses it.
//
// It exists for the same reason RiskTierUnspecified does. The zero value of the
// vocabulary is ActionRead, the one free action, so a parser that returned the
// zero value beside its boolean would hand the most permissive answer available
// to a question that had no answer. MinTier and Irreversible answer for this
// value as if it were irreversible at the highest tier, so a caller that
// ignored the boolean still fails closed.
const ActionUnspecified Action = -1

// String renders the action as the lowercase token the CLI, the console and every
// error message print. A value off the end of the vocabulary is rendered as
// "unknown(N)" rather than folded into a real action: a reader must never see a
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

// ParseAction maps a recorded action back to its Action. Matching is
// case-insensitive and surrounding whitespace is ignored, because the value
// arrives from a configuration file, a CLI argument or a request body and none
// of those is a good reason to refuse "Read".
//
// On failure the returned Action is ActionUnspecified, NOT ActionRead: the
// boolean is the contract, and a valid action must never travel beside it.
func ParseAction(s string) (Action, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	for _, a := range ActionVocabulary() {
		if a.String() == trimmed {
			return a, true
		}
	}
	return ActionUnspecified, false
}

// Validate reports whether the value is an action AAES can name. A registration
// that carries an action off the end of the vocabulary is refused rather than
// defaulted: every later comparison against the floor assumes a real action.
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

// Irreversible reports whether the action cannot be taken back: a delete, a send,
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

// MinTier is the FLOOR of the action: the least risk tier at which it may ever be
// governed, never a ceiling. read is free; a write, create, update, execute or
// invoke is at least R2 because it changes state or runs code; delete, send,
// pay, deploy and approve are at least R3 because they cannot be taken back.
//
// Policy may raise this floor, the registered capability tier may sit above it,
// and a scope may cap the tier -- but nothing may lower it, and a registration
// whose tier sits below the floor of an action it declares is refused at
// registration (see Capability.Validate).
//
// A value off the end of the vocabulary reports the HIGHEST tier. Validate
// refuses such a value; a caller that skipped Validate gets the strict answer
// rather than a free action.
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

// ActionVocabulary lists every action, in declaration order. It exists so a
// parser, a renderer or a help text cannot silently omit one: an action left out
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

// checkActions validates an action list carried by a registration. Capability and
// Scope both call it, because two registration paths that disagree about what a
// action list may contain is how a control stops controlling.
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

// actionFloor returns the highest MinTier among an action list, with the action that
// carries it. The boolean is false for an empty list, which has no floor: a
// registration that declares no actions keeps its registered tier, and the invoke
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
