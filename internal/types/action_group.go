package types

import "strings"

// ActionGroup is how the closed action list is presented. The vocabulary is not
// CRUD: agents also send, pay, deploy, execute, invoke and approve. The groups
// are presentation, not a second permission model.
type ActionGroup string

const (
	ActionGroupObserve      ActionGroup = "observe"
	ActionGroupChange       ActionGroup = "change"
	ActionGroupRun          ActionGroup = "run"
	ActionGroupIrreversible ActionGroup = "irreversible"
)

// Group is the presentation bucket of an action. A value off the vocabulary
// reports irreversible, the strict answer, matching MinTier and Irreversible.
func (a Action) Group() ActionGroup {
	switch a {
	case ActionRead:
		return ActionGroupObserve
	case ActionWrite, ActionCreate, ActionUpdate:
		return ActionGroupChange
	case ActionExecute, ActionInvoke:
		return ActionGroupRun
	case ActionDelete, ActionSend, ActionPay, ActionDeploy, ActionApprove, ActionShare, ActionTransfer:
		return ActionGroupIrreversible
	}
	return ActionGroupIrreversible
}

// Label is the human spelling of a group.
func (g ActionGroup) Label() string {
	switch g {
	case ActionGroupObserve:
		return "observe"
	case ActionGroupChange:
		return "change"
	case ActionGroupRun:
		return "run"
	case ActionGroupIrreversible:
		return "irreversible"
	}
	return string(g)
}

// ActionGroups lists the presentation buckets in the order a human reads them.
func ActionGroups() []ActionGroup {
	return []ActionGroup{
		ActionGroupObserve,
		ActionGroupChange,
		ActionGroupRun,
		ActionGroupIrreversible,
	}
}

// FormatActionsGrouped renders an action list as "observe: read; change: write,
// create". An empty list is the empty string. Actions stay named; the groups
// tell a reader which ones are irreversible without collapsing pay into create.
func FormatActionsGrouped(actions []Action) string {
	if len(actions) == 0 {
		return ""
	}
	byGroup := make(map[ActionGroup][]string, 4)
	for _, a := range actions {
		g := a.Group()
		byGroup[g] = append(byGroup[g], a.String())
	}
	parts := make([]string, 0, 4)
	for _, g := range ActionGroups() {
		names := byGroup[g]
		if len(names) == 0 {
			continue
		}
		parts = append(parts, g.Label()+": "+strings.Join(names, ", "))
	}
	return strings.Join(parts, "; ")
}
