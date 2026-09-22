package types

import "testing"

func TestActionGroupIsNotCRUD(t *testing.T) {
	want := map[Action]ActionGroup{
		ActionRead:     ActionGroupObserve,
		ActionWrite:    ActionGroupChange,
		ActionCreate:   ActionGroupChange,
		ActionUpdate:   ActionGroupChange,
		ActionExecute:  ActionGroupRun,
		ActionInvoke:   ActionGroupRun,
		ActionDelete:   ActionGroupIrreversible,
		ActionSend:     ActionGroupIrreversible,
		ActionPay:      ActionGroupIrreversible,
		ActionDeploy:   ActionGroupIrreversible,
		ActionApprove:  ActionGroupIrreversible,
		ActionShare:    ActionGroupIrreversible,
		ActionTransfer: ActionGroupIrreversible,
	}
	if len(want) != len(ActionVocabulary()) {
		t.Fatalf("group table covers %d verbs, vocabulary has %d", len(want), len(ActionVocabulary()))
	}
	for _, a := range ActionVocabulary() {
		if got := a.Group(); got != want[a] {
			t.Errorf("%s.Group() = %s, want %s", a, got, want[a])
		}
	}
	if ActionUnspecified.Group() != ActionGroupIrreversible {
		t.Fatal("an unknown verb must present as irreversible")
	}
}

func TestFormatActionsGroupedKeepsPayNamed(t *testing.T) {
	got := FormatActionsGrouped([]Action{ActionRead, ActionPay, ActionWrite})
	if got != "observe: read; change: write; irreversible: pay" {
		t.Fatalf("grouped = %q", got)
	}
	if FormatActionsGrouped(nil) != "" {
		t.Fatal("empty list must stay empty")
	}
}
