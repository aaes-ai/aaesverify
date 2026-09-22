package types

import (
	"strconv"
	"strings"
	"testing"
)

// The floors are the contract: policy may raise a tier above a verb's floor and
// no caller may lower one below it, so a floor that drifts silently changes what
// every policy comparison and every scope cap means. The table pins every
// action, and the count check below makes the test fail if an action is added and
// left unclassified rather than quietly inheriting an answer.
func TestActionFloorsAreTheDocumentedMinimum(t *testing.T) {
	want := map[Action]RiskTier{
		ActionRead:     R0RiskTier,
		ActionWrite:    R2RiskTier,
		ActionCreate:   R2RiskTier,
		ActionUpdate:   R2RiskTier,
		ActionExecute:  R2RiskTier,
		ActionInvoke:   R2RiskTier,
		ActionDelete:   R3RiskTier,
		ActionSend:     R3RiskTier,
		ActionPay:      R3RiskTier,
		ActionDeploy:   R3RiskTier,
		ActionApprove:  R3RiskTier,
		ActionShare:    R3RiskTier,
		ActionTransfer: R3RiskTier,
	}
	if len(want) != len(ActionVocabulary()) {
		t.Fatalf("the floor table covers %d actions but the vocabulary has %d; a new action must be classified deliberately",
			len(want), len(ActionVocabulary()))
	}
	for _, a := range ActionVocabulary() {
		if got := a.MinTier(); got != want[a] {
			t.Errorf("Action(%s).MinTier() = %s, want %s", a, got, want[a])
		}
	}
	// A value off the end of the vocabulary is not a free verb. Validate refuses
	// it, and a caller that skipped Validate must get the strictest answer, not
	// the cheapest one.
	if got := ActionUnspecified.MinTier(); got != MaxRiskTier {
		t.Errorf("ActionUnspecified.MinTier() = %s, want the highest tier %s", got, MaxRiskTier)
	}
	if got := Action(99).MinTier(); got != MaxRiskTier {
		t.Errorf("Action(99).MinTier() = %s, want the highest tier %s", got, MaxRiskTier)
	}
}

// The irreversible set is the verbs after which "stop" is no longer available.
func TestActionIrreversibleSetIsExactlyTheSeven(t *testing.T) {
	want := map[Action]bool{
		ActionRead:     false,
		ActionWrite:    false,
		ActionCreate:   false,
		ActionUpdate:   false,
		ActionDelete:   true,
		ActionSend:     true,
		ActionExecute:  false,
		ActionPay:      true,
		ActionDeploy:   true,
		ActionInvoke:   false,
		ActionApprove:  true,
		ActionShare:    true,
		ActionTransfer: true,
	}
	if len(want) != len(ActionVocabulary()) {
		t.Fatalf("the irreversibility table covers %d actions but the vocabulary has %d", len(want), len(ActionVocabulary()))
	}
	for _, a := range ActionVocabulary() {
		if got := a.Irreversible(); got != want[a] {
			t.Errorf("Action(%s).Irreversible() = %v, want %v", a, got, want[a])
		}
	}
	// Fail closed off the end of the vocabulary: an unknown verb is treated as
	// irreversible rather than waved through.
	if !ActionUnspecified.Irreversible() || !Action(99).Irreversible() {
		t.Error("an action off the end of the vocabulary reports itself as reversible")
	}
}

// Parsing is case-insensitive and trimmed, and a failed parse must never hand
// back a real verb. The zero value of the vocabulary is ActionRead, the one
// free verb, so returning it beside a false boolean would hand the most
// permissive answer available to a question that had no answer.
func TestParseActionIsCaseInsensitiveTrimmedAndFailClosed(t *testing.T) {
	for _, a := range ActionVocabulary() {
		for _, spelling := range []string{a.String(), strings.ToUpper(a.String()), "  " + a.String() + " "} {
			got, ok := ParseAction(spelling)
			if !ok || got != a {
				t.Fatalf("ParseAction(%q) = %s, %v; want %s, true", spelling, got, ok, a)
			}
		}
	}
	for _, raw := range []string{"", "   ", "frobnicate", "read write", "readwrite", "R3"} {
		got, ok := ParseAction(raw)
		if ok {
			t.Fatalf("ParseAction(%q) reported a known verb %s", raw, got)
		}
		if got != ActionUnspecified {
			t.Fatalf("ParseAction(%q) returned %s beside a failed parse; want %s", raw, got, ActionUnspecified)
		}
		if got.Validate() == nil {
			t.Fatalf("ParseAction(%q) returned a value that validates", raw)
		}
		if got.String() == "read" {
			t.Fatalf("ParseAction(%q) rendered as a real verb", raw)
		}
	}
}

// String must render a value off the end of the vocabulary as unknown(N) rather
// than picking a real verb: a reader must never see a permission described as
// "read" when the number meant nothing of the kind.
func TestActionStringRefusesToPickARealVerb(t *testing.T) {
	for _, a := range ActionVocabulary() {
		if got := a.String(); got == "" || strings.HasPrefix(got, "unknown(") {
			t.Errorf("Action(%d).String() = %q", int(a), got)
		}
	}
	for _, bad := range []Action{ActionUnspecified, Action(13), Action(99)} {
		want := "unknown(" + strconv.Itoa(int(bad)) + ")"
		if got := bad.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", int(bad), got, want)
		}
		if err := bad.Validate(); err == nil {
			t.Errorf("Action(%d).Validate() = nil, want a refusal", int(bad))
		}
	}
	for _, a := range ActionVocabulary() {
		if err := a.Validate(); err != nil {
			t.Errorf("Action(%s).Validate() = %v, want nil", a, err)
		}
	}
}

// The vocabulary is declaration order, and it must contain every verb exactly
// once: a verb left out becomes unparseable, which reads as "not recorded".
func TestActionVocabularyIsCompleteAndOrdered(t *testing.T) {
	want := []Action{
		ActionRead, ActionWrite, ActionCreate, ActionUpdate, ActionDelete,
		ActionSend, ActionExecute, ActionPay, ActionDeploy, ActionInvoke, ActionApprove,
		ActionShare, ActionTransfer,
	}
	got := ActionVocabulary()
	if len(got) != len(want) {
		t.Fatalf("ActionVocabulary() has %d verbs, want %d", len(got), len(want))
	}
	seen := map[Action]bool{}
	for i, a := range got {
		if a != want[i] {
			t.Fatalf("ActionVocabulary()[%d] = %s, want %s", i, a, want[i])
		}
		if seen[a] {
			t.Fatalf("ActionVocabulary() lists %s twice", a)
		}
		seen[a] = true
	}
	// The alias must be the same list, not a second one that can drift.
	if alias := ValidActions(); len(alias) != len(want) {
		t.Fatalf("ValidActions() has %d verbs, want %d", len(alias), len(want))
	} else {
		for i := range want {
			if alias[i] != want[i] {
				t.Fatalf("ValidActions()[%d] = %s, want %s", i, alias[i], want[i])
			}
		}
	}
}
