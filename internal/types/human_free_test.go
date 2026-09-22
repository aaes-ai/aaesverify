package types

import (
	"strings"
	"testing"
	"time"
)

// This file holds the type-level half of ADR-009 invariant 1: the shape of the
// sponsor's human-free approval opt-in, and the question a policy answers about
// whether it COULD be satisfied with no human at all.

func optedInWork() Work {
	return Work{
		WorkID: "w1", TenantID: "t1", Sponsor: "human-sponsor",
		State: WorkOpen, BudgetUSD: 100,
		HumanFreeApproval:        true,
		HumanFreeApprovalSponsor: "human-sponsor",
		HumanFreeApprovalAt:      time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC),
	}
}

// TestWorkRefusesAHalfHumanFreeOptIn: the opt-in is one act, recorded whole. A
// boolean with no subject, a subject who is not the accountable human, or a
// grant with no time would each read as autonomy while naming nobody
// answerable for it.
func TestWorkRefusesAHalfHumanFreeOptIn(t *testing.T) {
	valid := optedInWork()
	if err := valid.Validate(); err != nil {
		t.Fatalf("a complete opt-in was refused: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Work)
		want string
	}{
		{"no sponsor", func(w *Work) { w.HumanFreeApprovalSponsor = "" }, "no manager"},
		{"somebody else's grant", func(w *Work) { w.HumanFreeApprovalSponsor = "human-other" }, "only the accountable manager"},
		{"no time", func(w *Work) { w.HumanFreeApprovalAt = time.Time{} }, "no time"},
		{"sponsor without the opt-in", func(w *Work) { w.HumanFreeApproval = false; w.HumanFreeApprovalAt = time.Time{} }, "without the approval"},
		{"time without the opt-in", func(w *Work) { w.HumanFreeApproval = false; w.HumanFreeApprovalSponsor = "" }, "without the approval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := valid
			tc.mut(&w)
			err := w.Validate()
			if err == nil {
				t.Fatalf("work.Validate accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal does not name %q: %v", tc.want, err)
			}
		})
	}
}

// TestHumanFreeApprovalUsableRechecksTheWholeGrant: the decision path asks this
// question of a Work it did not necessarily load through the store, so every
// failure has to answer "no opt-in" rather than trust the boolean.
func TestHumanFreeApprovalUsableRechecksTheWholeGrant(t *testing.T) {
	w := optedInWork()
	sponsor, at, ok := w.HumanFreeApprovalUsable()
	if !ok || sponsor != "human-sponsor" || !at.Equal(w.HumanFreeApprovalAt) {
		t.Fatalf("a complete grant answered (%q, %s, %t)", sponsor, at, ok)
	}
	for name, mut := range map[string]func(*Work){
		"boolean false":      func(w *Work) { w.HumanFreeApproval = false },
		"no sponsor":         func(w *Work) { w.HumanFreeApprovalSponsor = "" },
		"different person":   func(w *Work) { w.HumanFreeApprovalSponsor = "human-other" },
		"no time":            func(w *Work) { w.HumanFreeApprovalAt = time.Time{} },
		"sponsor reshuffled": func(w *Work) { w.Sponsor = "human-other" },
	} {
		variant := w
		mut(&variant)
		if _, _, ok := variant.HumanFreeApprovalUsable(); ok {
			t.Fatalf("%s read as a usable opt-in", name)
		}
	}
}

// TestAllowsHumanFreePathNamesTheHumanFreeShapes: the policy question the
// gateway refuses on. Every case that says true is a policy an agent alone
// could satisfy for a reversible verb; every case that says false keeps a human
// by class or by floor.
func TestAllowsHumanFreePathNamesTheHumanFreeShapes(t *testing.T) {
	cases := []struct {
		name   string
		policy ApprovalPolicy
		action Action
		want   bool
	}{
		{"the default keeps a person", ApprovalPolicy{}, ActionWrite, false},
		{"an agent-only requirement", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}, ActionWrite, true},
		{"a mixed requirement with a minimum number of authorized persons", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman, ApproverAgent}, MinHumans: 1}, ActionWrite, false},
		{"a mixed requirement with no floor", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman, ApproverAgent}, MinHumans: 0}, ActionWrite, true},
		{"a human-only requirement", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman}, MinHumans: 0}, ActionWrite, false},
		{"nothing required at all", ApprovalPolicy{Required: 0, Classes: []ApproverClass{ApproverHuman}, MinHumans: 0}, ActionWrite, true},
		{"two approvals, no floor, an agent permitted", ApprovalPolicy{Required: 2, Classes: []ApproverClass{ApproverHuman, ApproverAgent}, MinHumans: 0}, ActionWrite, true},
		{"the default bundle's dual control", ApprovalPolicy{Required: 2, Classes: []ApproverClass{ApproverHuman}, MinHumans: 1}, ActionWrite, false},
		// The irreversible verbs keep the floor whatever the policy says, and an
		// unspecified verb answers as irreversible.
		{"an agent-only policy on delete", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}, ActionDelete, false},
		{"an agent-only policy on send", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}, ActionSend, false},
		{"an agent-only policy on pay", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}, ActionPay, false},
		{"an agent-only policy on deploy", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}, ActionDeploy, false},
		{"an agent-only policy on approve", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}, ActionApprove, false},
		{"an agent-only policy with no verb", ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverAgent}, MinHumans: 0}, ActionUnspecified, false},
		// Zero required with an agent permitted but a raised human floor: the
		// floor is what keeps the human.
		{"nothing required but a floor of one", ApprovalPolicy{Required: 0, Classes: []ApproverClass{ApproverHuman, ApproverAgent}, MinHumans: 1}, ActionWrite, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.AllowsHumanFreePath(tc.action); got != tc.want {
				t.Fatalf("AllowsHumanFreePath(%s) = %t, want %t", tc.action, got, tc.want)
			}
		})
	}
}
