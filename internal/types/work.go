package types

import (
	"fmt"
	"time"
)

// WorkState is the lifecycle of a unit of work. The set is deliberately small
// and deliberately terminal-aware: abandonment is a first-class outcome because
// the thing an examiner asks after an incident is not only what succeeded but
// what was left unfinished, and by whom.
type WorkState int

const (
	WorkDraft WorkState = iota
	WorkOpen
	WorkClaimed
	WorkBlocked
	WorkCompleted
	WorkAbandoned
	WorkExpired
)

func (w WorkState) String() string {
	switch w {
	case WorkDraft:
		return "draft"
	case WorkOpen:
		return "open"
	case WorkClaimed:
		return "claimed"
	case WorkBlocked:
		return "blocked"
	case WorkCompleted:
		return "completed"
	case WorkAbandoned:
		return "abandoned"
	case WorkExpired:
		return "expired"
	}
	return fmt.Sprintf("unknown(%d)", int(w))
}

// Terminal reports whether no further action may be taken against this work.
// A terminal task mints nothing: the budget is closed and the record is final.
func (w WorkState) Terminal() bool {
	return w == WorkCompleted || w == WorkAbandoned || w == WorkExpired
}

// AcceptsSpend reports whether an action may commit budget against this state.
func (w WorkState) AcceptsSpend() bool {
	return w == WorkOpen || w == WorkClaimed || w == WorkBlocked
}

// Work is the unit of work. Every governed action names one, or is refused.
//
// The zero value is deliberately NOT usable: WorkID and TenantID empty means the
// record does not exist, and the gateway refuses rather than treating an
// unnamed action as unconstrained.
type Work struct {
	WorkID   string
	TenantID string
	ParentID string // set when this work was delegated from another
	Title    string
	State    WorkState
	// Sponsor is the accountable human. Required for agent-assigned work: an
	// agent may not sponsor itself or another agent.
	Sponsor string
	// Assignee is the actor expected to do the work, human or agent. Empty means
	// unclaimed and any actor holding the capability may claim it.
	Assignee string
	// BudgetUSD is the ceiling for the whole unit of work, not per action.
	BudgetUSD float64
	// CommittedUSD is what has been authorised so far. It only grows. It is the
	// field that makes an aggregate bound possible, and it is committed inside
	// the same journal write that authorises an action.
	CommittedUSD float64
	// HumanFreeApproval is the work sponsor's opt-in to a human-free approval
	// path: it is the second half of ADR-009 invariant 1 ("no agent is ever the
	// sole authority for a human-accountable action unless the policy declares a
	// human-free path for that capability and verb AND the work's sponsor has
	// opted in"). The policy half says a human-free path is expressible; this
	// field is what records that the accountable human accepted it for THIS
	// work. Without it the gateway refuses a requirement a policy could satisfy
	// with no human at all.
	//
	// The zero value is the absence of the opt-in, which is what every work
	// written before this field existed carries: autonomy is earned, never
	// assumed.
	HumanFreeApproval bool
	// HumanFreeApprovalSponsor is the subject of the accountable human who opted
	// in. It must BE the work's Sponsor: "the work's sponsor has opted in" is the
	// invariant, and an opt-in from anyone else would be a different principal
	// granting autonomy over work they do not answer for. The field is kept
	// beside the boolean rather than inferred from Sponsor so a reader of a
	// record written when a different sponsor held the work cannot misattribute
	// the decision.
	HumanFreeApprovalSponsor string
	// HumanFreeApprovalAt is when the sponsor opted in. It is set by the work
	// store at the moment the opt-in is recorded, never by a caller, and it is
	// required whenever HumanFreeApproval is true: an opt-in with no time is an
	// opt-in nobody can place against the decisions taken under it.
	HumanFreeApprovalAt time.Time
	// Deadline bounds the work. After it, the work accepts no more spend.
	Deadline time.Time
	// Depth is the delegation depth, capped so a chain cannot multiply budgets.
	Depth int
	// RequiredApprovals names the capabilities or action classes that need a
	// recorded human approval within this work.
	RequiredApprovals []string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Revision          uint64 // increments on every transition; replay depends on it
}

// Remaining returns the unspent budget.
func (w Work) Remaining() float64 { return w.BudgetUSD - w.CommittedUSD }

// Validate enforces the invariants that make work governable.
func (w Work) Validate() error {
	if w.WorkID == "" || w.TenantID == "" {
		return fmt.Errorf("types: work requires WorkID and TenantID")
	}
	if w.Sponsor == "" {
		return fmt.Errorf("types: work %q requires an accountable manager", w.WorkID)
	}
	if w.BudgetUSD < 0 || !finite(w.BudgetUSD) {
		return fmt.Errorf("types: work %q has a negative budget", w.WorkID)
	}
	if w.CommittedUSD < 0 || !finite(w.CommittedUSD) {
		return fmt.Errorf("types: work %q has a negative committed amount", w.WorkID)
	}
	if w.CommittedUSD > w.BudgetUSD {
		return fmt.Errorf("types: work %q has committed %.2f above its budget %.2f", w.WorkID, w.CommittedUSD, w.BudgetUSD)
	}
	if w.Depth < 0 || w.Depth > DefaultMaxDelegationDepth {
		return fmt.Errorf("types: work %q has delegation depth %d, cap is %d", w.WorkID, w.Depth, DefaultMaxDelegationDepth)
	}
	return w.validateHumanFreeApproval()
}

// validateHumanFreeApproval checks the sponsor opt-in. It is all-or-nothing,
// and it can only come from the work's own sponsor. A boolean with no subject,
// a subject with no time, or a subject who is not the accountable human would
// each read as an opt-in while naming nobody answerable for it -- the
// permissive direction, on the one field that removes a human from the loop.
func (w Work) validateHumanFreeApproval() error {
	if w.HumanFreeApproval {
		switch {
		case w.HumanFreeApprovalSponsor == "":
			return fmt.Errorf("types: work %q carries an automated approval with no manager; autonomy must name the accountable person who granted it", w.WorkID)
		case w.HumanFreeApprovalSponsor != w.Sponsor:
			return fmt.Errorf("types: work %q has accountable manager %q and its automated approval names %q; only the accountable manager may record that approval",
				w.WorkID, w.Sponsor, w.HumanFreeApprovalSponsor)
		case w.HumanFreeApprovalAt.IsZero():
			return fmt.Errorf("types: work %q carries an automated approval opt-in with no time; an opt-in nobody can place against the decisions taken under it is not evidence", w.WorkID)
		}
	} else if w.HumanFreeApprovalSponsor != "" || !w.HumanFreeApprovalAt.IsZero() {
		return fmt.Errorf("types: work %q names the manager of an automated approval, or its time, without the approval itself; the approval is one act, recorded whole or not at all", w.WorkID)
	}
	return nil
}
