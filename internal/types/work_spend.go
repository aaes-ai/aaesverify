package types

import (
	"fmt"
	"time"
)

// HumanFreeApprovalUsable reports whether this work carries a sponsor opt-in a
// decision may rely on, and returns the sponsor and the moment it was granted.
func (w Work) HumanFreeApprovalUsable() (string, time.Time, bool) {
	if !w.HumanFreeApproval || w.HumanFreeApprovalSponsor == "" || w.HumanFreeApprovalSponsor != w.Sponsor || w.HumanFreeApprovalAt.IsZero() {
		return "", time.Time{}, false
	}
	return w.HumanFreeApprovalSponsor, w.HumanFreeApprovalAt.UTC(), true
}

// CanSpend reports whether an amount may be committed right now, and why not.
func (w Work) CanSpend(amount float64, now time.Time) error {
	if !w.State.AcceptsSpend() {
		return fmt.Errorf("work %q is %s and accepts no further spend", w.WorkID, w.State)
	}
	if !w.Deadline.IsZero() && now.After(w.Deadline) {
		return fmt.Errorf("work %q passed its deadline at %s", w.WorkID, w.Deadline.UTC().Format(time.RFC3339))
	}
	if amount < 0 || !finite(amount) {
		return fmt.Errorf("work %q: a negative or non-finite amount is not a spend", w.WorkID)
	}
	if !finite(w.BudgetUSD) || !finite(w.CommittedUSD) {
		return fmt.Errorf("work %q has a non-finite budget or committed amount", w.WorkID)
	}
	if w.Remaining() < amount {
		return fmt.Errorf("work %q has %.2f remaining of %.2f and cannot cover %.2f",
			w.WorkID, w.Remaining(), w.BudgetUSD, amount)
	}
	return nil
}
