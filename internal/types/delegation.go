package types

import (
	"fmt"
	"math"
	"time"
)

// DelegationContract is a typed handoff between actors. Coordination uses
// structured contracts; fulfillment is verified, not assumed.
type DelegationContract struct {
	ContractID string
	// TenantID scopes the contract. Without it a legacy entry point could only
	// key on the Sponsor, so two tenants reusing a contract identifier would
	// share a record.
	TenantID     string
	FromActor    string
	ToActor      string
	TaskID       string
	InputSchema  string
	OutputSchema string
	BudgetUSD    float64
	Deadline     time.Time
	Sponsor      string // remains accountable for the result
	Depth        int
}

// DefaultMaxDelegationDepth caps hand-off chains.
const DefaultMaxDelegationDepth = 2

// Validate enforces the depth cap and required fields.
//
// Every check fails closed. A negative depth is refused rather than clamped: the
// depth is what caps a hand-off chain, and a value below zero is a chain nobody
// can reason about. A budget that is NaN or infinite is refused because it
// compares false against every bound and so behaves as no budget at all. A
// contract whose target is its own sponsor is refused because the sponsor is the
// human who remains accountable for the result: an actor that sponsors itself is
// an actor whose failures have no owner, which is the state this field exists to
// make impossible.
func (c DelegationContract) Validate() error {
	if c.ContractID == "" || c.FromActor == "" || c.ToActor == "" {
		return fmt.Errorf("types: contract requires ContractID, FromActor and ToActor")
	}
	if c.TenantID == "" {
		return fmt.Errorf("types: contract %q requires a TenantID; an unscoped contract is not attributable", c.ContractID)
	}
	if c.Sponsor == "" {
		return fmt.Errorf("types: contract %q requires a manager who remains accountable", c.ContractID)
	}
	if c.Depth < 0 {
		return fmt.Errorf("types: contract %q has a negative delegation depth %d; depth is what caps a hand-off chain", c.ContractID, c.Depth)
	}
	if c.Depth > DefaultMaxDelegationDepth {
		return fmt.Errorf("types: delegation depth %d exceeds cap %d", c.Depth, DefaultMaxDelegationDepth)
	}
	if math.IsNaN(c.BudgetUSD) || math.IsInf(c.BudgetUSD, 0) {
		return fmt.Errorf("types: contract %q has a non-finite budget %v; a budget that cannot be compared to a bound is not a bound",
			c.ContractID, c.BudgetUSD)
	}
	if c.BudgetUSD < 0 {
		return fmt.Errorf("types: contract %q has a negative budget %.2f", c.ContractID, c.BudgetUSD)
	}
	if c.ToActor == c.Sponsor {
		return fmt.Errorf("types: contract %q names %q as both the accountable manager and the actor who does the work; an actor cannot manage itself",
			c.ContractID, c.Sponsor)
	}
	return nil
}
