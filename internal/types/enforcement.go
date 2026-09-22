package types

import "fmt"

// Enforcement is the ONE honesty label a permission carries. It answers a
// different question from custody: custody says where the credential lives,
// Enforcement says what AAES can actually do about a refusal.
//
// # The three labels
//
//   - Enforced: AAES holds or issues the credential for this permission, and a
//     refusal prevents the effect. This is the only label that may support a
//     coverage claim, and even then only when the rail confirms the execution.
//   - Observed: the actor holds the credential and AAES records the decision
//     without being able to prevent the call. pass_through custody is always
//     observed, never enforced, and an observation counts toward NO coverage
//     numerator.
//   - Inventory: the permission is registered so it can be reviewed, owned and
//     reported, but no live enforcement path exists yet. Inventory is a
//     product -- a register of record -- but it is never sold as control.
//
// A permission plane that claims to control what it cannot is worse than no
// plane at all, because the claim is the product. That is why the label is
// computed here and nowhere else.
type Enforcement int

const (
	// Enforced means a wired path resolves the credential and makes the call,
	// so a refusal prevents the effect.
	Enforced Enforcement = iota
	// Observed means AAES records the decision but cannot prevent the call.
	Observed
	// Inventory means the permission is registered and reviewable with no live
	// enforcement path.
	Inventory
)

func (e Enforcement) String() string {
	switch e {
	case Enforced:
		return "enforced"
	case Observed:
		return "observed"
	case Inventory:
		return "inventory"
	}
	return fmt.Sprintf("unknown(%d)", int(e))
}

// EnforcementFor is the single source of truth for the label the console, the
// API and any report must print. A caller must NEVER compute this itself: a
// second computation is a second answer, and the audit that produced ADR-008
// found exactly that class of failure -- a custody label read from the wiring
// rather than from the registration, green in the test suite.
//
// The mapping has three rules and no defaults:
//
//   - pass_through custody is ALWAYS Observed. The actor holds the credential,
//     so AAES can record the decision and cannot prevent the call, whatever the
//     deployment claims about a live path. Naming a live path does not
//     manufacture a credential AAES does not hold.
//   - an ENFORCING custody model with livePath true is Enforced: there is a
//     wired path that resolves the credential and makes the call, so a refusal
//     stops it.
//   - everything else is Inventory: registered, reviewable, reported, no live
//     enforcement path. That includes an enforcing custody model with no wired
//     path (registered but not wired), and a custody value off the end of the
//     vocabulary, which is not proof of enforcement either (understating
//     coverage is the safe direction).
//
// livePath is a fact about the deployment, never a caller's claim: it says a
// path was wired, not that someone asserted one.
func EnforcementFor(custody CustodyKind, livePath bool) Enforcement {
	if custody == CustodyPassThrough {
		return Observed
	}
	// A recorded custody value is a string in the journal, so it is parsed back
	// rather than trusted as a number: a value no version of this package
	// defined must read as inventory, not as enforcement.
	kind, known := ParseCustodyKind(custody.String())
	if !known || !kind.Enforcement() {
		return Inventory
	}
	if !livePath {
		return Inventory
	}
	return Enforced
}
