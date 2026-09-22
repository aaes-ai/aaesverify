package types

import (
	"fmt"
	"time"
)

// ApprovalState is where a required human decision stands.
type ApprovalState int

const (
	ApprovalNotRequired ApprovalState = iota
	ApprovalPending
	ApprovalGranted
	ApprovalRejected
	ApprovalExpired
)

func (a ApprovalState) String() string {
	switch a {
	case ApprovalNotRequired:
		return "not_required"
	case ApprovalPending:
		return "pending"
	case ApprovalGranted:
		return "granted"
	case ApprovalRejected:
		return "rejected"
	case ApprovalExpired:
		return "expired"
	}
	return fmt.Sprintf("unknown(%d)", int(a))
}

// Approval is a decision recorded as a first-class, referenced act.
//
// It exists because the policy layer can only carry booleans about whether an
// approval is needed. A boolean cannot be shown to an examiner, cannot be
// revoked, and cannot say who decided, when, or what they saw.
//
// ADR-009 adds the quorum fields. The record now says WHO decided and IN WHAT
// CAPACITY: ApproverKind is the class of the approver, ApproverAuthority says
// whether the decision is decisive or a recorded recommendation, and an agent
// approver's model identity is recorded beside it. Those fields are written by
// the approval store at decision time and are never taken from a caller.
// Requester, Sponsor, the requester's model identity, the verb and
// ApprovalPolicyID are fixed when the approval is raised, because independence
// and the policy that applied must be facts of the record rather than of the
// state in force later.
//
// Every field added here carries json:",omitempty". The store's hash chain is
// computed over the canonical encoding of this struct, so a field that encoded
// itself when empty would change the hash of every record written before it
// existed and make an upgraded store refuse its own history. An omitted field
// also reads as its zero value, and the zero values here are exactly the old
// semantics: a human, granted.
type Approval struct {
	ApprovalID string
	TenantID   string
	WorkID     string
	// IntentID binds the approval to the specific action it authorises. An
	// approval for one action is not an approval for the next one.
	IntentID string
	// Approver is the actor who decided. Whether that actor may decide is the
	// approval policy's rule, applied by the store against the directory at
	// decision time (ADR-009).
	Approver string
	State    ApprovalState
	Reason   string
	// PayloadHash is the digest of what the approver was shown. It is recorded so
	// "they approved something else" is answerable.
	PayloadHash string
	// BundleHash and EngineVersion pin the policy under which the decision was
	// taken, so a re-decision replays against the same rules.
	BundleHash    string
	EngineVersion string
	// ExpiresAt bounds the approval. An approval is not a standing permission.
	ExpiresAt time.Time
	DecidedAt time.Time
	CreatedAt time.Time

	// --- Set by the approval store at decision time. A request that arrives
	// carrying any of these is refused, because accepting one would let a caller
	// manufacture a capacity no directory confirmed. ---

	// ApproverKind is the class of the approver: human, agent or service. The
	// zero value is Human, which is what every record written before ADR-009
	// was.
	ApproverKind ApproverClass `json:",omitempty"`
	// ApproverAuthority says whether this decision is decisive (granted) or a
	// recorded recommendation that never satisfies a requirement.
	ApproverAuthority ApprovalAuthority `json:",omitempty"`
	// ApproverSponsor is the accountable human of an agent approver, empty for a
	// human. It is recorded because "an agent under the same principal" is an
	// independence rule, and the principal is the sponsor.
	ApproverSponsor string `json:",omitempty"`
	// ApproverModelProvider, ApproverModelFamily and ApproverModel are the model
	// identity the approver was REGISTERED with in the directory. They are set
	// only for an agent approver, and an agent without a complete identity may
	// not approve at all: an approval that cannot say which model gave it is not
	// provenance. ApproverModelSource labels where the identity came from, so the
	// record does not read as observation.
	ApproverModelProvider string `json:",omitempty"`
	ApproverModelFamily   string `json:",omitempty"`
	ApproverModel         string `json:",omitempty"`
	ApproverModelSource   string `json:",omitempty"`

	// --- Fixed when the approval is raised. ---

	// Requester is the actor that proposed the action this approval authorises.
	// Self-approval is refused under every policy, so the store needs this fact
	// on the record rather than inferred from the intent.
	Requester string `json:",omitempty"`
	// RequesterSponsor is the requester's accountable human when the requester
	// is an agent. It is the requester's principal for the independence rule.
	RequesterSponsor string `json:",omitempty"`
	// RequesterModelProvider, RequesterModelFamily and RequesterModel are the
	// model identity the REQUESTER was registered with. Independence includes
	// the model family: an approval from an actor registered with the same
	// family as the requester is correlated, and the comparison is only possible
	// because both identities are on the record.
	RequesterModelProvider string `json:",omitempty"`
	RequesterModelFamily   string `json:",omitempty"`
	RequesterModel         string `json:",omitempty"`
	// Sponsor is the accountable human of the work the action is committed
	// against. "IndependentOf: [sponsor]" is checked against it.
	Sponsor string `json:",omitempty"`
	// RequesterManagers is the manager SET of the requester, sealed when the
	// approval was raised. It is what makes the manager rule countable from the
	// record alone: the store counts approvals it did not witness, and a rule
	// that had to re-read a directory which may since have changed would be
	// counting against a set nobody approved under.
	//
	// It is EMPTY for a requester with no manager set, which is every record
	// written before the set existed and every human requester. The field is
	// omitempty, so an old record still encodes -- and still hashes -- exactly
	// as it did.
	RequesterManagers ManagerSet `json:",omitempty"`
	// RequesterManagersSource says which of the three shapes the set above is:
	// nothing recorded (resolve the single manager field), a one-entry set
	// materialised from that field, or a set an operator declared. A reader
	// therefore never has to guess whether it is looking at a declared set or a
	// derived one.
	RequesterManagersSource ManagerSource `json:",omitempty"`
	// Action is the verb the approval authorises, recorded so the human floor for
	// an irreversible verb can be applied to this intent's quorum by a surface
	// that holds only the record. Empty means the surface that raised the
	// approval named none.
	Action string `json:",omitempty"`
	// ApprovalPolicyID identifies the approval policy that applied when the
	// approval was raised: the canonical hash of the policy, or empty for the
	// deployment default. An approval raised under a different policy does not
	// satisfy a decision taken under another one.
	ApprovalPolicyID string `json:",omitempty"`
}

// Validate enforces that an approval is attributable, bounded, and honest about
// the capacity in which it was decided.
func (a Approval) Validate() error {
	if a.ApprovalID == "" || a.TenantID == "" || a.WorkID == "" {
		return fmt.Errorf("types: approval requires ApprovalID, TenantID and WorkID")
	}
	if a.Approver == "" {
		return fmt.Errorf("types: approval %q has no approver", a.ApprovalID)
	}
	if a.ExpiresAt.IsZero() {
		return fmt.Errorf("types: approval %q never expires; an approval must be bounded", a.ApprovalID)
	}
	if err := a.validateApproverCapacity(); err != nil {
		return err
	}
	// A sealed manager set must be one AAES could have written: at least one
	// accountable manager, no duplicate entry, at most one primary. A record
	// whose set names no accountable manager would make the manager rule
	// uncomputable while reading as if it had one.
	if len(a.RequesterManagers) > 0 {
		if err := a.RequesterManagers.Validate(a.Requester); err != nil {
			return fmt.Errorf("types: approval %q: %w", a.ApprovalID, err)
		}
	}
	if err := a.RequesterManagersSource.Validate(); err != nil {
		return fmt.Errorf("types: approval %q: %w", a.ApprovalID, err)
	}
	// A recorded verb must be one AAES can name. An unnameable verb would make
	// the human floor for an irreversible action uncomputable from the record,
	// and reading it as "not irreversible" is the permissive direction.
	if a.Action != "" {
		if _, ok := ParseAction(a.Action); !ok {
			return fmt.Errorf("types: approval %q records an unknown action %q", a.ApprovalID, a.Action)
		}
	}
	return nil
}

// validateApproverCapacity checks the class, the authority and the model
// identity the decision was recorded with: the facts that say in what capacity
// the approver decided.
func (a Approval) validateApproverCapacity() error {
	if err := a.ApproverKind.Validate(); err != nil {
		return fmt.Errorf("types: approval %q: %w", a.ApprovalID, err)
	}
	if err := a.ApproverAuthority.Validate(); err != nil {
		return fmt.Errorf("types: approval %q: %w", a.ApprovalID, err)
	}
	// An agent approval must carry the model it was registered with. The store
	// refuses an agent approver without one; this restates the rule where a
	// record from any other source is checked, because "which model approved" is
	// the question an agent approval exists to answer.
	if a.ApproverKind == ApproverAgent {
		if a.ApproverModelProvider == "" || a.ApproverModelFamily == "" || a.ApproverModel == "" {
			return fmt.Errorf("types: approval %q was decided by an agent but records no registered model identity", a.ApprovalID)
		}
	}
	return nil
}

// Usable reports whether the approval may authorise this exact action now.
//
// Every check fails closed. An earlier version let an approval whose IntentID was
// empty satisfy any intent, and treated a zero ExpiresAt as "never expires".
// Neither state is reachable through the approval store — it binds every
// approval to one intent and requires a positive TTL — but a helper that is
// lenient in the permissive direction is a trap for whoever reaches for it next.
// An approval authorises one action, or it authorises nothing.
func (a Approval) Usable(intentID string, now time.Time) error {
	if a.State != ApprovalGranted {
		return fmt.Errorf("approval %q is %s", a.ApprovalID, a.State)
	}
	if a.Approver == "" {
		return fmt.Errorf("approval %q is granted but names no approver", a.ApprovalID)
	}
	if a.ExpiresAt.IsZero() {
		return fmt.Errorf("approval %q has no expiry; an unbounded approval is not an approval", a.ApprovalID)
	}
	if now.After(a.ExpiresAt) {
		return fmt.Errorf("approval %q expired at %s", a.ApprovalID, a.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// Exact match with both sides required: an unbound approval authorises
	// nothing rather than everything.
	if a.IntentID == "" || intentID == "" {
		return fmt.Errorf("approval %q and the requested action must both name an intent", a.ApprovalID)
	}
	if a.IntentID != intentID {
		return fmt.Errorf("approval %q authorises a different action", a.ApprovalID)
	}
	return nil
}

// BoundToBundle reports whether this approval was raised under the policy bundle
// a decision is being taken under.
//
// The bundle hash is recorded when the approval is raised, because the human who
// grants it approves the action under the rules in force at that moment. A policy
// bundle is editable; without this check an approval granted under a permissive
// bundle authorises the same intent after the rule that constrained it was
// tightened, which turns the human decision into a decision about a rule set that
// no longer exists.
//
// Fail-closed in both directions. An approval that records no bundle is NOT
// "bound to whatever bundle is current": it is unbound, and an unbound approval
// authorises nothing, so a record written before this field existed cannot
// silently pass. A decision that carries no bundle cannot be checked against one
// and is refused rather than compared against an empty string that an equally
// empty approval would match.
func (a Approval) BoundToBundle(bundleHash string) error {
	if a.BundleHash == "" {
		return fmt.Errorf("approval %q records no policy bundle, so no decision can be shown to have been taken under the rules the approver saw; it must be raised again under the current bundle", a.ApprovalID)
	}
	if bundleHash == "" {
		return fmt.Errorf("this decision records no policy bundle, so approval %q cannot be checked against the rules it was raised under; failing closed", a.ApprovalID)
	}
	if a.BundleHash != bundleHash {
		return fmt.Errorf("approval %q was raised under policy bundle %s but this decision is taken under policy bundle %s; an approval by a person does not carry across a policy change, so the action must be approved under the bundle it will run under",
			a.ApprovalID, a.BundleHash, bundleHash)
	}
	return nil
}
