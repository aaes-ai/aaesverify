package types

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// ActorKind distinguishes agents from humans. Both are first-class actors.
type ActorKind int

const (
	KindAgent ActorKind = iota
	KindHuman
)

func (k ActorKind) String() string {
	if k == KindHuman {
		return "human"
	}
	return "agent"
}

// ActorRef is a Directory entry for an agent or a human.
type ActorRef struct {
	ActorID    string
	Kind       ActorKind
	Role       string
	TenantID   string
	Sponsor    string  // accountable human; REQUIRED for agents
	TrustScore float64 // 0..1 rolling eval pass rate; never a guarantee on novel tasks
	// Subject is the operator's stable subject at the customer's identity
	// provider (the OIDC "sub" claim, or the directory's immutable id). It is
	// what a login asserts and what the record names, and it is separate from
	// ActorID because an organisation may key its directory by a mail alias
	// while the provider's subject never changes. Empty means the actor was
	// registered before the field existed, or has no identity-provider account
	// (an agent, or a locally seeded sponsor).
	Subject string
	// Groups are the identity-provider groups the operator was imported from,
	// in the order the directory returned them. They are kept on the actor so a
	// refusal can name the mapped role and an access review can say which group
	// carried it, instead of the mapping being a fact only the import ran with.
	Groups []string
	// Roles are the operator roles this human carries on the operator surfaces
	// (types.Role). They are resolved from Groups at import time and re-resolved
	// by the identity policy when an admin changes the mapping; they are stored
	// on the actor so the console's gate reads the directory rather than
	// re-deriving a mapping on every request.
	Roles []Role
	// Model is the AI model this actor was registered with, at three levels of
	// identity and with the source of the claim. It lives on the actor because
	// the actor is what the directory knows: the gateway cannot observe which
	// model ran, so it records the registration, and a request can never supply
	// a different one. An actor registered with no model keeps the unknown ref,
	// which is why none of this is required -- every deployment that predates the
	// field still registers.
	Model ModelRef
	// ExternalRefs are the attributed external identifiers the actor was
	// registered with (for example its Entra Agent ID, when the deployment
	// mapped one). They are CORRELATION DATA, never trust material: they let
	// an auditor join a sealed record to the customer's own registry export,
	// and they never count as a witness, never feed --require-independent and
	// never change the enforcement label. The directory stamps every entry
	// AsRegistered at registration time, exactly as it stamps the model, and
	// an actor registered with none keeps the empty slice, which is what every
	// deployment that predates the field carries.
	ExternalRefs []ExternalRef
	// Managers is the ordered manager SET: several humans, several other agents,
	// or a mix. It is EMPTY on every actor registered before it existed, and an
	// empty set is read through the single Sponsor field (see
	// EffectiveManagers), which is what keeps every such actor behaving exactly
	// as it did.
	//
	// The order is the routing order and the first entry is asked first. An
	// agent with one manager in this set behaves exactly as it did with the
	// single field: that entry is the first entry.
	Managers ManagerSet
	// ManagersSource says how Managers came to be: nothing recorded (the single
	// Sponsor field, ManagerSourceLegacy), a one-entry set MATERIALISED from the
	// single field on a write (ManagerSourceSingle), or a set an operator
	// declared (ManagerSourceSet). It is recorded so a reader of the actor, and
	// of every sealed record the actor's decisions carry, can tell a set that
	// was declared from one AAES derived -- without either being reinterpreted.
	ManagersSource ManagerSource
	// ReportsTo is the human this human reports to. Routing only; Authorize never reads it.
	ReportsTo string
	// TeamID is the agent team this agent belongs to, when it belongs to one.
	// Empty on humans and on agents registered before teams existed.
	TeamID string
	// Away is true when this human is out and their Successor may decide.
	Away bool
	// Successor is the human who may decide while Away is true. Routing only.
	Successor string
}

// Validate enforces the manager invariant for agents.
//
// An agent needs at least one accountable manager, named either in the single
// manager field (every existing registration) or in the set. When BOTH are
// present they must agree on who the primary accountable manager is: a record
// that says two different things about who answers for the agent is refused
// rather than resolved by preference, because either reading would be a guess
// about a control.
func (a ActorRef) Validate() error {
	if a.ActorID == "" || a.TenantID == "" {
		return fmt.Errorf("types: actor requires ActorID and TenantID")
	}
	if err := a.ManagersSource.Validate(); err != nil {
		return fmt.Errorf("types: actor %q: %w", a.ActorID, err)
	}
	if a.Kind == KindAgent {
		if err := a.validateAgentManagers(); err != nil {
			return err
		}
	} else if len(a.Managers) > 0 {
		return fmt.Errorf("types: actor %q is a %s and carries a manager set; only an agent is managed",
			a.ActorID, a.Kind)
	}
	if a.Kind == KindHuman && strings.TrimSpace(a.TeamID) != "" {
		return fmt.Errorf("types: actor %q is a named person and carries a team_id; only an agent belongs to a team", a.ActorID)
	}
	// The model is validated for shape at registration, so a malformed identity
	// is refused by the directory rather than sealed onto a decision later. A
	// zero Model is valid: it is the unknown case.
	if err := a.Model.Validate(); err != nil {
		return fmt.Errorf("types: actor %q has an unusable model identity: %w", a.ActorID, err)
	}
	if a.TrustScore < 0 || a.TrustScore > 1 {
		return fmt.Errorf("types: trust score must be within [0,1], got %v", a.TrustScore)
	}
	return a.validateGroupsAndRoles()
}

// validateAgentManagers enforces the manager invariant for an agent: at least
// one accountable manager, named in the single field or in the set, and -- when
// both are present -- agreement on who the primary accountable manager is.
func (a ActorRef) validateAgentManagers() error {
	if strings.TrimSpace(a.Sponsor) == "" && len(a.Managers) == 0 {
		return fmt.Errorf("types: agent %q requires an accountable manager", a.ActorID)
	}
	if a.Away || strings.TrimSpace(a.Successor) != "" {
		return fmt.Errorf("types: agent %q carries away or successor; only a named person may be out", a.ActorID)
	}
	if len(a.Managers) > 0 {
		if err := a.Managers.Validate(a.ActorID); err != nil {
			return err
		}
		if strings.TrimSpace(a.Sponsor) != "" {
			primary, ok := a.Managers.Primary()
			if !ok || strings.TrimSpace(primary.ActorID) != strings.TrimSpace(a.Sponsor) {
				return fmt.Errorf("types: agent %q sponsor %q does not match the manager set's primary accountable manager", a.ActorID, a.Sponsor)
			}
		}
	} else if err := SingleManagerSet(a.Sponsor, KindHuman).Validate(a.ActorID); err != nil {
		// The single field is validated through the same set rule, so the two
		// shapes cannot disagree about what a manager must be.
		return err
	}
	return nil
}

// Scope is authority granted to an actor over one capability.
type Scope struct {
	Capability string
	MaxTier    RiskTier
	// SpendCapUSD bounds ONE action under this scope, in US dollars.
	//
	// ZERO means "no per-task cap is declared" and is deliberate, not an
	// oversight: every deployment that predates caps registers scopes with no
	// cap, and reading zero as a zero-dollar budget would refuse all of them
	// rather than tighten anything. The dangerous direction is the other one --
	// a NEGATIVE cap, which the old comparison (cap > 0) silently read as
	// unlimited -- so a negative cap is refused at registration by Validate. A
	// NaN or an infinity is refused for the same reason: it compares false
	// against every bound and so behaves as unlimited.
	SpendCapUSD  float64
	RequiresDual bool
	// Actions restricts the verbs this scope may perform. Empty keeps today's
	// behaviour -- no restriction beyond the verbs the capability itself
	// declares -- so every actor registered before this field existed keeps
	// working.
	Actions []Action
	// ResourceIDs restricts the resources this scope may touch. Empty means no
	// restriction. A non-empty list is the set of resource ids the actor may
	// name under this scope; an id that is empty or whitespace restricts
	// nothing while reading as if it did, so it is refused.
	ResourceIDs []string
	// DataClasses restricts the data classes this scope may touch. Empty means
	// no restriction.
	DataClasses []DataClassification
}

// Validate enforces what can be known about a scope before it is registered.
//
// It lives on the type rather than in one registry so a second registration path
// cannot enforce a weaker rule than the first: two entry points that disagree
// about what a scope may contain is how a control stops controlling.
func (s Scope) Validate() error {
	if strings.TrimSpace(s.Capability) == "" {
		return fmt.Errorf("types: scope requires a capability")
	}
	if s.MaxTier < R0RiskTier || s.MaxTier > MaxRiskTier {
		return fmt.Errorf("types: scope %q has an invalid tier %d", s.Capability, int(s.MaxTier))
	}
	if math.IsNaN(s.SpendCapUSD) || math.IsInf(s.SpendCapUSD, 0) {
		return fmt.Errorf("types: scope %q has a non-finite spend cap %v, which compares false against every bound and would read as unlimited",
			s.Capability, s.SpendCapUSD)
	}
	if s.SpendCapUSD < 0 {
		return fmt.Errorf("types: scope %q has a negative spend cap %.2f; a negative cap is not a budget, and treating it as unlimited is the opposite of what it looks like",
			s.Capability, s.SpendCapUSD)
	}
	// The three restriction lists share one rule: empty means unrestricted,
	// which is the behaviour every existing registration has. A list that is
	// present is a restriction and is validated as one, because a restriction
	// AAES cannot read is worse than none -- it reads as if it narrowed
	// something.
	if err := checkActions(fmt.Sprintf("types: scope %q", s.Capability), s.Actions); err != nil {
		return err
	}
	for i, id := range s.ResourceIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("types: scope %q names an empty resource id at index %d; an empty resource id restricts nothing while reading as if it did",
				s.Capability, i)
		}
	}
	for i, d := range s.DataClasses {
		if !d.Valid() {
			return fmt.Errorf("types: scope %q names an unknown data classification %d at index %d; a classification AAES cannot name is not one it may record as public",
				s.Capability, int(d), i)
		}
	}
	return nil
}

// Grant is a task-scoped, time-limited, non-transferable credential.
type Grant struct {
	GrantID         string
	ActorID         string
	TenantID        string
	Capability      string
	Tier            RiskTier
	TaskID          string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	SpendCapUSD     float64
	NonTransferable bool
	// BudgetGrantID names the PERIOD BUDGET grant the decision was taken
	// against: the per-actor ceiling surface.Spend.Decide read beside the work
	// budget and the capability's cost ceiling. It is empty when no grant
	// applied, which is what every deployment that registers no period budget
	// has always had.
	//
	// It is ON the credential rather than only in the journal because the
	// credential is what the executor presents: a spend that crosses the grant
	// later has a name, and an operator can answer "under which budget" from the
	// artifact the call carried rather than only from the sealed record.
	BudgetGrantID string
	Issuer        string // signing key identifier, bound into the signature
	Signature     []byte
}

// GrantMaterial is the exact byte material covered by a grant signature. The
// spend ceiling, tier, TTL and the period budget the decision was taken against
// are all inside it: a signed grant whose spend cap sits outside the signature
// is a bearer token with a decorative field, and a budget attribution outside it
// could be rewritten by anyone who holds the token.
func (g Grant) GrantMaterial() []any {
	return []any{
		g.GrantID, g.ActorID, g.TenantID, g.Capability, g.Tier.String(), g.TaskID,
		g.IssuedAt.UTC().Format(time.RFC3339Nano), g.ExpiresAt.UTC().Format(time.RFC3339Nano),
		g.SpendCapUSD, g.NonTransferable, g.BudgetGrantID, g.Issuer,
	}
}

// TTL returns the grant lifetime.
func (g Grant) TTL() time.Duration { return g.ExpiresAt.Sub(g.IssuedAt) }

// Valid reports whether the grant is unexpired, non-transferable and attributed.
func (g Grant) Valid(now time.Time) bool {
	if !g.NonTransferable || g.GrantID == "" || g.ActorID == "" {
		return false
	}
	return now.Before(g.ExpiresAt) && !now.Before(g.IssuedAt)
}

// MaxGrantTTL is the hard ceiling for any grant. ADR-004.
const MaxGrantTTL = 15 * time.Minute
