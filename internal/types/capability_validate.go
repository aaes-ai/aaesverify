package types

import (
	"fmt"
	"strings"
)

// Validate enforces the invariants that make a capability governable.
func (c Capability) Validate() error {
	if c.CapabilityID == "" || c.Version == "" {
		return errf("capability requires CapabilityID and Version")
	}
	if c.Owner == "" {
		return errf("capability %q requires an accountable owner", c.CapabilityID)
	}
	if err := c.validateTierAndDataClass(); err != nil {
		return err
	}
	if _, known := ParseCustodyKind(c.Custody.String()); !known {
		return errf("capability %q names an unknown custody model %q", c.CapabilityID, c.Custody.String())
	}
	if err := c.validateResultPath(); err != nil {
		return err
	}
	if err := c.validateSigning(); err != nil {
		return err
	}
	if err := c.validateToolWiring(); err != nil {
		return err
	}
	return nil
}

// validateTierAndDataClass checks the registered tier, the data classification
// and the floors a declared verb imposes on both.
func (c Capability) validateTierAndDataClass() error {
	if c.RiskTier < R0RiskTier || c.RiskTier > MaxRiskTier {
		return errf("capability %q has an invalid risk tier", c.CapabilityID)
	}
	if !c.DataClass.Valid() {
		return errf("capability %q has an unknown data classification %d; a classification AAES cannot name is not a classification it may record as public",
			c.CapabilityID, int(c.DataClass))
	}
	// The verb list is checked before the floor below, because a floor computed
	// over an invalid verb is a number attached to nothing.
	if err := checkActions(fmt.Sprintf("capability %q", c.CapabilityID), c.Actions); err != nil {
		return err
	}
	// Regulated data needs an object. A capability that says "I touch PII" and
	// names no resource forces every later reader to infer what it touched from
	// the registration, which is the inference the sealed intent exists to
	// remove.
	if c.DataClass >= DataPII && strings.TrimSpace(c.ResourceID) == "" {
		return errf("capability %q is registered for %s data and names no resource; a capability that touches PII, PHI or financial data must name the resource it touches, because the decision records the resource and class it was taken against",
			c.CapabilityID, c.DataClass)
	}
	// The floor of a declared verb binds the registration. RiskTier is what
	// policy, the scope cap and the approval gate compare against, so a
	// capability registered below the floor of a verb it declares would be
	// governed more cheaply than the verb itself allows.
	if carrier, floor, ok := actionFloor(c.Actions); ok && c.RiskTier < floor {
		return errf("capability %q declares the action %q whose minimum tier is %s but is registered at %s; a tier may be raised above the minimum tier for a declared action and never set below it",
			c.CapabilityID, carrier, floor, c.RiskTier)
	}
	return nil
}

// validateResultPath checks the registered result mode, its acknowledgement and
// its rendezvous location.
func (c Capability) validateResultPath() error {
	// The result path is validated at REGISTRATION, in the same place as the
	// endpoint and the allowlist, because a mode the platform cannot honour must
	// not become registrable and then fail on every call after the effect has
	// already happened.
	if !c.ResultMode.Valid() {
		return errf("capability %q names an unknown result mode %s; AAES refuses to name a result path it does not define (want one of %s)",
			c.CapabilityID, c.ResultMode, ResultModeVocabulary())
	}
	if ack := c.ResultAck; ack != nil {
		switch {
		case strings.TrimSpace(ack.Owner) == "":
			return errf("capability %q carries a result acknowledgement with no owner; an acknowledgement is a person accepting a risk, and one with nobody named is not accountable",
				c.CapabilityID)
		case strings.TrimSpace(ack.Reason) == "":
			return errf("capability %q carries a result acknowledgement with no reason; the acknowledgement is the record of WHY regulated content is returned inline, and a blank reason records nothing",
				c.CapabilityID)
		case c.ResultMode != ResultInlineBounded:
			return errf("capability %q declares result mode %s and carries an acknowledgement, which exists only for inline_bounded; an acknowledgement beside a mode that returns no content reads as an approval for something that does not happen",
				c.CapabilityID, c.ResultMode)
		}
	}
	location := strings.TrimSpace(c.ResultResourceID)
	switch c.ResultMode {
	case ResultInlineBounded:
		if location != "" {
			return errf("capability %q declares result mode inline_bounded and names result_resource_id %q; a result location belongs to rendezvous, and carrying one here reads as a governed handoff that never happens",
				c.CapabilityID, location)
		}
		// The one rule that makes inline content a decision rather than a
		// default: regulated data does not leave AAES inline because nobody
		// objected. Somebody has to have accepted it, by name, with a reason,
		// and that acceptance is part of the registration a reviewer reads.
		if c.DataClass >= DataPII && c.ResultAck == nil {
			return errf("capability %q is registered for %s data and declares result mode inline_bounded without an acknowledgement; returning regulated content inline puts AAES in the data path and hands the caller bytes the class was registered to keep in place, so it is refused unless the registration names the accountable owner and the reason in result_ack_owner and result_ack_reason",
				c.CapabilityID, c.DataClass)
		}
	case ResultRendezvous:
		if location == "" {
			return errf("capability %q declares result mode rendezvous and names no result_resource_id; a rendezvous returns a LOCATION instead of a payload, and a registration that names none has no location to return",
				c.CapabilityID)
		}
	default:
		if location != "" {
			return errf("capability %q declares result mode %s and names result_resource_id %q; the location is meaningful only for rendezvous, and carrying one for a mode that returns no location is configuration AAES would silently ignore",
				c.CapabilityID, c.ResultMode, location)
		}
	}
	return nil
}

// validateToolWiring checks the credentialed tool's destination, operation and
// egress allowlist.
func (c Capability) validateToolWiring() error {
	if c.Kind == CapTool && c.RiskTier >= R3RiskTier && c.EgressAllowlist == nil {
		return errf("tool %q reaches R3+ without an egress allowlist; empty is not the same as unrestricted", c.CapabilityID)
	}
	if c.SecretRefID != "" && c.InjectName == "" {
		return errf("capability %q has a secret but no injection point", c.CapabilityID)
	}
	if c.Kind == CapTool && c.RiskTier >= R2RiskTier {
		if c.Endpoint == "" {
			return errf("tool %q reaches R2+ without an endpoint; the destination must be registered, never supplied by a caller", c.CapabilityID)
		}
		if !isRegisteredOperation(c.Method) {
			return errf("tool %q has an endpoint but no usable registered operation, got %q", c.CapabilityID, c.Method)
		}
		// The registered destination must itself pass the egress allowlist.
		// Otherwise a tool could be registered with an endpoint it is not
		// permitted to reach, and the failure would only appear at call time.
		authority, err := c.EndpointAuthority()
		if err != nil {
			return err
		}
		if !c.EgressAllowed(authority) {
			return errf("tool %q endpoint authority %q is not in its own egress allowlist %v",
				c.CapabilityID, authority, c.EgressAllowlist)
		}
	}
	return nil
}

// isRegisteredOperation reports whether an operation is registered in a shape a
// connector can execute.
//
// It is deliberately vocabulary-free. This layer cannot know whether the
// capability is bound to HTTP ("GET", "POST"), SQL ("query", "exec"), an MCP
// tool name, a CLI command or a browser action, and a universal vocabulary here
// would either refuse a legitimate connector or accept a name no connector
// implements. Before this check existed in this shape, the HTTP vocabulary was
// enforced at the domain layer, which made a governed SQL write impossible to
// register: a write is R2 and could not name the driver's own operation.
//
// What this layer enforces is that an operation IS registered, bounded and
// printable. The CONNECTOR refuses a name outside its own vocabulary at the
// moment it runs, and the registration/binding cross-check refuses a binding
// whose operation disagrees with the registration.
func isRegisteredOperation(m string) bool {
	if m == "" || len(m) > 64 {
		return false
	}
	for _, r := range m {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
