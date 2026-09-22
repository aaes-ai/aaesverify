package types

import (
	"net/url"
	"time"
)

// Capability is one registered thing an actor may do: a tool that acts, or a
// skill that describes how to act. Version is pinned; floating "latest" is not
// representable.
type Capability struct {
	CapabilityID string
	Kind         CapabilityKind
	Version      string
	Source       string // signed or audited origin
	RiskTier     RiskTier
	DataClass    DataClassification
	// Actions are the verbs this capability may perform. An empty list is not
	// the empty permission: a capability that declares no verbs behaves as
	// invoke, which is how every capability registered before this field
	// existed keeps working, and a caller that then names a different verb is
	// refused.
	//
	// Every DECLARED verb carries a floor (Action.MinTier) and the registered
	// RiskTier may not sit below the highest of them: policy may raise a tier,
	// a registration may not understate one. An empty list is left at the
	// registered tier, because raising it to the invoke floor would
	// retroactively refuse every pre-existing R0/R1 registration; a capability
	// that wants the invoke floor declares invoke.
	Actions []Action
	// ResourceID names the resource this capability acts on. Empty means none is
	// declared, which is allowed only below PII: a capability whose data class
	// is pii, phi or financial must name the resource it touches, because
	// otherwise the decision records a class with no object and the register of
	// record cannot answer "which data can this actor reach".
	ResourceID     string
	CostCeilingUSD float64
	// EgressAllowlist restricts where a tool may send data. Empty means nowhere,
	// not everywhere: a tool with no allowlist cannot make an outbound call.
	EgressAllowlist []string
	// Endpoint is the destination this capability is bound to. It belongs here
	// and not in the request, because a caller that can name a destination can
	// exfiltrate to anywhere, and the egress allowlist then only constrains
	// honest callers. Registered and reviewed once, used every time.
	Endpoint string
	// Method is the HTTP method for an HTTP-bound tool. Ignored for skills.
	Method string
	// RequiresReview is true for procedural knowledge that a human must review
	// before deployment, and for third-party tools whose descriptions are
	// themselves an injection vector.
	RequiresReview bool
	Owner          string // accountable human
	SecretRefID    string // set only for credentialed tools
	Inject         Injection
	InjectName     string
	// Custody is how the credential for this capability is obtained, and it is
	// the fact that decides whether an action under this capability was ENFORCED
	// or merely OBSERVED. It belongs here rather than only on a wiring-time
	// binding, because a receipt must be able to state which one it was without
	// consulting the deployment that happened to run it.
	//
	// The zero value is CustodyInline, which is the enforced model, so a
	// capability built without thought is governed rather than silently
	// observational. A capability that should be observed must say so.
	Custody      CustodyKind
	RegisteredAt time.Time
	// ResultMode says what happens to the rail's response body. The zero value
	// is ResultDigest, which is today's behaviour and every pre-field
	// registration, so the field is additive. It is registration data like
	// Endpoint: a caller never names it.
	//
	// The json tags are additive: no field of this struct carried a tag before
	// this one, and a pre-field capability marshals with no result keys at all,
	// so a view that serialises a capability directly is unchanged for every
	// registration that does not use the result path.
	ResultMode ResultMode `json:"result_mode,omitempty"`
	// ResultResourceID is the registered resource at which a rendezvous
	// capability's output is expected. It is required for ResultRendezvous (a
	// rendezvous that names no location has no location to return) and refused
	// for every other mode (a location with digest mode is configuration that
	// reads as if content landing somewhere were governed, and it is not).
	ResultResourceID string `json:"result_resource_id,omitempty"`
	// ResultAck is the accountable acknowledgement that makes
	// ResultInlineBounded available to a capability registered for a regulated
	// data class. Nil means none was declared, which is the only honest value
	// for a capability over public or internal data.
	ResultAck *ResultAcknowledgement `json:"result_ack,omitempty"`
	// Sign is how the resolved credential becomes an authenticated request.
	// The zero value is SignNone — verbatim injection, which is today's
	// behaviour and every registration written before this field existed — so
	// the field is additive. It is registration data like Endpoint: a caller
	// never names it, and a connector that cannot honour the registered mode
	// refuses rather than falling back to an unsigned call.
	Sign SigningMode `json:"sign,omitempty"`
	// SignRegion and SignService are the optional explicit SigV4 credential
	// scope (e.g. "us-east-1" and "iam"). Both are set or neither is; when
	// both are empty the connector derives the scope from the registered
	// endpoint host and refuses a host it cannot derive one from. They are
	// refused beside SignNone, where they would be configuration AAES silently
	// ignored.
	SignRegion  string `json:"sign_region,omitempty"`
	SignService string `json:"sign_service,omitempty"`
}

// ResultAcknowledgementOwner returns the accountable owner recorded for an
// inline result over regulated data, or "" when none was declared. It is a
// helper so a receipt or a console line cannot read a nil acknowledgement as an
// empty one.
func (c Capability) ResultAcknowledgementOwner() string {
	if c.ResultAck == nil {
		return ""
	}
	return c.ResultAck.Owner
}

// EndpointAuthority returns the host[:port] of the bound endpoint, which is what
// the egress allowlist is compared against.
func (c Capability) EndpointAuthority() (string, error) {
	if c.Endpoint == "" {
		return "", errf("capability %q has no endpoint", c.CapabilityID)
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return "", errf("capability %q has an unparseable endpoint: %w", c.CapabilityID, err)
	}
	// The registered locator must be absolute and name a host; the ALLOWLIST is
	// compared against that host. The scheme's vocabulary belongs to the
	// connector, not to this layer: an HTTP capability must be http(s) with a
	// method the HTTP connector executes, a SQL capability names a DSN and an
	// operation of "query" or "exec", and this layer cannot tell them apart
	// because the capability does not carry its connector. Requiring http(s)
	// here is what made a governed SQL write impossible to register: a write is
	// R2, so it reached this check and was refused for naming its own destination
	// and its own operation.
	if u.Scheme == "" {
		return "", errf("capability %q endpoint is not absolute (no scheme); the registered destination must name a scheme and a host", c.CapabilityID)
	}
	// Credentials in the authority are refused at REGISTRATION, not only at call
	// time. The connector refuses them too, but by then the endpoint has already
	// been printed by the CLI and written to the registry file, which is operator
	// data that gets copied, mailed and committed: a password there is a password
	// in a place nobody treats as a secret. The credential belongs in custody,
	// and the endpoint names a destination, nothing else.
	if u.User != nil {
		return "", errf("capability %q endpoint carries credentials in its authority; the credential belongs in custody, not in the registered URL", c.CapabilityID)
	}
	if u.Host == "" {
		return "", errf("capability %q endpoint has no host", c.CapabilityID)
	}
	return u.Host, nil
}

// EffectiveActions are the verbs a decision under this capability may name.
//
// A capability that declares no verbs behaves as invoke: it is the registered
// tool, called as a tool, which is exactly today's behaviour. The default is
// the NARROWEST verb rather than the union of everything the capability might
// do, so a caller that then names write is refused rather than grandfathered
// in.
//
// The returned slice is a copy. A caller that could mutate it could widen a
// registered permission from the outside, and a registration is the one thing
// that must not be editable through a getter.
func (c Capability) EffectiveActions() []Action {
	if len(c.Actions) == 0 {
		return []Action{ActionInvoke}
	}
	out := make([]Action, len(c.Actions))
	copy(out, c.Actions)
	return out
}

// IsCredentialed reports whether using this capability requires a brokered secret.
func (c Capability) IsCredentialed() bool { return c.SecretRefID != "" }

// EgressAllowed reports whether a destination authority is permitted for this
// tool. A tool with no allowlist permits nothing.
//
// Matching is case-insensitive because host names are, and it is EXACT: a
// suffix or substring match would let evil-example.com satisfy an example.com
// allowlist. The entry may include a port ("example.com:8443"), in which case
// only that port is satisfied.
//
// This helper exists for registration-time validation, the CLI and tests; the
// enforcement point is the connector, which parses the request URL and passes
// url.URL.Host. An earlier version compared with ==, so it was case-sensitive
// and a caller passing "EXAMPLE.com" would have been denied by a rule that
// reads as if it should pass. The connector worked around it rather than
// relying on it, which is exactly the kind of trap this package should not
// contain.
func (c Capability) EgressAllowed(authority string) bool {
	for _, h := range c.EgressAllowlist {
		if ASCIIEqualFold(h, authority) {
			return true
		}
	}
	return false
}

// ASCIIEqualFold compares two authority strings case-insensitively over ASCII
// ONLY, and is the single authoritative host comparison in the system.
//
// Unicode folding is wrong for host names, and dangerously so: strings.EqualFold
// folds U+212A (KELVIN SIGN) to "k" and U+017F (LATIN SMALL LETTER LONG S) to
// "s", so a non-ASCII host would satisfy an ASCII allowlist entry while the
// wire host is a different name. It also has to be the SAME function
// everywhere: while registration validated with Unicode folding and the
// connector enforced with ASCII folding, a capability could pass Validate and
// then be denied on every call, which contradicts the rule that an unreachable
// tool cannot be registered. Divergence in a control's matching rule is how a
// control silently stops controlling.
func ASCIIEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiLower(a[i]) != asciiLower(b[i]) {
			return false
		}
	}
	return true
}

func asciiLower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
