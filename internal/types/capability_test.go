package types

import "testing"

// Egress matching must be exact apart from case. A suffix or substring rule
// would let evil-example.com satisfy an example.com allowlist, which is the
// single most likely way an egress control silently stops controlling anything.
func TestEgressAllowedIsExactAndCaseInsensitive(t *testing.T) {
	c := Capability{
		CapabilityID:    "payments.send",
		Version:         "1.0.0",
		RiskTier:        R3RiskTier,
		Owner:           "ops",
		EgressAllowlist: []string{"api.example.com", "example.com:8443"},
	}

	allowed := []string{"api.example.com", "API.EXAMPLE.COM", "Api.Example.Com", "example.com:8443"}
	for _, h := range allowed {
		if !c.EgressAllowed(h) {
			t.Fatalf("EgressAllowed(%q) = false, want true", h)
		}
	}

	refused := []string{
		"evil-example.com",        // suffix attack
		"api.example.com.evil.io", // prefix then suffix
		"notapi.example.com",      // substring
		"example.com.evil.test",
		"example.com",      // the bare host is not the port-qualified entry
		"example.com:9999", // wrong port
		"",                 // empty authority
	}
	for _, h := range refused {
		if c.EgressAllowed(h) {
			t.Fatalf("EgressAllowed(%q) = true, want false", h)
		}
	}
}

// A tool with no allowlist permits nothing. Empty must never read as "anywhere".
func TestEgressAllowedEmptyAllowlistPermitsNothing(t *testing.T) {
	c := Capability{CapabilityID: "x", Version: "1.0.0", Owner: "o", RiskTier: R3RiskTier}
	for _, h := range []string{"example.com", "localhost", ""} {
		if c.EgressAllowed(h) {
			t.Fatalf("empty allowlist permitted %q", h)
		}
	}
}

func TestValidateRefusesR3ToolWithoutAllowlist(t *testing.T) {
	c := Capability{CapabilityID: "pay", Version: "1.0.0", Kind: CapTool, RiskTier: R3RiskTier, Owner: "o"}
	if err := c.Validate(); err == nil {
		t.Fatal("an R3 tool with a nil allowlist was accepted")
	}
	// A skill is not an executable and is not subject to the egress rule.
	s := Capability{CapabilityID: "how-to-pay", Version: "1.0.0", Kind: CapSkill, RiskTier: R3RiskTier, Owner: "o"}
	if err := s.Validate(); err != nil {
		t.Fatalf("an R3 skill was refused: %v", err)
	}
}
