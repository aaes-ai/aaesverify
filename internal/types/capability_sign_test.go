package types

import (
	"strings"
	"testing"
)

// signingCapability is a valid aws-v4 registration; each test below breaks
// exactly one rule and expects Validate to name it.
func signingCapability() Capability {
	return Capability{
		CapabilityID: "aws.iam.users.list",
		Kind:         CapTool,
		Version:      "1.0.0",
		RiskTier:     R0RiskTier,
		Owner:        "ops",
		SecretRefID:  "secret-ref-aws-key-pair",
		Inject:       InjectHeader,
		InjectName:   "Authorization",
		Sign:         SignAWSV4,
	}
}

// TestValidateSigningMode locks the registration rules that keep a signed
// capability from being registered in a shape that would execute unsigned or
// misattributed.
func TestValidateSigningMode(t *testing.T) {
	if err := signingCapability().Validate(); err != nil {
		t.Fatalf("a valid aws-v4 registration was refused: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(c *Capability)
		wantErr string
	}{
		{"an unknown mode", func(c *Capability) { c.Sign = SigningMode(42) }, "unknown signing mode"},
		{"no secret reference", func(c *Capability) { c.SecretRefID = "" }, "no secret reference"},
		{"a query injection point", func(c *Capability) { c.Inject = InjectQuery; c.InjectName = "key" },
			"injection point must be exactly header Authorization"},
		{"a different header", func(c *Capability) { c.InjectName = "X-Api-Key" },
			"injection point must be exactly header Authorization"},
		{"half of a scope", func(c *Capability) { c.SignRegion = "us-east-1" }, "half of a signing scope"},
		{"the other half of a scope", func(c *Capability) { c.SignService = "iam" }, "half of a signing scope"},
		{"a scope with no mode", func(c *Capability) {
			c.Sign = SignNone
			c.SignRegion, c.SignService = "us-east-1", "iam"
		}, "a scope without a mode"},
		{"a scope that is not a token", func(c *Capability) {
			c.SignRegion, c.SignService = "us east 1", "iam"
		}, "not a printable token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := signingCapability()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("%s: accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%s: error = %v, want it to name %q", tc.name, err, tc.wantErr)
			}
		})
	}

	// The explicit scope is valid when it is whole, and the injection point
	// match is case-insensitive because header names are.
	c := signingCapability()
	c.SignRegion, c.SignService = "us-east-1", "iam"
	c.InjectName = "authorization"
	if err := c.Validate(); err != nil {
		t.Fatalf("a whole explicit scope was refused: %v", err)
	}
}

// TestParseSigningMode locks the wire vocabulary: the empty spelling is the
// pre-field behaviour, aws-v4 is the one mode, and anything else is refused
// rather than folded into unsigned execution.
func TestParseSigningMode(t *testing.T) {
	for _, spelling := range []string{"", "  ", "aws-v4", "AWS-V4"} {
		if _, ok := ParseSigningMode(spelling); !ok {
			t.Fatalf("ParseSigningMode(%q) refused the vocabulary", spelling)
		}
	}
	if mode, _ := ParseSigningMode("aws-v4"); mode != SignAWSV4 {
		t.Fatalf("ParseSigningMode(aws-v4) = %v", mode)
	}
	if mode, _ := ParseSigningMode(""); mode != SignNone {
		t.Fatalf("ParseSigningMode(empty) = %v, want SignNone", mode)
	}
	for _, spelling := range []string{"aws-v5", "none", "sigv4", "0"} {
		if _, ok := ParseSigningMode(spelling); ok {
			t.Fatalf("ParseSigningMode(%q) accepted an unknown mode", spelling)
		}
	}
	if got := SignAWSV4.String(); got != "aws-v4" {
		t.Fatalf("SignAWSV4.String() = %q", got)
	}
	if got := SignNone.String(); got != "" {
		t.Fatalf("SignNone.String() = %q, want empty so unsigned entries round-trip", got)
	}
	if SigningMode(42).Valid() || !SignNone.Valid() || !SignAWSV4.Valid() {
		t.Fatal("Valid disagrees with the vocabulary")
	}
}
