package types

import (
	"strings"
	"testing"
)

// A registered endpoint that carries credentials in its authority is refused at
// REGISTRATION. The connector refuses it at call time too, but by then the URL
// has been printed by the operator CLI and written to the registry file, which
// is copied, mailed and committed: a password there is a password in a place
// nobody treats as a secret. The credential belongs in custody.
func TestCredentialedEndpointIsRefusedAtRegistration(t *testing.T) {
	base := Capability{
		CapabilityID: "wire.transfer", Version: "1.0.0", Kind: CapTool, RiskTier: R3RiskTier,
		Owner: "ops", Method: "POST", EgressAllowlist: []string{"rail.test"},
	}
	for _, tc := range []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{"a plain endpoint is fine", "https://rail.test/v1/effect", false},
		{"a port is fine when the allowlist names it", "https://rail.test:8443/v1/effect", false},
		{"a userinfo component is refused", "https://user:supersecret@rail.test/v1/effect", true},
		{"a bare user is refused too", "https://user@rail.test/v1/effect", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Endpoint = tc.endpoint
			if strings.Contains(tc.endpoint, ":8443") {
				c.EgressAllowlist = []string{"rail.test:8443"}
			}
			err := c.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate accepted %s", tc.endpoint)
				}
				if !strings.Contains(err.Error(), "credentials in its authority") {
					t.Fatalf("refusal = %q, want it to name the credentialed authority", err.Error())
				}
				// The password must not be echoed back, not even in the refusal:
				// an error is one of the places a credential must never appear.
				if strings.Contains(err.Error(), "supersecret") {
					t.Fatalf("the refusal echoes the credential: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate refused %s: %v", tc.endpoint, err)
			}
		})
	}
}
