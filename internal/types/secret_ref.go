package types

import (
	"time"
)

// SecretRef is a reference to credential material. It deliberately carries no
// plaintext: the gateway and policy engine see references, and only the broker
// resolves one.
type SecretRef struct {
	SecretRefID string
	TenantID    string
	Name        string
	Location    Location
	// Handle names the material inside a provider, e.g. an ARN or a vault path.
	// It is empty for LocInline, where the store owns its own addressing.
	Handle    string
	ExpiresAt time.Time
	CreatedAt time.Time
	RotatedAt time.Time
}

// Expired reports whether the secret should be considered unusable. An expired
// secret fails closed: the broker refuses rather than attempting the call.
func (s SecretRef) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt)
}

func (s SecretRef) Validate() error {
	if s.SecretRefID == "" || s.TenantID == "" || s.Name == "" {
		return errf("secret reference requires SecretRefID, TenantID and Name")
	}
	if s.Location == LocKMS && s.Handle == "" {
		return errf("secret %q is KMS-backed but carries no handle", s.Name)
	}
	return nil
}
