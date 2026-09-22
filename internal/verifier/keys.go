package verifier

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParsePublicKey accepts a hex or base64 Ed25519 public key, with optional
// surrounding whitespace and an optional "ed25519:" prefix.
func ParsePublicKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "ed25519:")
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	return nil, fmt.Errorf("verifier: not a %d-byte hex or base64 Ed25519 public key", ed25519.PublicKeySize)
}

// ParseSeed accepts a hex or base64 Ed25519 private seed.
func ParseSeed(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.SeedSize {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.SeedSize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == ed25519.SeedSize {
		return b, nil
	}
	return nil, fmt.Errorf("verifier: not a %d-byte hex or base64 Ed25519 seed", ed25519.SeedSize)
}
