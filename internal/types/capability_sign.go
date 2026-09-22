package types

import "strings"

// SigningMode is how a credentialed capability turns stored material into an
// authenticated request. The zero value is SignNone, which is today's
// behaviour and every registration written before the field existed: the
// resolved material is injected verbatim at the declared injection point.
//
// The mode is registration data, exactly like Endpoint: a caller never names
// it, because a mode the caller could choose would let the caller decide
// whether the credential leaves AAES transformed or verbatim.
type SigningMode int

const (
	// SignNone means no signing step: custody resolves one value and the
	// connector injects it as stored.
	SignNone SigningMode = iota
	// SignAWSV4 means AWS Signature Version 4: the stored material is the
	// documented access_key_id/secret_access_key/session_token document, and
	// the connector computes the Authorization header per request from it
	// instead of injecting anything verbatim. The scope the signature is bound
	// to is the capability's SignRegion and SignService, or the scope derived
	// from the registered endpoint when those are empty.
	SignAWSV4
)

// String renders the wire spelling of the mode.
func (s SigningMode) String() string {
	switch s {
	case SignAWSV4:
		return "aws-v4"
	case SignNone:
		return ""
	}
	return "unknown"
}

// ParseSigningMode maps a wire spelling onto the mode. The empty string is
// SignNone, so an entry that never mentions signing parses to the behaviour it
// was written under. The second return value reports whether the spelling is
// one AAES defines: an unknown mode is refused rather than folded into
// SignNone, because folding it would execute UNSIGNED a capability its author
// declared signed.
func ParseSigningMode(raw string) (SigningMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return SignNone, true
	case "aws-v4":
		return SignAWSV4, true
	}
	return SignNone, false
}

// Valid reports whether the value is one of the defined modes.
func (s SigningMode) Valid() bool {
	switch s {
	case SignNone, SignAWSV4:
		return true
	}
	return false
}

// SigningVocabulary renders the closed signing-mode list for an error message.
func SigningVocabulary() string {
	return "aws-v4"
}

// validateSigning checks the signing mode against the rest of the
// registration. The rules exist so a signed capability cannot be registered in
// a shape that would execute unsigned or misattributed:
//
//   - the mode must be one AAES defines;
//   - a signing mode signs WITH a credential, so a secret reference is
//     required;
//   - aws-v4 computes the Authorization header, so the declared injection
//     point must be exactly that header: any other point would read as if the
//     material went somewhere the signer does not put it;
//   - the scope override is both fields or neither, because a half-named
//     scope is configuration nobody can review.
func (c Capability) validateSigning() error {
	if !c.Sign.Valid() {
		return errf("capability %q names an unknown signing mode %d; AAES refuses to name a signing mode it does not define (want one of %s)",
			c.CapabilityID, int(c.Sign), SigningVocabulary())
	}
	if c.Sign == SignNone {
		if strings.TrimSpace(c.SignRegion) != "" || strings.TrimSpace(c.SignService) != "" {
			return errf("capability %q names a signing scope but no signing mode; a scope without a mode is configuration AAES would silently ignore",
				c.CapabilityID)
		}
		return nil
	}
	if strings.TrimSpace(c.SecretRefID) == "" {
		return errf("capability %q declares signing mode %s but no secret reference; a signing mode signs with the stored credential, so the reference is required",
			c.CapabilityID, c.Sign)
	}
	if c.Inject != InjectHeader || !ASCIIEqualFold(c.InjectName, "Authorization") {
		return errf("capability %q declares signing mode %s with injection %s %q; aws-v4 computes the Authorization header per request, so the injection point must be exactly header Authorization",
			c.CapabilityID, c.Sign, c.Inject, c.InjectName)
	}
	region, service := strings.TrimSpace(c.SignRegion), strings.TrimSpace(c.SignService)
	if (region == "") != (service == "") {
		return errf("capability %q names half of a signing scope (region %q, service %q); the override is sign_region and sign_service together or neither",
			c.CapabilityID, c.SignRegion, c.SignService)
	}
	for _, value := range []string{region, service} {
		for _, r := range value {
			if r < 0x21 || r > 0x7e {
				return errf("capability %q names a signing scope value that is not a printable token; the scope is part of the signature and must be exact",
					c.CapabilityID)
			}
		}
	}
	return nil
}
