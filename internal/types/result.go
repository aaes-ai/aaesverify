package types

import (
	"fmt"
	"strings"
)

// ResultMode names what a brokered call does with the rail's RESPONSE BODY.
//
// The decision, the receipt and the Outcome have always described an effect
// without its content: the body is read once, digested and discarded, so an
// agent in a locked-down estate that reads through AAES receives evidence that
// a read happened and none of the data it read. That is coherent for a write and
// incoherent for a read, and this field is the per-capability answer to it.
//
// The mode is REGISTRATION data, exactly like the endpoint and the egress
// allowlist. A caller never names it, because a caller that could choose
// "return the bytes" could turn every capability into an exfiltration path.
//
// The zero value is ResultDigest, which is what every capability registered
// before this field existed means, so the field is additive: a registration that
// does not mention it behaves byte-for-byte as it did.
type ResultMode int

const (
	// ResultDigest is the default and today's behaviour: the body is read once
	// under the response bound, digested, and discarded. The caller receives the
	// digest and never the content, and this package stores nothing.
	ResultDigest ResultMode = iota
	// ResultInlineBounded returns the body to the caller of the brokered call,
	// and only to that caller, under a size cap, a content-type allowlist, a
	// bounded timeout and a no-store rule. Nothing is cached, logged or recorded:
	// the sealed receipt carries a marker (bytes, content type, digest) and never
	// the content.
	ResultInlineBounded
	// ResultRendezvous means the call produces its output somewhere the caller
	// already has access to: an object-store path, a queue, a mailbox. AAES
	// records the effect and the LOCATION as a registered resource id, returns
	// the location reference, and never holds the payload.
	ResultRendezvous
)

// String renders the mode as the spelling registrations and receipts use. A
// value off the end of the enum renders as unknown(N) rather than as the
// nearest defined mode, because a mode AAES cannot name is not a mode it may
// silently treat as the default.
func (m ResultMode) String() string {
	switch m {
	case ResultDigest:
		return "digest"
	case ResultInlineBounded:
		return "inline_bounded"
	case ResultRendezvous:
		return "rendezvous"
	}
	return fmt.Sprintf("unknown(%d)", int(m))
}

// Valid reports whether the value is one of the defined modes. Like
// DataClassification.Valid, it exists because an unset or undecodable value must
// be refused rather than folded into the zero value: the zero value is the safe
// direction here (nothing is returned), but a value off the end of the enum was
// never reviewed by anyone, and Capability.Validate refuses it by name.
func (m ResultMode) Valid() bool {
	switch m {
	case ResultDigest, ResultInlineBounded, ResultRendezvous:
		return true
	}
	return false
}

// ResultModes lists every mode, in declaration order, so a parser or a renderer
// cannot silently omit one.
func ResultModes() []ResultMode {
	return []ResultMode{ResultDigest, ResultInlineBounded, ResultRendezvous}
}

// ParseResultMode maps a recorded mode back to its value. Matching is
// case-insensitive and surrounding whitespace is ignored, so "Inline_Bounded"
// and "inline_bounded" are one mode.
//
// On failure the returned mode is ResultDigest BESIDE a false boolean. The mode
// is the zero value because a Go caller has to have something, and the boolean
// is what a caller must test: a parser that treated "false" as "digest" would
// turn a typo in a registration file into the silent default.
func ParseResultMode(raw string) (ResultMode, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	for _, m := range ResultModes() {
		if m.String() == trimmed {
			return m, true
		}
	}
	return ResultDigest, false
}

// ResultModeVocabulary renders the closed set for an error message, so a
// refusal names every value that would have been accepted.
func ResultModeVocabulary() string {
	names := make([]string, 0, len(ResultModes()))
	for _, m := range ResultModes() {
		names = append(names, m.String())
	}
	return strings.Join(names, ", ")
}

// ResultAcknowledgement is an accountable human's explicit acceptance that a
// capability registered for a REGULATED data class returns content inline.
//
// The acknowledgement is a fact of the registration, not a runtime flag: it
// names WHO accepted it and WHY, so a later reader of the registry can ask the
// person and read the reason. It is required only for inline_bounded on pii,
// phi or financial data; a capability over public or internal data needs none,
// and adding one to a capability that does not return content inline is
// configuration that reads as an approval for something that does not happen.
type ResultAcknowledgement struct {
	// Owner is the accountable human's id: the same vocabulary as
	// Capability.Owner. An acknowledgement with no owner is not accountable.
	Owner string `json:"owner"`
	// Reason is why returning this class inline is acceptable. It is recorded,
	// never interpreted.
	Reason string `json:"reason"`
}
