package types

import (
	"strings"
	"testing"
)

// resultCapability is a registrable capability with the result field under test.
// It is deliberately the R2 tool shape so the result rules are exercised beside
// the endpoint rules rather than instead of them.
func resultCapability(mode ResultMode, class DataClassification) Capability {
	c := Capability{
		CapabilityID:    "reports.export",
		Kind:            CapTool,
		Version:         "1.0.0",
		Owner:           "ops@example.com",
		RiskTier:        R2RiskTier,
		DataClass:       class,
		Endpoint:        "https://rail.example.com/v1/export",
		Method:          "POST",
		EgressAllowlist: []string{"rail.example.com"},
		ResultMode:      mode,
	}
	if class >= DataPII {
		c.ResourceID = "res-reports"
	}
	return c
}

// The zero value is today's behaviour. Every capability registered before the
// field existed carries it, so a zero value that meant anything else would
// change the meaning of every existing registration.
func TestResultModeZeroValueIsDigest(t *testing.T) {
	var zero ResultMode
	if zero != ResultDigest {
		t.Fatalf("the zero ResultMode is %s, want digest", zero)
	}
	if got := zero.String(); got != "digest" {
		t.Fatalf("zero.String() = %q, want digest", got)
	}
	if !zero.Valid() {
		t.Fatal("the zero value reports itself invalid; every pre-field capability carries it")
	}
	// A capability that never mentions the field must validate exactly as it did.
	if err := resultCapability(ResultDigest, DataInternal).Validate(); err != nil {
		t.Fatalf("a pre-field capability no longer validates: %v", err)
	}
}

// The vocabulary round-trips, and a spelling outside it is refused BESIDE a
// false boolean rather than folded into digest.
func TestParseResultModeRoundTripsAndRefusesUnknown(t *testing.T) {
	for _, mode := range ResultModes() {
		got, ok := ParseResultMode(mode.String())
		if !ok || got != mode {
			t.Fatalf("ParseResultMode(%q) = %s/%v, want %s/true", mode.String(), got, ok, mode)
		}
		if _, ok := ParseResultMode("  " + strings.ToUpper(mode.String()) + " "); !ok {
			t.Fatalf("ParseResultMode did not accept %q case-insensitively", mode.String())
		}
	}
	for _, raw := range []string{"", "stream", "inline", "in line_bounded", "inline-bounded", "RENDEZVOUS!", "0"} {
		got, ok := ParseResultMode(raw)
		if ok {
			t.Fatalf("ParseResultMode(%q) accepted an unknown mode as %s", raw, got)
		}
	}
	if vocabulary := ResultModeVocabulary(); !strings.Contains(vocabulary, "inline_bounded") || !strings.Contains(vocabulary, "rendezvous") {
		t.Fatalf("the vocabulary omits a mode: %q", vocabulary)
	}
}

// A value off the end of the enum is refused by name: it was reviewed by nobody.
func TestCapabilityRefusesAnUnknownResultMode(t *testing.T) {
	c := resultCapability(ResultMode(9), DataInternal)
	err := c.Validate()
	if err == nil {
		t.Fatal("a capability with an undefined result mode validated")
	}
	if !strings.Contains(err.Error(), "unknown result mode") || !strings.Contains(err.Error(), "unknown(9)") {
		t.Fatalf("the refusal does not name the mode: %v", err)
	}
	if !strings.Contains(err.Error(), "digest") || !strings.Contains(err.Error(), "rendezvous") {
		t.Fatalf("the refusal does not name the vocabulary: %v", err)
	}
}

// Regulated data does not go out inline because nobody objected. The refusal has
// to say WHY, because an operator reading it is the person who can fix it.
func TestInlineBoundedOnRegulatedDataRequiresAnAcknowledgement(t *testing.T) {
	for _, class := range []DataClassification{DataPII, DataPHI, DataFinancial} {
		c := resultCapability(ResultInlineBounded, class)
		err := c.Validate()
		if err == nil {
			t.Fatalf("%s data with inline_bounded and no acknowledgement validated", class)
		}
		for _, want := range []string{"inline_bounded", class.String(), "acknowledgement", "result_ack_owner", "result_ack_reason"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal for %s does not mention %q: %v", class, want, err)
			}
		}
	}
	// The same capability with the accountable owner and the reason is a
	// reviewed decision rather than a default.
	for _, class := range []DataClassification{DataPII, DataPHI, DataFinancial} {
		c := resultCapability(ResultInlineBounded, class)
		c.ResultAck = &ResultAcknowledgement{Owner: "dpo@example.com", Reason: "the report is redacted before it leaves the rail"}
		if err := c.Validate(); err != nil {
			t.Fatalf("%s data with an acknowledgement did not validate: %v", class, err)
		}
	}
	// Public and internal data need none: the rule is about regulated classes,
	// not about the mode.
	if err := resultCapability(ResultInlineBounded, DataInternal).Validate(); err != nil {
		t.Fatalf("internal data with inline_bounded and no acknowledgement was refused: %v", err)
	}
}

// An acknowledgement missing either half is not an acknowledgement.
func TestIncompleteAcknowledgementIsRefused(t *testing.T) {
	for name, ack := range map[string]*ResultAcknowledgement{
		"no owner":  {Reason: "because"},
		"no reason": {Owner: "dpo@example.com"},
		"blank":     {Owner: "  ", Reason: "  "},
	} {
		c := resultCapability(ResultInlineBounded, DataPII)
		c.ResultAck = ack
		if err := c.Validate(); err == nil {
			t.Fatalf("an acknowledgement with %s validated", name)
		}
	}
}

// Rendezvous has nothing to return without a location, so a registration that
// names none is refused rather than becoming a call that returns no reference.
func TestRendezvousRequiresAResultResource(t *testing.T) {
	c := resultCapability(ResultRendezvous, DataInternal)
	err := c.Validate()
	if err == nil {
		t.Fatal("rendezvous with no result_resource_id validated")
	}
	if !strings.Contains(err.Error(), "rendezvous") || !strings.Contains(err.Error(), "result_resource_id") {
		t.Fatalf("the refusal does not name the mode and the missing field: %v", err)
	}
	c.ResultResourceID = "res-exports"
	if err := c.Validate(); err != nil {
		t.Fatalf("rendezvous with a location did not validate: %v", err)
	}
}

// A location on a mode that returns no location is configuration AAES would
// otherwise ignore, which is how a reviewer comes to believe a governed handoff
// exists.
func TestResultResourceIsRefusedOutsideRendezvous(t *testing.T) {
	for _, mode := range []ResultMode{ResultDigest, ResultInlineBounded} {
		c := resultCapability(mode, DataInternal)
		c.ResultResourceID = "res-exports"
		err := c.Validate()
		if err == nil {
			t.Fatalf("a location with result mode %s validated", mode)
		}
		if !strings.Contains(err.Error(), "result_resource_id") {
			t.Fatalf("the refusal for %s does not name the field: %v", mode, err)
		}
	}
}

// The acknowledgement exists only for inline_bounded; beside another mode it
// reads as an approval for something that does not happen.
func TestAcknowledgementIsRefusedOutsideInlineBounded(t *testing.T) {
	for _, mode := range []ResultMode{ResultDigest, ResultRendezvous} {
		c := resultCapability(mode, DataPII)
		c.ResourceID = "res-reports"
		if mode == ResultRendezvous {
			c.ResultResourceID = "res-exports"
		}
		c.ResultAck = &ResultAcknowledgement{Owner: "dpo@example.com", Reason: "reviewed"}
		if err := c.Validate(); err == nil {
			t.Fatalf("an acknowledgement with result mode %s validated", mode)
		}
	}
}

// ResultAcknowledgementOwner distinguishes "no acknowledgement" from an
// acknowledgement with an empty owner, so a reader cannot mistake one for the
// other through a nil dereference.
func TestResultAcknowledgementOwnerReadsNilAsEmpty(t *testing.T) {
	if got := (Capability{}).ResultAcknowledgementOwner(); got != "" {
		t.Fatalf("a capability with no acknowledgement reported owner %q", got)
	}
	c := Capability{ResultAck: &ResultAcknowledgement{Owner: "dpo@example.com"}}
	if got := c.ResultAcknowledgementOwner(); got != "dpo@example.com" {
		t.Fatalf("ResultAcknowledgementOwner = %q", got)
	}
}
