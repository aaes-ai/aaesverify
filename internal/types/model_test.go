package types

import (
	"strings"
	"testing"
)

// TestModelRefValidateShape pins the shape rules. The point of validating shape
// only is that no provider list exists here: the values are opaque, so every
// rule below is about whether the value can be sealed and rendered honestly,
// never about whether it names a real model.
func TestModelRefValidateShape(t *testing.T) {
	cases := []struct {
		name    string
		ref     ModelRef
		wantErr string
	}{
		{"unknown ref", UnknownModel(), ""},
		{"zero ref", ModelRef{}, ""},
		{"empty with empty source", ModelRef{Provider: "", Family: "", Model: "", Source: ""}, ""},
		{"whitespace reads as empty", ModelRef{Provider: "   ", Family: "	", Model: " "}, ""},
		{"registered triple", RegisteredModel("example_provider", "example_family", "example_model_1"), ""},
		{"namespaced model is legal", RegisteredModel("meta", "llama_3", "meta-llama/Llama-3.1_8B"), ""},
		{
			"provider only is incomplete",
			ModelRef{Provider: "example_provider", Source: ModelSourceRegistered},
			"incomplete; missing Family, Model",
		},
		{
			"provider and family without a model is incomplete",
			ModelRef{Provider: "example_provider", Family: "example_family", Source: ModelSourceRegistered},
			"incomplete; missing Model",
		},
		{
			"family without a provider is incomplete",
			ModelRef{Family: "example_family", Model: "example_model_1", Source: ModelSourceRegistered},
			"incomplete; missing Provider",
		},
		{
			"a complete identity must say where it came from",
			ModelRef{Provider: "example_provider", Family: "example_family", Model: "example_model_1"},
			"carries no source",
		},
		{
			"a complete identity cannot be labelled unknown",
			ModelRef{Provider: "example_provider", Family: "example_family", Model: "example_model_1", Source: ModelSourceUnknown},
			"labels its source",
		},
		{
			"an unrecognised source is refused",
			ModelRef{Provider: "example_provider", Family: "example_family", Model: "example_model_1", Source: "guessed"},
			"unknown model source",
		},
		{
			"an empty identity cannot claim a registration",
			ModelRef{Source: ModelSourceRegistered},
			"nothing was registered to attribute",
		},
		{
			"an empty identity cannot claim a registration with padding",
			ModelRef{Provider: "  ", Source: ModelSourceRegistered},
			"nothing was registered to attribute",
		},
		{
			"over-long provider",
			RegisteredModel(strings.Repeat("p", MaxModelIdentityLen+1), "example_family", "example_model_1"),
			"bound is 64",
		},
		{
			"over-long family",
			RegisteredModel("example_provider", strings.Repeat("f", MaxModelIdentityLen+1), "example_model_1"),
			"bound is 64",
		},
		{
			"over-long model",
			RegisteredModel("example_provider", "example_family", strings.Repeat("m", MaxModelIdentityLen+1)),
			"bound is 64",
		},
		{"space inside a level", RegisteredModel("example provider", "example_family", "example_model_1"), "only letters, digits"},
		{"colon inside a level", RegisteredModel("example_provider", "example:family", "example_model_1"), "only letters, digits"},
		{"at sign inside a level", RegisteredModel("example_provider", "example_family", "example@model"), "only letters, digits"},
		{"newline inside a level", RegisteredModel("example_provider", "example_family", "example\nmodel"), "only letters, digits"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ref.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate(%s) = %v, want nil", tc.ref, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate(%s) = nil, want an error containing %q", tc.ref, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestModelRefTrimIsNotSilentReduction is the failure mode the constructor would
// have if it folded a partial declaration into "unknown": the deployment would
// believe it had registered a model that nothing recorded.
func TestModelRefTrimIsNotSilentReduction(t *testing.T) {
	partial := RegisteredModel("example_provider", "", "")
	if partial.Known() {
		t.Fatal("a partial identity reads as known")
	}
	if partial.Source != ModelSourceRegistered {
		t.Fatalf("a partial identity lost its source: %q", partial.Source)
	}
	if err := partial.Validate(); err == nil {
		t.Fatal("a partial identity was accepted; a half answer to 'which model' must be refused, not recorded as unknown")
	}
	if got := RegisteredModel("  ", "	", " "); got != UnknownModel() {
		t.Fatalf("a declaration of only whitespace = %+v, want the unknown ref", got)
	}
}

func TestRegisteredModelTrimsAndStamps(t *testing.T) {
	got := RegisteredModel("  example_provider ", " example_family	", "example_model_1  ")
	want := ModelRef{Provider: "example_provider", Family: "example_family", Model: "example_model_1", Source: ModelSourceRegistered}
	if got != want {
		t.Fatalf("RegisteredModel = %+v, want %+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("trimmed identity is not valid: %v", err)
	}
}

// TestModelRefStringIsStable pins the rendering: an identity with its source, or
// "unknown". The seal covers the four fields individually, so this is a display
// contract, but a display contract that changes silently is a log-comparison
// bug.
func TestModelRefStringIsStable(t *testing.T) {
	cases := []struct {
		ref  ModelRef
		want string
	}{
		{UnknownModel(), "unknown"},
		{ModelRef{}, "unknown"},
		{RegisteredModel("example_provider", "example_family", "example_model_1"), "example_provider/example_family/example_model_1 (registered)"},
		{ModelRef{Provider: "example_provider", Family: "example_family", Model: "example_model_1", Source: ModelSourceUnknown}, "example_provider/example_family/example_model_1 (unknown)"},
	}
	for _, tc := range cases {
		if got := tc.ref.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

// TestModelRefMatches is the declaration rule the gateway applies: a caller may
// name any one level or the full identity, and anything else is a different
// model.
func TestModelRefMatches(t *testing.T) {
	ref := RegisteredModel("example_provider", "example_family", "example_model_1")
	for _, ok := range []string{"example_provider", "example_family", "example_model_1", "example_provider/example_family/example_model_1", " example_model_1 "} {
		if !ref.Matches(ok) {
			t.Errorf("Matches(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "   ", "example_model", "example_model_1_flash", "EXAMPLE_MODEL_1", "example_provider/example_family/example_model_2", "example_provider/example_family"} {
		if ref.Matches(bad) {
			t.Errorf("Matches(%q) = true, want false", bad)
		}
	}
	if UnknownModel().Matches("example_model_1") {
		t.Error("the unknown ref matched a declaration; nothing was registered to check it against")
	}
}

func TestAsRegisteredStampsOnlyAKnownIdentity(t *testing.T) {
	known := ModelRef{Provider: "example_provider", Family: "example_family", Model: "example_model_1"}
	if got := known.AsRegistered(); got.Source != ModelSourceRegistered {
		t.Fatalf("AsRegistered did not stamp a known identity: %+v", got)
	}
	unknown := UnknownModel()
	if got := unknown.AsRegistered(); got != unknown {
		t.Fatalf("AsRegistered changed an empty ref: %+v", got)
	}
}

// TestActorRefValidateCarriesTheModelRules proves the directory cannot store a
// malformed identity: ActorRef validation reaches the model rules, so a
// registration is refused at the boundary rather than at seal time.
func TestActorRefValidateCarriesTheModelRules(t *testing.T) {
	base := ActorRef{ActorID: "agent-1", Kind: KindAgent, TenantID: "t1", Sponsor: "human-1", TrustScore: 0.9}
	if err := base.Validate(); err != nil {
		t.Fatalf("an actor with no model must be valid: %v", err)
	}
	base.Model = RegisteredModel("example_provider", "example_family", "example_model_1")
	if err := base.Validate(); err != nil {
		t.Fatalf("an actor with a registered model must be valid: %v", err)
	}
	bad := base
	bad.Model = ModelRef{Provider: "example_provider"}
	err := bad.Validate()
	if err == nil {
		t.Fatal("an actor with a partial model identity was accepted")
	}
	if !strings.Contains(err.Error(), "agent-1") {
		t.Fatalf("error %q does not name the actor", err)
	}
}
