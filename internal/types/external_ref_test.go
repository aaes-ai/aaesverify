package types

import (
	"strings"
	"testing"
)

// The external reference is the one field whose whole purpose is correlation,
// so its validation is the contract: a registry nobody can interpret, an
// unreadable address, an unattributed claim and an ambiguous mapping are all
// refused before they can reach a sealed record.

func validRef() ExternalRef {
	return ExternalRef{
		Registry: ExternalRegistryEntraAgentID,
		Kind:     "service_principal_object_id",
		Value:    "8f3a2c10-0000-4000-8000-abcdef012345",
		Source:   ExternalRefSourceRegistered,
	}
}

func TestExternalRefValidateAcceptsTheRegisteredShape(t *testing.T) {
	if err := validRef().Validate(); err != nil {
		t.Fatalf("the registered reference was refused: %v", err)
	}
}

func TestExternalRefValidateRefuses(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ExternalRef)
		want string
	}{
		{"an unknown registry", func(r *ExternalRef) { r.Registry = "some_other_registry" }, "some_other_registry"},
		{"an empty registry", func(r *ExternalRef) { r.Registry = "" }, "registry"},
		{"an empty kind", func(r *ExternalRef) { r.Kind = "" }, "kind"},
		{"an empty value", func(r *ExternalRef) { r.Value = "" }, "value"},
		{"an unattributed source", func(r *ExternalRef) { r.Source = "" }, "registered"},
		{"an invented source", func(r *ExternalRef) { r.Source = "verified_live" }, "verified_live"},
		{"a kind that is not printable", func(r *ExternalRef) { r.Kind = "object\tid" }, "printable ASCII"},
		{"a value that is not printable", func(r *ExternalRef) { r.Value = "id\nwith newline" }, "printable ASCII"},
		{"an over-long kind", func(r *ExternalRef) { r.Kind = strings.Repeat("k", maxExternalRefNameBytes+1) }, "bound"},
		{"an over-long value", func(r *ExternalRef) { r.Value = strings.Repeat("v", maxExternalRefValueBytes+1) }, "bound"},
	}
	for _, tc := range cases {
		ref := validRef()
		tc.mut(&ref)
		err := ref.Validate()
		if err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: refusal %q does not name %q", tc.name, err, tc.want)
		}
	}
}

func TestExternalRefAsRegisteredStampsTheSource(t *testing.T) {
	// The directory stamps rather than trusts: a caller-supplied label is
	// contradicted, exactly as with the model identity.
	ref := validRef()
	ref.Source = "verified_live"
	if got := ref.AsRegistered(); got.Source != ExternalRefSourceRegistered {
		t.Fatalf("source = %q, want the stamped %q", got.Source, ExternalRefSourceRegistered)
	}
}

func TestExternalRefMatchesIgnoresTheSourceLabel(t *testing.T) {
	a := validRef()
	b := a
	b.Source = ""
	if !a.Matches(b) {
		t.Fatal("references naming the same object did not match; the source label is AAES's own and plays no part")
	}
	b.Value = "different"
	if a.Matches(b) {
		t.Fatal("references naming different objects matched")
	}
}

func TestExternalRefSourceStringRendersTheUnknownCase(t *testing.T) {
	// An unset source renders as "unknown" so a bug cannot look like a blank
	// field; validation refuses it on a present reference, so no sealed record
	// carries it.
	if got := ExternalRefSource("").String(); got != "unknown" {
		t.Fatalf("empty source renders %q, want %q", got, "unknown")
	}
	if got := ExternalRefSourceRegistered.String(); got != "registered" {
		t.Fatalf("registered source renders %q", got)
	}
}

func TestExternalRegistryVocabularyIsClosedAndSeeded(t *testing.T) {
	if !ValidExternalRegistry(ExternalRegistryEntraAgentID) {
		t.Fatal("the seed registry entra_agent_id is not in the vocabulary")
	}
	if ValidExternalRegistry("entra") || ValidExternalRegistry("ENTRA_AGENT_ID") {
		t.Fatal("a spelling other than the vocabulary's own was accepted")
	}
}
