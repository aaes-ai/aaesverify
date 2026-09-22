package types

import (
	"strings"
	"testing"
	"time"
)

func validResource() Resource {
	return Resource{
		ResourceID: "res-payments",
		TenantID:   "tenant-a",
		Kind:       ResTable,
		Locator:    "payments.transactions",
		DataClass:  DataPII,
		Owner:      "human-ops",
		Residency:  "eu",
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
	}
}

// Validate refuses a resource missing any dimension a sealed decision would
// record, because a registration with a hole in it produces evidence with a
// hole in it. The valid case is asserted first so a later rule cannot make the
// whole type unregistrable without this test saying which rule did it.
func TestResourceValidateRequiresEveryDimension(t *testing.T) {
	if err := validResource().Validate(); err != nil {
		t.Fatalf("a fully specified resource was refused: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*Resource)
		want string
	}{
		{"no id", func(r *Resource) { r.ResourceID = "  " }, "ResourceID"},
		{"no tenant", func(r *Resource) { r.TenantID = "" }, "TenantID"},
		{"no owner", func(r *Resource) { r.Owner = " " }, "Owner"},
		{"no locator", func(r *Resource) { r.Locator = "  " }, "locator"},
		{"unknown kind", func(r *Resource) { r.Kind = ResourceKind(99) }, "kind"},
		{"unknown class", func(r *Resource) { r.DataClass = DataClassification(42) }, "classification"},
	}
	for _, tc := range cases {
		r := validResource()
		tc.mut(&r)
		err := r.Validate()
		if err == nil {
			t.Fatalf("%s: an incomplete resource was accepted", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: refusal %q does not name %s", tc.name, err, tc.want)
		}
	}
	// A public resource with no locator is still refused: the locator is what
	// the owner reviewed, not a PII-only requirement.
	r := validResource()
	r.Locator = ""
	if err := r.Validate(); err == nil {
		t.Fatal("a resource with no locator was accepted")
	}
}

// The kind parse is case-insensitive and trimmed, and a failed parse must not
// return a real kind: the zero value is ResBucket, and filing a resource under
// the one kind nobody asked for is how a register of record stops being one.
func TestParseResourceKindIsCaseInsensitiveAndFailClosed(t *testing.T) {
	for _, k := range ResourceKindVocabulary() {
		for _, spelling := range []string{k.String(), strings.ToUpper(k.String()), " " + k.String() + " "} {
			got, ok := ParseResourceKind(spelling)
			if !ok || got != k {
				t.Fatalf("ParseResourceKind(%q) = %s, %v; want %s, true", spelling, got, ok, k)
			}
		}
	}
	for _, raw := range []string{"", "bucket list", "s3", "mcp-server"} {
		got, ok := ParseResourceKind(raw)
		if ok {
			t.Fatalf("ParseResourceKind(%q) reported a known kind %s", raw, got)
		}
		if got != ResourceKindUnspecified {
			t.Fatalf("ParseResourceKind(%q) = %s beside a failed parse; want %s", raw, got, ResourceKindUnspecified)
		}
		if got.String() == ResBucket.String() {
			t.Fatalf("ParseResourceKind(%q) rendered as a real kind", raw)
		}
	}
	want := []ResourceKind{
		ResBucket, ResTable, ResQueue, ResRepo, ResSite, ResMailbox,
		ResChannel, ResNumber, ResMCPServer, ResGraph, ResAPI,
		ResBrowserProfile, ResDesktop,
	}
	if len(ResourceKindVocabulary()) != len(want) {
		t.Fatalf("ResourceKindVocabulary() has %d kinds, want %d", len(ResourceKindVocabulary()), len(want))
	}
	for i, k := range want {
		if ResourceKindVocabulary()[i] != k {
			t.Fatalf("ResourceKindVocabulary()[%d] = %s, want %s", i, ResourceKindVocabulary()[i], k)
		}
	}
	if got := ResourceKind(99).String(); got != "unknown(99)" {
		t.Fatalf("ResourceKind(99).String() = %q, want unknown(99)", got)
	}
}
