package types

import "fmt"

// This file holds ExternalRef, the attributed external identifier a sealed
// record may carry beside the AAES actor id (design:
// docs/engineering/ENTRA-AGENT-ID-AWARENESS.md). An external reference is
// CORRELATION DATA, never trust material: it answers an auditor's question --
// "which object in the customer's own registry does this AAES actor correspond
// to?" -- and nothing else. No external registry is a witness, none counts
// toward --require-independent, and the presence of a reference never changes
// the enforcement label, which custody and wiring alone decide.

// ExternalRef is one attributed external identifier: the registry that issued
// it, the kind of object it names within that registry, the registry's own
// value, and the source of the claim. It is deliberately flat strings rather
// than a nested per-registry shape, for the same reason the model identity is:
// the journal's explicit canonical encoder must be able to list every element
// by hand, and a field the encoder cannot see is a field the seal does not
// cover.
type ExternalRef struct {
	// Registry names the external registry, from the closed vocabulary below.
	// The vocabulary is closed but not single-vendor: a new registry is added
	// here, by name, with its falsification tests, never by a deployment
	// spelling something new into a sealed record.
	Registry string `json:"registry"`
	// Kind names the object type within the registry, in the registry's own
	// terms (for entra_agent_id, the service principal object id). It is a
	// bounded name, not a closed vocabulary: kinds are the registry's to
	// define and AAES records rather than legislates them.
	Kind string `json:"kind"`
	// Value is the registry's own identifier. It is an ADDRESS, not a
	// signature: the record asserts that the deployment registered this
	// mapping, and asserts nothing about what the registry says today.
	Value string `json:"value"`
	// Source says where the claim came from, modeled on ModelSource. The only
	// value a record may carry is registered: the mapping came from the actor
	// registration, stamped by the directory at registration time. An
	// unattributed reference would read as observation AAES did not perform,
	// so it is refused rather than recorded.
	Source ExternalRefSource `json:"source"`
}

// ExternalRefSource is AAES's own vocabulary for where an external reference
// came from -- the deployment registers the mapping, and this label records
// what AAES did with it. It is not the registry's vocabulary and no registry
// value may appear here.
type ExternalRefSource string

const (
	// ExternalRefSourceRegistered means the reference is the mapping the actor
	// was REGISTERED with in the directory. It is NOT verification against the
	// live registry: AAES records the registration and does not call the
	// registry on the decision path, exactly as it does not call the model.
	ExternalRefSourceRegistered ExternalRefSource = "registered"
)

// String renders the source label. The zero value renders as "unknown" so an
// unset source cannot be mistaken for a blank field; validation refuses an
// unknown source on a present reference, so a sealed record never carries it.
func (s ExternalRefSource) String() string {
	if s == "" {
		return "unknown"
	}
	return string(s)
}

// The closed registry vocabulary. Seed membership per the Phase B design:
// entra_agent_id is the Microsoft Entra Agent ID registry (a service principal
// with servicePrincipalType=ServiceIdentity under a blueprint application);
// the name matches the identity plane's AgentIdentitySource spelling so a
// record, a principal mapping and an identity adapter name one registry one
// way. Adding a registry is a code change with tests, never a configuration.
const (
	// ExternalRegistryEntraAgentID is the Microsoft Entra Agent ID registry.
	// The name is a VALUE in this vocabulary; per docs/INTERFACES.md invariant
	// 6 no vendor name appears in a field name, and none does.
	ExternalRegistryEntraAgentID = "entra_agent_id"
)

// ExternalRegistries lists the closed vocabulary in stable order, for error
// messages that name what a record may carry.
func ExternalRegistries() []string {
	return []string{ExternalRegistryEntraAgentID}
}

// ValidExternalRegistry reports whether name is in the closed vocabulary.
func ValidExternalRegistry(name string) bool {
	for _, r := range ExternalRegistries() {
		if name == r {
			return true
		}
	}
	return false
}

const (
	// maxExternalRefNameBytes bounds the registry and kind. They are names a
	// reader compares, not documents.
	maxExternalRefNameBytes = 64
	// maxExternalRefValueBytes bounds the registry's identifier. Directory
	// object ids are short; the bound is generous while still refusing a
	// field that could carry a payload into the evidence.
	maxExternalRefValueBytes = 256
)

// Validate refuses a reference a sealed record may not carry: a registry
// outside the closed vocabulary (a mapping nobody can interpret later), an
// empty or unprintable kind or value (an address nobody can read), or a
// source other than registered (an unattributed claim, which would read as
// verification AAES does not perform). The check runs at registration and
// again at the record layer, so a record written by a path that bypassed the
// directory cannot seal a reference the deployment could not have registered.
func (r ExternalRef) Validate() error {
	if !ValidExternalRegistry(r.Registry) {
		return fmt.Errorf("external reference registry %q is not one of the known registries %v; a record may only name a registry AAES can interpret", r.Registry, ExternalRegistries())
	}
	if err := validExternalRefName("kind", r.Kind); err != nil {
		return err
	}
	if err := validExternalRefValue(r.Value); err != nil {
		return err
	}
	if r.Source != ExternalRefSourceRegistered {
		return fmt.Errorf("external reference source %q is not %q: an external identifier is correlation data the deployment registered, and an unattributed one would read as verification AAES does not perform", r.Source.String(), ExternalRefSourceRegistered)
	}
	return nil
}

// AsRegistered stamps the reference as registration-sourced, the same rule as
// ModelRef.AsRegistered: a reference carried by an actor record is, by
// construction, the mapping the actor was registered with, so the source
// label is AAES's statement about the value and not the registrant's.
func (r ExternalRef) AsRegistered() ExternalRef {
	r.Source = ExternalRefSourceRegistered
	return r
}

// Matches reports whether two references name the same object: registry, kind
// and value agree. The source label is AAES's own and plays no part in the
// comparison, exactly as a caller's model declaration is compared to the
// registration by identity and not by label.
func (r ExternalRef) Matches(other ExternalRef) bool {
	return r.Registry == other.Registry && r.Kind == other.Kind && r.Value == other.Value
}

// validExternalRefName checks a name field: non-empty, bounded, printable
// ASCII. A value with a control character or a byte outside printable ASCII
// would make "which object" unanswerable by anyone who did not already know.
func validExternalRefName(field, s string) error {
	if s == "" {
		return fmt.Errorf("external reference %s is empty; a reference that cannot name its %s names nothing", field, field)
	}
	if len(s) > maxExternalRefNameBytes {
		return fmt.Errorf("external reference %s is %d bytes, the bound is %d", field, len(s), maxExternalRefNameBytes)
	}
	return validExternalRefPrintable(field, s)
}

func validExternalRefValue(s string) error {
	if s == "" {
		return fmt.Errorf("external reference value is empty; a reference with no registry identifier is a claim about nothing")
	}
	if len(s) > maxExternalRefValueBytes {
		return fmt.Errorf("external reference value is %d bytes, the bound is %d", len(s), maxExternalRefValueBytes)
	}
	return validExternalRefPrintable("value", s)
}

func validExternalRefPrintable(field, s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("external reference %s contains a byte that is not printable ASCII", field)
		}
	}
	return nil
}
