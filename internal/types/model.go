package types

import "strings"

// ModelRef identifies the AI model that produced a governed decision, at three
// levels of identity, and says where that identity came from.
//
// Why three levels rather than one string. An examiner asking "which model
// produced this outcome" is answered incompletely by any single name. The
// provider answers whose infrastructure served it, the family answers which line
// of models it belongs to, and the model answers which artifact ran. Correlated
// model failure -- one family failing the same way for every tenant that uses it
// -- is only computable from the family, and a family answer is only meaningful
// while it is pinned to the provider that served it.
//
// Why Source. AAES never calls a model and therefore never observes which one
// ran. The identity on a record is the identity the deployment registered the
// actor with, so the record must say that and nothing stronger. The honest
// sentence the product can make is "this is the model the actor was registered
// with at decision time", and Source is what keeps a record from implying more.
//
// The values are opaque to this package. No vendor, product or family name is
// compiled in: the shape is validated here and the vocabulary comes from
// registration, so adding a provider is a configuration change rather than a
// code change (docs/INTERFACES.md invariant 6).
type ModelRef struct {
	Provider string
	Family   string
	Model    string
	Source   ModelSource
}

// ModelSource names where a recorded model identity came from. It is AAES's own
// vocabulary and not the deployment's: the deployment registers the identity,
// and this label records what AAES did with it.
type ModelSource string

const (
	// ModelSourceUnknown means no model was registered for the actor. It is the
	// honest label for "AAES does not know", and it is what a record carries when
	// the deployment declared none. It is deliberately not an error: most
	// deployments predate this field, and refusing every actor without one would
	// break them to record a fact they never had.
	ModelSourceUnknown ModelSource = "unknown"
	// ModelSourceRegistered means the value is the identity the actor was
	// registered with in the directory. It is NOT verification that this is the
	// model that ran: AAES does not call the model, so it cannot make that claim.
	ModelSourceRegistered ModelSource = "registered"
)

// String renders the source label. The zero value reads as "unknown", because a
// model identity with no recorded source is exactly a value AAES cannot
// attribute, and printing an empty string there would let a bug look like a
// blank field rather than an unattributed claim.
func (s ModelSource) String() string {
	if s == "" {
		return string(ModelSourceUnknown)
	}
	return string(s)
}

// MaxModelIdentityLen bounds each level of the identity. Real provider, family
// and model names are short; the bound exists so a registration cannot seal a
// document into a field whose only purpose is to answer "which model".
const MaxModelIdentityLen = 64

// isModelIdentityChar reports whether r may appear in a level of the identity.
// The set is deliberately narrow -- letters, digits, dot, underscore, hyphen and
// slash -- and covers every provider, family and model spelling in use,
// including namespaced ones such as "meta-llama/Llama-3". It deliberately
// excludes whitespace, quotes, commas, colons and control characters: a value
// that cannot be rendered unambiguously in a log line, an error message and a
// JSONL record is not a value the record should carry.
func isModelIdentityChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '.', r == '_', r == '-', r == '/':
		return true
	}
	return false
}

// UnknownModel returns the ref for the case where nothing is registered. It is
// the zero-value reading of a model identity: no levels, unknown source.
func UnknownModel() ModelRef { return ModelRef{Source: ModelSourceUnknown} }

// RegisteredModel builds the identity a directory registration records. It trims
// the levels and stamps the source, because "this is what was registered" is
// AAES's statement about the value and not the registrant's. A partial identity
// is NOT silently reduced to unknown: it comes back stamped and incomplete, so
// Validate refuses it and the deployment is told which level is missing instead
// of being recorded as having declared nothing.
func RegisteredModel(provider, family, model string) ModelRef {
	m := ModelRef{
		Provider: strings.TrimSpace(provider),
		Family:   strings.TrimSpace(family),
		Model:    strings.TrimSpace(model),
	}
	if m.empty() {
		return UnknownModel()
	}
	m.Source = ModelSourceRegistered
	return m
}

// empty reports whether no level of the identity is set.
func (m ModelRef) empty() bool {
	return strings.TrimSpace(m.Provider) == "" &&
		strings.TrimSpace(m.Family) == "" &&
		strings.TrimSpace(m.Model) == ""
}

// Known reports whether a complete identity is present. A ref with one or two
// levels set is not known: a partial answer to "which model" is a different
// claim, and Validate refuses it rather than letting this method fold it into
// the unknown case.
func (m ModelRef) Known() bool {
	return strings.TrimSpace(m.Provider) != "" &&
		strings.TrimSpace(m.Family) != "" &&
		strings.TrimSpace(m.Model) != ""
}

// AsRegistered returns the ref as a directory holds it: an identity present in an
// actor record is, by construction, the identity the actor was registered with
// here, so the source becomes "registered". An empty ref stays unknown. The
// directory applies this rather than the caller, so a registrant cannot label an
// unverifiable claim as though AAES had checked it.
func (m ModelRef) AsRegistered() ModelRef {
	if m.Known() {
		m.Source = ModelSourceRegistered
	}
	return m
}

// Identity renders the three levels without the source label, for logs and for
// matching a caller's declaration. It is empty when nothing is registered. It is
// not a parse format: a slash is legal inside a level, so the fields remain the
// record and this rendering is for humans.
func (m ModelRef) Identity() string {
	if !m.Known() {
		return ""
	}
	return m.Provider + "/" + m.Family + "/" + m.Model
}

// String renders the ref canonically: the identity and the source label, or
// "unknown" when nothing is registered. It is stable, so a log line or an error
// message can be compared across runs.
func (m ModelRef) String() string {
	if !m.Known() {
		return string(ModelSourceUnknown)
	}
	return m.Identity() + " (" + m.Source.String() + ")"
}

// Matches reports whether a caller's declaration names this model. A declaration
// may name any one level -- the provider, the family or the exact model -- or the
// full identity rendering, and it must equal one of them exactly.
//
// Exact and case-sensitive, deliberately: "GLM-5" and "glm-5" are different
// strings to every API that would serve them, so a gateway that folded case
// would accept a declaration it cannot check. An empty declaration matches
// nothing here; the gateway treats "no declaration" as its own case, because
// "the caller said nothing" and "the caller said something wrong" must not be
// the same branch.
func (m ModelRef) Matches(decl string) bool {
	decl = strings.TrimSpace(decl)
	if decl == "" || !m.Known() {
		return false
	}
	return decl == m.Provider || decl == m.Family || decl == m.Model || decl == m.Identity()
}

// Validate enforces the shape rules of an identity and the honesty rule of its
// source. It validates SHAPE only: it has no list of providers, families or
// models and never will, because such a list in a core package is exactly the
// vendor coupling the invariants forbid.
//
// The rules, and why each exists:
//
//   - No levels set is the unknown case, and it is valid. That is the state of
//     every actor registered before this field existed, and the state of every
//     deployment that has not declared a model.
//   - Some levels set is refused. A registration that names a provider and no
//     model answers half the question, and recording half an answer as though it
//     were the answer is how a provenance field becomes decoration.
//   - Each level is non-empty after trimming, bounded in length, and restricted
//     to the identity character set, so the value can be sealed into a JSONL
//     record and rendered in a log line without escaping or ambiguity.
//   - A complete identity must carry a source. The only source that may sit
//     beside an identity is "registered": AAES has no other way to know a model,
//     and a value labelled "unknown" while carrying a full identity claims the
//     identity twice over while denying it once.
func (m ModelRef) Validate() error {
	if m.empty() {
		if m.Source != "" && m.Source != ModelSourceUnknown {
			return errf("types: a model ref with no provider, family or model cannot claim source %q; nothing was registered to attribute", m.Source)
		}
		return nil
	}

	levels := []struct{ name, value string }{
		{"Provider", m.Provider},
		{"Family", m.Family},
		{"Model", m.Model},
	}
	missing := make([]string, 0, len(levels))
	for _, level := range levels {
		if strings.TrimSpace(level.value) == "" {
			missing = append(missing, level.name)
		}
	}
	if len(missing) > 0 {
		return errf("types: model identity is incomplete; missing %s (provider %q, family %q, model %q)",
			strings.Join(missing, ", "), m.Provider, m.Family, m.Model)
	}
	for _, level := range levels {
		if err := validateModelLevel(level.name, level.value); err != nil {
			return err
		}
	}

	switch m.Source {
	case ModelSourceRegistered:
		return nil
	case ModelSourceUnknown:
		return errf("types: model %s carries a complete identity but labels its source %q; an identity AAES cannot attribute is a declaration, not a fact", m.Identity(), m.Source)
	case "":
		return errf("types: model %s carries no source; an identity that does not say where it came from cannot be told from a declaration", m.Identity())
	default:
		return errf("types: unknown model source %q (want %q or %q)", m.Source, ModelSourceRegistered, ModelSourceUnknown)
	}
}

// validateModelLevel applies the shape rules to one level of the identity.
func validateModelLevel(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return errf("types: model %s is empty", name)
	}
	if value != strings.TrimSpace(value) {
		return errf("types: model %s %q has leading or trailing whitespace; a registration must be normalised before it is sealed", name, value)
	}
	if len(value) > MaxModelIdentityLen {
		return errf("types: model %s is %d characters; the bound is %d", name, len(value), MaxModelIdentityLen)
	}
	for _, r := range value {
		if !isModelIdentityChar(r) {
			return errf("types: model %s %q contains %q; only letters, digits, dot, underscore, hyphen and slash are allowed", name, value, r)
		}
	}
	return nil
}
