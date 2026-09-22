// Package types is the frozen domain vocabulary every other package speaks:
// actors, capabilities, actions, resources, data classes, tiers, scopes,
// work, approvals and the one enforcement label.
//
// Two properties are load-bearing.
//
// The vocabulary is a contract, not an implementation detail. docs/INTERFACES.md
// freezes it: a renamed field or a re-spelled enum value is a breaking change
// to every stored record and every sealed export, so change here is additive
// and nothing is renamed in place. Where a user-facing term has moved on
// (manager for sponsor, action for verb), the historical field names stay and
// the README glossary carries the mapping.
//
// The enforcement label is computed, never claimed: EnforcementFor derives
// enforced, observed or inventory from the custody model and the wiring, so a
// record cannot assert a strength the mechanism does not provide.
//
// Nothing here talks to the world. The package holds values, validation and
// the derivations over them, and imports nothing outside the standard
// library.
package types
