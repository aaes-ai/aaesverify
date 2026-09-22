package types

import (
	"fmt"
)

// ManagerSource says how a manager set came to be. It is recorded on the actor
// and on the sealed approval record so a reader never has to guess whether the
// entries were declared or derived.
type ManagerSource int

const (
	// ManagerSourceLegacy (the zero value) means only the single manager field
	// is recorded. It is what every actor and every sealed record written before
	// the set existed carries, and a reader resolves it to a one-entry set with
	// the accountable role. Nothing was reinterpreted: the value is read where
	// it was always read.
	ManagerSourceLegacy ManagerSource = iota
	// ManagerSourceSingle means the set was MATERIALISED from the single manager
	// field on a write. It is one accountable, primary entry derived from the
	// legacy value, and it is labelled so a reader can tell it from a set an
	// operator declared.
	ManagerSourceSingle
	// ManagerSourceSet means an operator declared the entries explicitly.
	ManagerSourceSet
)

// String renders the source as the lowercase token the console prints.
func (s ManagerSource) String() string {
	switch s {
	case ManagerSourceLegacy:
		return "legacy"
	case ManagerSourceSingle:
		return "single"
	case ManagerSourceSet:
		return "set"
	}
	return fmt.Sprintf("unknown(%d)", int(s))
}

// Validate reports whether the source is one AAES can name.
func (s ManagerSource) Validate() error {
	switch s {
	case ManagerSourceLegacy, ManagerSourceSingle, ManagerSourceSet:
		return nil
	}
	return fmt.Errorf("%w: unknown manager source %d", ErrManagerSource, int(s))
}
