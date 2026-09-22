package types

import (
	"fmt"
	"strings"
)

// EffectKey identifies one intended effect so that a retry cannot double-spend.
//
// Derived from the work and the step, not from the request: two attempts to do
// the same thing under the same work must produce the same key, and an
// accidental second attempt must be refused rather than executed twice. The key
// is committed inside the same journal write that authorises the action, so the
// guarantee survives a crash.
type EffectKey struct {
	WorkID string
	// StepKey is the caller's name for the step within the work, for example
	// "send-confirmation" or "charge-invoice-4471". It must be stable across
	// retries, which is why it is a name rather than an index.
	StepKey string
}

// String renders the key canonically. The separator is a control character so
// that no combination of identifier contents can produce the same string from
// different parts.
func (e EffectKey) String() string {
	return e.WorkID + "\x1f" + e.StepKey
}

func (e EffectKey) Validate() error {
	if e.WorkID == "" {
		return fmt.Errorf("types: an effect key requires a WorkID")
	}
	if e.StepKey == "" {
		return fmt.Errorf("types: an effect key requires a StepKey; without one a retry cannot be told from a new action")
	}
	if strings.ContainsRune(e.WorkID, '\x1f') || strings.ContainsRune(e.StepKey, '\x1f') {
		return fmt.Errorf("types: an effect key cannot contain the unit-separator used to encode it")
	}
	return nil
}
