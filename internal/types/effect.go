package types

import "fmt"

// EffectClass records how far an action actually got, so a receipt can
// distinguish "denied" from "authorized but never used" from "executed".
//
// This distinction is load-bearing. The evidence pack's coverage attestation
// claims a percentage of in-scope agent effects traversed the gateway; that
// claim is only checkable if an examiner can tell an authorization apart from
// an execution. Without it a minted-but-unused grant is indistinguishable from
// a completed action, and the coverage number is self-reported.
type EffectClass int

const (
	// EffectDenied means the gateway refused; no grant was minted.
	EffectDenied EffectClass = iota
	// EffectMintedUnused means a grant was issued but no effect was ever
	// recorded against it. This is the state a crash between mint and effect
	// leaves behind, and it must never be counted as coverage.
	EffectMintedUnused
	// EffectExecuted means the effect was confirmed at the rail.
	EffectExecuted
	// EffectAuthorized means the gateway authorised the action and minted a
	// grant, and NO effect has been recorded because this path never attempts
	// one: Handle decides and returns, and only HandleBrokered executes.
	//
	// It is appended rather than inserted so the existing wire values keep their
	// meaning: EffectDenied stays 0 and still means "the gateway refused". The
	// zero value of the enum was denied, and a successful grant that serialised
	// as class 0 told a reader the opposite of what happened. This class exists so
	// that "authorised, not yet executed" has its own honest spelling. It is NOT
	// EffectMintedUnused: that class says an execution was attempted or a crash
	// intervened, and this one says nothing was attempted yet.
	EffectAuthorized
)

func (c EffectClass) String() string {
	switch c {
	case EffectDenied:
		return "denied"
	case EffectMintedUnused:
		return "minted_unused"
	case EffectExecuted:
		return "executed"
	case EffectAuthorized:
		return "authorized"
	}
	return fmt.Sprintf("unknown(%d)", int(c))
}

// CountsTowardCoverage reports whether this class may be counted in a coverage
// attestation. Only a confirmed execution counts. A denial counts as governance
// working but not as coverage of an effect, and an unused mint counts as neither.
func (c EffectClass) CountsTowardCoverage() bool { return c == EffectExecuted }
