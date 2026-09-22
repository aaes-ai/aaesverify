package types

import "fmt"

// RiskTier classifies an action by consequence. R0 is free; R4 always requires a human.
type RiskTier int

const (
	R0RiskTier RiskTier = iota // read
	R1RiskTier                 // draft
	R2RiskTier                 // internal state change
	R3RiskTier                 // spend / external comms
	R4RiskTier                 // destructive / legal
)

// MaxRiskTier is the highest defined tier.
const MaxRiskTier = R4RiskTier

func (r RiskTier) String() string {
	if r < R0RiskTier || r > MaxRiskTier {
		return fmt.Sprintf("R?%d", int(r))
	}
	return fmt.Sprintf("R%d", int(r))
}

// RiskTierUnspecified is what a parser returns BESIDE an error. It is not a
// tier: it is outside [R0, R4], String renders it as "R?-1", and every range
// check in the system refuses it. It exists because an earlier revision returned
// R0 together with the parse error, and R0 is the one tier that is free and
// auto-executable, so a caller that forgot to check the error was handed the
// most permissive answer available to a question that had NO answer.
const RiskTierUnspecified RiskTier = -1

// ParseRiskTier parses "R0".."R4".
//
// On failure the tier returned is RiskTierUnspecified, NOT R0: a valid tier must
// never travel beside an error, because the two are read by different code and
// only one of them is usually checked.
func ParseRiskTier(s string) (RiskTier, error) {
	switch s {
	case "R0":
		return R0RiskTier, nil
	case "R1":
		return R1RiskTier, nil
	case "R2":
		return R2RiskTier, nil
	case "R3":
		return R3RiskTier, nil
	case "R4":
		return R4RiskTier, nil
	}
	return RiskTierUnspecified, fmt.Errorf("types: invalid risk tier %q", s)
}

// AutoExecutable reports whether a tier may execute without a human gate,
// assuming policy and budget allow it. The range is checked at both ends:
// RiskTierUnspecified is below R0 and would otherwise read as the most
// auto-executable value there is, which is the same leniency that made the old
// parser return R0 with its error.
func (r RiskTier) AutoExecutable() bool { return r >= R0RiskTier && r <= R2RiskTier }
