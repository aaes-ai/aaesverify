package types

import (
	"fmt"
	"sort"
	"strings"
)

// AccessDuration is the SHAPE of an entitlement: how long it is meant to last
// and what makes it end. It is a separate fact from the TTL, because the TTL
// answers "until when" and this answers "on what basis", and the two must not
// be conflated: a standing grant and a just-in-time grant are both time-bound,
// but only one of them survives a workflow boundary and only one of them
// carries a post-hoc review obligation.
//
// The zero value is deliberately the empty string, which every stored access
// record written before this vocabulary existed carries, and it READS AS
// just_in_time: the shape every grant had before there were five. A record
// whose shape AAES cannot name is refused by Validate rather than folded into
// the permissive default.
type AccessDuration string

const (
	// DurationJustInTime is the original shape: an actor asks for a permission
	// it does not hold, a human decides, and the entitlement lapses at its own
	// expiry. Nothing survives the window.
	DurationJustInTime AccessDuration = "just_in_time"
	// DurationStanding is a permission granted ahead of the work it will be
	// used for. It is longer than just-in-time by construction, so its control
	// is not the window but the REVIEW: it carries a review expiry bounded by
	// the deployment's maximum standing window, it must be re-attested before
	// that expiry, and it must be NARROWER than what just-in-time could grant
	// on demand (see access.Request.NarrowerThanJIT). A standing grant that is
	// as broad as the just-in-time ceiling is a registration change wearing a
	// duration, and it is refused.
	DurationStanding AccessDuration = "standing"
	// DurationScheduledWindow is a just-in-time grant that is honoured only
	// inside the hours it names, in the timezone it names. Outside them it
	// authorises nothing, and the refusal says which window it is outside.
	DurationScheduledWindow AccessDuration = "scheduled_window"
	// DurationWorkBound is a grant bound to one unit of work: it ends when the
	// work's deadline passes or the work reaches a terminal state, whichever
	// comes first, even if its own expiry is later.
	DurationWorkBound AccessDuration = "work_bound"
	// DurationBreakGlass is emergency access: short by construction, approved
	// on the shortest path the deployment allows, and carrying a MANDATORY
	// post-hoc review obligation that stays open until a human closes it.
	DurationBreakGlass AccessDuration = "break_glass"
)

// AccessDurations returns every shape in the vocabulary, in the order a human
// reads them: the ordinary one first, the emergency one last.
func AccessDurations() []AccessDuration {
	return []AccessDuration{
		DurationJustInTime,
		DurationStanding,
		DurationScheduledWindow,
		DurationWorkBound,
		DurationBreakGlass,
	}
}

// String renders the wire spelling.
func (d AccessDuration) String() string { return string(d) }

// OrJustInTime resolves the zero value to the shape it means. Every read of a
// stored record goes through this: the field was added after records existed,
// and an absent field is the just-in-time shape rather than an unknown one.
func (d AccessDuration) OrJustInTime() AccessDuration {
	if d == "" {
		return DurationJustInTime
	}
	return d
}

// Valid reports whether the value is a shape this package names. The empty
// value is NOT valid here: Validate calls OrJustInTime first, so a reader that
// gets an invalid answer is looking at a spelling AAES does not define rather
// than at a record written before the vocabulary existed.
func (d AccessDuration) Valid() bool {
	switch d {
	case DurationJustInTime, DurationStanding, DurationScheduledWindow, DurationWorkBound, DurationBreakGlass:
		return true
	}
	return false
}

// ReviewControlled reports whether the shape's control is a human review rather
// than the clock alone. A standing grant is controlled by its review expiry and
// a break-glass grant by its post-hoc review obligation; every other shape ends
// when its window ends.
func (d AccessDuration) ReviewControlled() bool {
	switch d.OrJustInTime() {
	case DurationStanding, DurationBreakGlass:
		return true
	}
	return false
}

// ParseAccessDuration parses a wire spelling. It is case-insensitive and
// tolerates the hyphenated spelling a human types, but it never guesses: an
// unknown word is an error naming the vocabulary.
func ParseAccessDuration(s string) (AccessDuration, error) {
	trimmed := strings.TrimSpace(strings.ToLower(s))
	switch trimmed {
	case "", "jit", "just-in-time", "just_in_time":
		return DurationJustInTime, nil
	case "standing", "standing_access":
		return DurationStanding, nil
	case "scheduled", "scheduled-window", "window", "scheduled_window":
		return DurationScheduledWindow, nil
	case "work", "work-bound", "work_bound":
		return DurationWorkBound, nil
	case "break-glass", "breakglass", "break_glass", "emergency":
		return DurationBreakGlass, nil
	}
	return "", fmt.Errorf("types: unknown access duration %q (want one of %s)", s, AccessDurationVocabulary())
}

// AccessDurationVocabulary renders the vocabulary for a refusal message.
func AccessDurationVocabulary() string {
	names := make([]string, 0, len(AccessDurations()))
	for _, d := range AccessDurations() {
		names = append(names, string(d))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
