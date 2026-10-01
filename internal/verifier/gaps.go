package verifier

import (
	"fmt"
	"strings"
)

// checkGaps validates every tombstone the export carries and requires every
// missing sequence range to be named by one. It runs only when the chain itself
// verified: an edited export fails earlier, and this check answers the next
// question — "is the export complete?" — rather than the first.
func checkGaps(exp *ExportFile, res *Result) {
	if len(exp.Entries) > 0 && exp.Entries[0].Sequence == 0 {
		// Sequences start at 1. A first entry at 0 would make missingRanges
		// unable to see a missing sequence 1, so it is refused here rather than
		// silently skipped.
		res.addError("the export's first entry has sequence 0; sequences start at 1")
		return
	}
	usable := checkTombstones(exp, res)
	coverMissingRanges(exp, usable, res)
	warnPartiallyRemovedRanges(exp, usable, res)
	summarizeGaps(res)
}

// checkTombstones validates every tombstone the export carries and returns the
// entries whose tombstone is well-formed enough to explain a missing range.
// A malformed tombstone is an error; it must not also count as coverage.
func checkTombstones(exp *ExportFile, res *Result) []EntryView {
	usable := make([]EntryView, 0, 2)
	for _, e := range exp.Entries {
		t := e.Tombstone
		if t == nil {
			continue
		}
		res.TombstonesChecked++
		if !tombstoneIsWellFormed(e, res) {
			continue
		}
		usable = append(usable, e)
	}
	return usable
}

// tombstoneIsWellFormed reports whether one tombstone names a real range that
// precedes it, states a reason, an authorizer and a removal time. Every
// refusal is recorded on res.
func tombstoneIsWellFormed(e EntryView, res *Result) bool {
	t := e.Tombstone
	switch {
	case t.FromSequence == 0 || t.ToSequence < t.FromSequence:
		res.addError("entry sequence %d: tombstone range %d..%d is not a range", e.Sequence, t.FromSequence, t.ToSequence)
		return false
	case t.ToSequence >= e.Sequence:
		res.addError("entry sequence %d: tombstone names %d..%d, which does not precede the tombstone's own sequence; a tombstone cannot explain itself away", e.Sequence, t.FromSequence, t.ToSequence)
		return false
	case strings.TrimSpace(t.Reason) == "":
		res.addError("entry sequence %d: tombstone names range %d..%d and states no reason", e.Sequence, t.FromSequence, t.ToSequence)
		return false
	case strings.TrimSpace(t.AuthorizedBy) == "":
		res.addError("entry sequence %d: tombstone names range %d..%d and no authorising operator or policy", e.Sequence, t.FromSequence, t.ToSequence)
		return false
	case t.RemovedAt.IsZero():
		res.addError("entry sequence %d: tombstone names range %d..%d and no removal time", e.Sequence, t.FromSequence, t.ToSequence)
		return false
	}
	return true
}

// coverMissingRanges requires every sequence range absent from the export to be
// named by a usable tombstone, and records the ranges a tombstone does cover as
// GapViews.
func coverMissingRanges(exp *ExportFile, usable []EntryView, res *Result) {
	for _, g := range missingRanges(exp.Entries) {
		covered := false
		for _, e := range usable {
			t := e.Tombstone
			if t.FromSequence <= g[0] && t.ToSequence >= g[1] {
				res.Gaps = append(res.Gaps, GapView{
					FromSequence: g[0], ToSequence: g[1], TombstoneSequence: e.Sequence,
					Reason: t.Reason, AuthorizedBy: t.AuthorizedBy, PolicyID: t.PolicyID, RemovedAt: t.RemovedAt,
				})
				covered = true
				break
			}
		}
		if !covered {
			res.addError("sequence range %d..%d is missing from the export and no tombstone names it; a range removed without a tombstone is a deleted record, not retention", g[0], g[1])
		}
	}
}

// warnPartiallyRemovedRanges warns where a tombstone names a range the export
// still holds entries in: the log was linked before the removal, so nothing is
// missing, but the operator should see that the removal is not yet visible.
func warnPartiallyRemovedRanges(exp *ExportFile, usable []EntryView, res *Result) {
	for _, e := range usable {
		t := e.Tombstone
		present := 0
		for _, x := range exp.Entries {
			if x.Tombstone == nil && x.Sequence >= t.FromSequence && x.Sequence <= t.ToSequence {
				present++
			}
		}
		if present > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("tombstone at sequence %d names range %d..%d and the export still contains %d entry(ies) in it; the log was linked before the removal, so the removal is recorded but nothing is missing from this export", e.Sequence, t.FromSequence, t.ToSequence, present))
		}
	}
}

// summarizeGaps turns the covered ranges into the one summary line an operator
// reads, and marks the result gapped.
func summarizeGaps(res *Result) {
	if len(res.Gaps) > 0 {
		res.Gapped = true
		var names []string
		for _, g := range res.Gaps {
			names = append(names, fmt.Sprintf("%d..%d", g.FromSequence, g.ToSequence))
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d sequence range(s) were removed under retention and are named by tombstones: %s", len(res.Gaps), strings.Join(names, ", ")))
	}
}

// missingRanges returns the sequence ranges absent from an ordered entry list,
// as inclusive [from, to] pairs. It assumes the chain check has already
// established that sequences are strictly increasing.
func missingRanges(entries []EntryView) [][2]uint64 {
	var gaps [][2]uint64
	var prev uint64
	for _, e := range entries {
		if e.Sequence > prev+1 {
			gaps = append(gaps, [2]uint64{prev + 1, e.Sequence - 1})
		}
		if e.Sequence > prev {
			prev = e.Sequence
		}
	}
	return gaps
}
