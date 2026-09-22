package types

import (
	"strings"
	"testing"
)

// TestAccessDurationVocabulary proves the shapes are a closed vocabulary: the
// five names round-trip, the empty value means the shape every record written
// before the vocabulary existed carried, and an unknown word is refused naming
// the vocabulary rather than folded into the permissive default.
func TestAccessDurationVocabulary(t *testing.T) {
	for _, d := range AccessDurations() {
		if !d.Valid() {
			t.Fatalf("%q is in the vocabulary and does not validate", d)
		}
		if d.OrJustInTime() != d {
			t.Fatalf("%q resolved to %q", d, d.OrJustInTime())
		}
		parsed, err := ParseAccessDuration(string(d))
		if err != nil || parsed != d {
			t.Fatalf("ParseAccessDuration(%q) = %q, %v", d, parsed, err)
		}
	}
	if AccessDuration("").Valid() {
		t.Fatal("the empty duration validates as a named shape; it is the zero value and Validate resolves it through OrJustInTime")
	}
	if got := AccessDuration("").OrJustInTime(); got != DurationJustInTime {
		t.Fatalf("an absent duration reads as %q, want just_in_time", got)
	}
	for _, raw := range []string{"", "jit", "just-in-time", "JUST_IN_TIME"} {
		if parsed, err := ParseAccessDuration(raw); err != nil || parsed != DurationJustInTime {
			t.Fatalf("ParseAccessDuration(%q) = %q, %v; want just_in_time", raw, parsed, err)
		}
	}
	for _, raw := range []string{"standing", "standing_access"} {
		if parsed, err := ParseAccessDuration(raw); err != nil || parsed != DurationStanding {
			t.Fatalf("ParseAccessDuration(%q) = %q, %v; want standing", raw, parsed, err)
		}
	}
	for _, raw := range []string{"scheduled-window", "window", "scheduled"} {
		if parsed, err := ParseAccessDuration(raw); err != nil || parsed != DurationScheduledWindow {
			t.Fatalf("ParseAccessDuration(%q) = %q, %v; want scheduled_window", raw, parsed, err)
		}
	}
	for _, raw := range []string{"work-bound", "work"} {
		if parsed, err := ParseAccessDuration(raw); err != nil || parsed != DurationWorkBound {
			t.Fatalf("ParseAccessDuration(%q) = %q, %v; want work_bound", raw, parsed, err)
		}
	}
	for _, raw := range []string{"break-glass", "breakglass", "emergency"} {
		if parsed, err := ParseAccessDuration(raw); err != nil || parsed != DurationBreakGlass {
			t.Fatalf("ParseAccessDuration(%q) = %q, %v; want break_glass", raw, parsed, err)
		}
	}
	if _, err := ParseAccessDuration("forever"); err == nil {
		t.Fatal("an unknown duration parsed")
	} else if !strings.Contains(err.Error(), "break_glass") || !strings.Contains(err.Error(), "standing") {
		t.Fatalf("the refusal does not name the vocabulary: %v", err)
	}
}

// TestAccessDurationReviewControl names which shapes depend on a human review
// rather than on their window: that fact is what the console's review queue and
// the access package's reads both build on.
func TestAccessDurationReviewControl(t *testing.T) {
	want := map[AccessDuration]bool{
		DurationJustInTime:      false,
		DurationStanding:        true,
		DurationScheduledWindow: false,
		DurationWorkBound:       false,
		DurationBreakGlass:      true,
	}
	for _, d := range AccessDurations() {
		if got := d.ReviewControlled(); got != want[d] {
			t.Fatalf("%q.ReviewControlled() = %v, want %v", d, got, want[d])
		}
	}
	if AccessDuration("").ReviewControlled() {
		t.Fatal("an absent duration reads as review-controlled; it is just_in_time")
	}
	if len(AccessDurations()) != 5 {
		t.Fatalf("the vocabulary has %d shapes, want 5", len(AccessDurations()))
	}
}
