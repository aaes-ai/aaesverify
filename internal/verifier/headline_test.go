package verifier

import "testing"

func TestIntegrityHeadlineReservesPassForIndependentAttestation(t *testing.T) {
	if got := (&Result{OK: true}).IntegrityHeadline(); got != "CONSISTENT" {
		t.Fatalf("witness-less headline = %q", got)
	}
	if got := (&Result{OK: true, IndependentWitnesses: 1}).IntegrityHeadline(); got != "PASS" {
		t.Fatalf("witness headline = %q", got)
	}
	if got := (&Result{OK: true, TimestampsIndependent: 1}).IntegrityHeadline(); got != "PASS" {
		t.Fatalf("timestamp headline = %q", got)
	}
}
