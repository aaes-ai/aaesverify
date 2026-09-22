package hash

// The JSON-number exponent bound: a number whose decimal shift exceeds the
// parser's limit is refused rather than canonicalised into something two
// encoders could disagree about.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalJSONRefusesAnOutOfBoundExponent(t *testing.T) {
	_, err := CanonicalJSON(json.Number("1e100001"))
	if err == nil || !strings.Contains(err.Error(), "exponent exceeds") {
		t.Fatalf("canonicalising 1e100001 err = %v", err)
	}
	// The bound is symmetric: a huge negative shift is refused the same way.
	if _, err := CanonicalJSON(json.Number("1e-100001")); err == nil || !strings.Contains(err.Error(), "exponent exceeds") {
		t.Fatalf("canonicalising 1e-100001 err = %v", err)
	}
	// At the bound the number still canonicalises.
	if _, err := CanonicalJSON(json.Number("1e100000")); err != nil {
		t.Fatalf("canonicalising 1e100000 at the bound: %v", err)
	}
}
