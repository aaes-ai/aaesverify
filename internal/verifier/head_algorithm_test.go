package verifier

import (
	"strings"
	"testing"
)

func TestRefuseUnknownHeadAlgorithm(t *testing.T) {
	if err := RefuseUnknownHeadAlgorithm(""); err != nil {
		t.Fatal(err)
	}
	if err := RefuseUnknownHeadAlgorithm(HeadSignatureAlgorithm); err != nil {
		t.Fatal(err)
	}
	err := RefuseUnknownHeadAlgorithm("rsa")
	if err == nil || !strings.Contains(err.Error(), "rsa") {
		t.Fatalf("err = %v, want a refusal naming rsa", err)
	}
}
