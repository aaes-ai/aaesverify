package verifier

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// TestHeadPayloadOmitsFalsePreAnchor locks omitempty on TreeHead.PreAnchor:
// absent and false must produce identical signed bytes; true must differ.
func TestHeadPayloadOmitsFalsePreAnchor(t *testing.T) {
	base := hash.TreeHead{
		LogID:    hash.DeriveLogID("tenant-a"),
		Index:    1,
		RootHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TreeSize: 1,
		SignedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}

	absent := HeadPayload(base)
	withFalse := base
	withFalse.PreAnchor = false
	falsePayload := HeadPayload(withFalse)
	withTrue := base
	withTrue.PreAnchor = true
	truePayload := HeadPayload(withTrue)

	if len(absent) == 0 || len(falsePayload) == 0 || len(truePayload) == 0 {
		t.Fatal("HeadPayload returned empty bytes")
	}
	if !bytes.Equal(absent, falsePayload) {
		t.Fatalf("absent and false PreAnchor payloads differ:\nabsent=%s\nfalse =%s", absent, falsePayload)
	}
	if bytes.Equal(absent, truePayload) {
		t.Fatalf("true PreAnchor payload matched the omitted form: %s", truePayload)
	}
	if !strings.Contains(string(truePayload), `"pre_anchor":true`) {
		t.Fatalf("true payload does not carry pre_anchor: %s", truePayload)
	}
	if strings.Contains(string(absent), "pre_anchor") {
		t.Fatalf("omitted PreAnchor still appears in payload: %s", absent)
	}
}
