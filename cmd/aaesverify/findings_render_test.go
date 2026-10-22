package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

func TestShreddedExportDoesNotRenderAnOrdinarySuccess(t *testing.T) {
	result := &verifier.Result{OK: true, IndependentWitnesses: 1}
	// Decode an event through JSON below to avoid coupling to producer types.
	if err := json.Unmarshal([]byte(`{"ok":true,"independent_witnesses":1,"shred_events":[{}]}`), result); err != nil {
		t.Fatal(err)
	}
	rendered := renderVerify(result)
	if !strings.Contains(rendered, "OK with shredded fields (1 key destruction(s) recorded; 0 entries carry encrypted identifiers)") {
		t.Fatalf("shred headline hidden: %s", rendered)
	}
}
