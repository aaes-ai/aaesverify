package main

import (
	"encoding/json"
	"github.com/aaes-ai/aaesverify/internal/verifier"
	"strings"
	"testing"
)

func TestShreddedExportDoesNotRenderAnOrdinarySuccess(t *testing.T) {
	result := &verifier.Result{OK: true, IndependentWitnesses: 1}
	// Decode an event through JSON below to avoid coupling to producer types.
	if err := json.Unmarshal([]byte(`{"ok":true,"independent_witnesses":1,"shred_events":[{}]}`), result); err != nil {
		t.Fatal(err)
	}
	rendered := renderVerify(result)
	if !strings.Contains(rendered, "OK WITH SHREDDED FIELDS") {
		t.Fatalf("shred headline hidden: %s", rendered)
	}
}
