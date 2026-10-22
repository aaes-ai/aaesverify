package verifier

import "testing"

// pinnedUsageLeafV4 is the leaf the verifier recomputes for usageLeafLine,
// pinned before ModelUsage had an estimated member.
const pinnedUsageLeafV4 = "fdabea6c032104d22e4613766dd5bfa96b49f31207b1f31b0f151286b0c15907"

func usageLeafLine(t *testing.T, extra map[string]any) []byte {
	t.Helper()
	line := validReceiptLeafMapV4()
	usage := map[string]any{"input_tokens": 3, "output_tokens": 4, "total_tokens": 7, "settled_minor": 1, "currency": "USD"}
	for k, v := range extra {
		usage[k] = v
	}
	line["receipt"].(map[string]any)["model_usage"] = usage
	return marshalV4(t, line)
}

func TestAMeasuredUsageLeafVerifiesAsBeforeEstimates(t *testing.T) {
	view, err := DecodeReceiptLeafV4(usageLeafLine(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := view.RecomputeLeafV4()
	if err != nil || leaf != pinnedUsageLeafV4 {
		t.Fatalf("a measured usage leaf moved: %s %v", leaf, err)
	}
}

func TestTheEstimatedMarkIsOptionalAndOnlyTrue(t *testing.T) {
	view, err := DecodeReceiptLeafV4(usageLeafLine(t, map[string]any{"estimated": true}))
	if err != nil {
		t.Fatal(err)
	}
	if leaf, err := view.RecomputeLeafV4(); err != nil || leaf == pinnedUsageLeafV4 {
		t.Fatalf("an estimate did not verify, or is not bound: %s %v", leaf, err)
	}
	for _, bad := range []any{false, "true", 1} {
		view, err := DecodeReceiptLeafV4(usageLeafLine(t, map[string]any{"estimated": bad}))
		if err == nil {
			_, err = view.RecomputeLeafV4()
		}
		if err == nil {
			t.Fatalf("estimated %v was accepted", bad)
		}
	}
}
