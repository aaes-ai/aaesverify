package verifier

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// Strict-decode refusals and per-line parse refusals for the v4 wire format
// (design section 4.2 and 6.1), plus the canonicalisation failure paths of
// the typed leaf recomputations.

func TestV4RejectDuplicateMembersRefusals(t *testing.T) {
	t.Run("invalid character is a token error", func(t *testing.T) {
		if err := rejectDuplicateMembers([]byte(`{"a": @}`)); err == nil {
			t.Fatal("an invalid token passed the token walk")
		}
	})
	t.Run("mismatched closing delimiter is unbalanced", func(t *testing.T) {
		// The streaming decoder refuses a mismatched delimiter before the
		// walk sees it, so the guard is exercised directly.
		_, err := walkMemberTokenV4(nil, json.Delim('}'))
		if err == nil || !strings.Contains(err.Error(), "unbalanced") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("non-string object member name refused", func(t *testing.T) {
		// The streaming decoder never produces this token sequence from real
		// input, so the guard is exercised directly.
		stack := []memberFrameV4{{object: true, expectKey: true, seen: map[string]struct{}{}}}
		_, err := walkMemberTokenV4(stack, float64(1))
		if err == nil || !strings.Contains(err.Error(), "member name expected") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestV4LeafRecomputeRefusals(t *testing.T) {
	// PreimageV4 validates first, so an envelope-invalid leaf cannot be
	// canonicalised; the recompute helpers surface that as an error.
	t.Run("receipt", func(t *testing.T) {
		_, err := (&ReceiptLeafViewV4{}).RecomputeLeafV4()
		if err == nil || !strings.Contains(err.Error(), "canonicalise receipt leaf") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("approval", func(t *testing.T) {
		_, err := (&ApprovalLeafViewV4{}).RecomputeLeafV4()
		if err == nil || !strings.Contains(err.Error(), "canonicalise approval leaf") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("summary", func(t *testing.T) {
		_, err := (&SummaryLeafViewV4{}).RecomputeLeafV4()
		if err == nil || !strings.Contains(err.Error(), "canonicalise summary leaf") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("summary producer payload", func(t *testing.T) {
		if _, err := (&SummaryLeafViewV4{}).SummaryProducerPayloadV4(); err == nil {
			t.Fatal("an invalid leaf produced a producer payload")
		}
	})
}

func TestV4EqualTimePtrNilCases(t *testing.T) {
	now := v4Base
	if equalTimePtrV4(nil, &now) || equalTimePtrV4(&now, nil) {
		t.Fatal("a nil time pointer equalled a non-nil one")
	}
	if !equalTimePtrV4(nil, nil) {
		t.Fatal("two nil time pointers differ")
	}
}

func TestV4IsHexEmpty(t *testing.T) {
	if isHexV4("") {
		t.Fatal("the empty string reported as hex")
	}
}

// TestV4HeaderLineRefusal covers a first line that probes as a header but
// fails the header decode.
func TestV4HeaderLineRefusal(t *testing.T) {
	doc := `{"type":"header","entry_count":"two"}` + "\n"
	res := VerifyExportReaderResult(strings.NewReader(doc), nil, VerifyOptions{})
	if res.OK || !strings.Contains(strings.Join(res.Errors, " "), "line 1") {
		t.Fatalf("ok=%v errors=%v", res.OK, res.Errors)
	}
}

// TestV4BodyLineRefusals covers the per-type decode refusals, the line-order
// rule (no leaf after an anchor), and the unknown-type refusal.
func TestV4BodyLineRefusals(t *testing.T) {
	header := strings.SplitN(newV4Builder(t).build().text, "\n", 2)[0]
	anchored := newV4Builder(t)
	anchored.anchors = append(anchored.anchors, v4AnchorSpec{key: anchored.signing, treeSize: 2})
	anchoredText := anchored.build().text

	cases := []struct {
		name string
		doc  string
		frag string
	}{
		{"entry after anchor", anchoredText + `{"type":"entry"}` + "\n", "follows an anchor"},
		{"approval after anchor", anchoredText + `{"type":"approval"}` + "\n", "follows an anchor"},
		{"summary after anchor", anchoredText + `{"type":"summary"}` + "\n", "follows an anchor"},
		{"receipt failing validation", header + "\n" + `{"type":"receipt"}` + "\n", "line 2"},
		{"approval failing validation", header + "\n" + `{"type":"approval"}` + "\n", "line 2"},
		{"summary failing validation", header + "\n" + `{"type":"summary"}` + "\n", "line 2"},
		{"unknown line type", header + "\n" + `{"type":"bogus"}` + "\n", "unknown line type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadExportReader(strings.NewReader(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("err=%v, want fragment %q", err, tc.frag)
			}
		})
	}
}

// TestV4AppendHelperRefusals exercises the append helpers' preimage failure
// paths directly: a decoded leaf always validates, so these guards are
// reachable only for a leaf canonicalisation cannot encode.
func TestV4AppendHelperRefusals(t *testing.T) {
	t.Run("entry with an unencodable timestamp", func(t *testing.T) {
		entry := v4Entry("tenant-a", 1, v4Base)
		entry.OccurredAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		exp := &ExportFile{}
		if err := exp.appendEntryV4(entry, 2); err == nil {
			t.Fatal("an entry canonicalisation failure was not reported")
		}
	})
	t.Run("receipt", func(t *testing.T) {
		exp := &ExportFile{}
		if err := exp.appendReceiptV4(ReceiptLeafViewV4{}, 2); err == nil {
			t.Fatal("an invalid receipt leaf was appended")
		}
	})
	t.Run("approval", func(t *testing.T) {
		exp := &ExportFile{}
		if err := exp.appendApprovalV4(ApprovalLeafViewV4{}, 2); err == nil {
			t.Fatal("an invalid approval leaf was appended")
		}
	})
	t.Run("summary", func(t *testing.T) {
		exp := &ExportFile{}
		if err := exp.appendSummaryV4(SummaryLeafViewV4{}, 2); err == nil {
			t.Fatal("an invalid summary leaf was appended")
		}
	})
}

// TestV4SummaryDecodeRefusals covers the summary envelope and input head
// guards of design section 5.1 that existing golden fixtures do not refuse.
func TestV4SummaryDecodeRefusals(t *testing.T) {
	valid := func(t *testing.T) *SummaryLeafViewV4 {
		sum := validSummaryLeafTypedV4(t, "tenant-a")
		sum.ChainHash = "claim"
		sum.Leaf = "claim"
		return sum
	}
	t.Run("wrong schema", func(t *testing.T) {
		sum := valid(t)
		sum.Schema = ExportSchemaV3
		_, err := DecodeSummaryLeafV4(marshalV4(t, sum))
		if err == nil || !strings.Contains(err.Error(), "summary leaf schema") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("period_end present but zero", func(t *testing.T) {
		sum := valid(t)
		sum.PeriodStart = v4timep(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		sum.PeriodEnd = v4timep(time.Time{})
		_, err := DecodeSummaryLeafV4(marshalV4(t, sum))
		if err == nil || !strings.Contains(err.Error(), "period_end") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("v4 input head with a wrong algorithm", func(t *testing.T) {
		sum := valid(t)
		sum.Inputs[0].Head.Algorithm = "rsa"
		_, err := DecodeSummaryLeafV4(marshalV4(t, sum))
		if err == nil || !strings.Contains(err.Error(), "must name algorithm") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("v2 input head carrying a schema member", func(t *testing.T) {
		sum := valid(t)
		sum.Inputs = []SummaryInputV4{{
			InputID:  "in-v2",
			Schema:   ExportSchemaV2,
			TenantID: "tenant-a",
			KeyID:    "ledger-k1",
			Head: hash.TreeHead{
				LogID:     hash.DeriveLogID("tenant-a"),
				Index:     1,
				RootHash:  hex64v4,
				TreeSize:  1,
				SignedAt:  v4Base,
				Signature: []byte("AAAA"),
				Schema:    ExportSchemaV3,
			},
		}}
		_, err := DecodeSummaryLeafV4(marshalV4(t, sum))
		if err == nil || !strings.Contains(err.Error(), "does not carry schema") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("finding is not an object", func(t *testing.T) {
		sum := valid(t)
		sum.Body = json.RawMessage(`{"limitations":[],"findings":[1]}`)
		_, err := DecodeSummaryLeafV4(marshalV4(t, sum))
		if err == nil || !strings.Contains(err.Error(), "finding must be an object") {
			t.Fatalf("err=%v", err)
		}
	})
}

// TestV4BundleDecodeRefusal covers the strict proof presence rules: a
// parent_proof object with no members is present but unusable.
func TestV4BundleDecodeRefusal(t *testing.T) {
	b, _ := buildReceiptBundleV4(t)
	raw := marshalV4(t, b)
	var asMap map[string]json.RawMessage
	if err := jsonUnmarshalV4(raw, &asMap); err != nil {
		t.Fatal(err)
	}
	asMap["parent_proof"] = json.RawMessage(`{}`)
	raw = marshalV4(t, asMap)
	_, err := DecodeReceiptBundleV1(raw)
	if err == nil || !strings.Contains(err.Error(), "parent_proof.index") {
		t.Fatalf("err=%v", err)
	}
}
