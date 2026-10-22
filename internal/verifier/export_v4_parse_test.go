package verifier

import (
	"errors"
	"strings"
	"testing"
)

// The v4 parsing refusals (design sections 4.1, 4.2, 6.1, 6.2): the header
// schema fixes the decoder for the whole file, typed lines under a legacy
// header and legacy-only constructs under a v4 header are refused, and strict
// decoding applies to every v4 line including anchors.

func TestV4TypedLinesRefusedUnderLegacyHeaders(t *testing.T) {
	entries := []EntryView{v4Entry("tenant-a", 1, v4Base)}
	pub, priv := testKey(t)
	for _, schema := range []string{ExportSchemaV2, ExportSchemaV3} {
		for _, typed := range []map[string]any{validReceiptLeafMapV4(), validApprovalLeafMapV4(), validSummaryLeafMapV4()} {
			doc := sealSchemaExport(t, schema, "tenant-a", entries, pub, priv, v4Base)
			doc += string(marshalV4(t, typed)) + "\n"
			if _, err := LoadExportReader(strings.NewReader(doc)); err == nil ||
				!strings.Contains(err.Error(), "unknown line type") {
				t.Fatalf("%s + %v: err = %v, want unknown line type", schema, typed["type"], err)
			}
		}
	}
}

func TestV4LegacyConstructsRefusedUnderV4Header(t *testing.T) {
	doc := newV4Builder(t).build()
	lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")

	t.Run("entry with unknown member", func(t *testing.T) {
		var entry map[string]any
		if err := jsonUnmarshalV4([]byte(lines[1]), &entry); err != nil {
			t.Fatal(err)
		}
		entry["surprise"] = 1
		out := spliceLine(t, lines, 1, entry)
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("entry with amount_usd", func(t *testing.T) {
		var entry map[string]any
		if err := jsonUnmarshalV4([]byte(lines[1]), &entry); err != nil {
			t.Fatal(err)
		}
		entry["amount_usd"] = 12.5
		out := spliceLine(t, lines, 1, entry)
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrSchema) {
			t.Fatalf("err = %v, want ErrSchema", err)
		}
	})

	t.Run("anchor with unknown member", func(t *testing.T) {
		b := newV4Builder(t)
		b.anchors = []v4AnchorSpec{{key: b.signing, treeSize: 2, legacy: true}}
		adoc := b.build()
		alines := strings.Split(strings.TrimRight(adoc.text, "\n"), "\n")
		last := alines[len(alines)-1]
		var anchor map[string]any
		if err := jsonUnmarshalV4([]byte(last), &anchor); err != nil {
			t.Fatal(err)
		}
		anchor["surprise"] = 1
		out := spliceLine(t, alines, len(alines)-1, anchor)
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("anchor with unknown nested witness member", func(t *testing.T) {
		b := newV4Builder(t)
		w := newV4KeyPair("witness-1", 31)
		b.anchors = []v4AnchorSpec{{key: b.signing, treeSize: 2, legacy: true, witnesses: []v4WitnessSpec{{id: "w1", key: w}}}}
		adoc := b.build()
		alines := strings.Split(strings.TrimRight(adoc.text, "\n"), "\n")
		last := alines[len(alines)-1]
		var anchor map[string]any
		if err := jsonUnmarshalV4([]byte(last), &anchor); err != nil {
			t.Fatal(err)
		}
		anchor["witnesses"].([]any)[0].(map[string]any)["surprise"] = 1
		out := spliceLine(t, alines, len(alines)-1, anchor)
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("trailing JSON after an entry line", func(t *testing.T) {
		lines[1] += " {}"
		out := strings.Join(lines, "\n") + "\n"
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("duplicate member in an entry line", func(t *testing.T) {
		dup := strings.Replace(lines[1], `"sequence":1`, `"sequence":1,"sequence":1`, 1)
		if dup == lines[1] {
			t.Fatal("fixture did not contain the sequence member")
		}
		lines[1] = dup
		out := strings.Join(lines, "\n") + "\n"
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
}

// TestV4UnknownSchemaRefusedBeforeBody pins section 6.1: the header's exact
// schema decides before ANY body line decodes — no content-sniffing, no
// fallback to an older parser.
func TestV4UnknownSchemaRefusedBeforeBody(t *testing.T) {
	for _, schema := range []string{"aaes.export/v5", "aaes.export/v99", "aaes.export/v0"} {
		doc := `{"type":"header","schema":"` + schema + `","tenant_id":"t"}` + "\n" +
			"{not json at all\n"
		_, err := LoadExportReader(strings.NewReader(doc))
		if !errors.Is(err, ErrSchema) {
			t.Fatalf("%s: err = %v, want ErrSchema", schema, err)
		}
		if !strings.Contains(err.Error(), "line 1") {
			t.Fatalf("%s: the body line was decoded first: %v", schema, err)
		}
	}
}

// TestV4HeaderStrictDecode: unknown and duplicate members on a v4 header are
// refused, while the same extras on a v2/v3 header keep the legacy lenient
// path.
func TestV4HeaderStrictDecode(t *testing.T) {
	doc := newV4Builder(t).build()
	lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")

	t.Run("unknown member refused", func(t *testing.T) {
		var hdr map[string]any
		if err := jsonUnmarshalV4([]byte(lines[0]), &hdr); err != nil {
			t.Fatal(err)
		}
		hdr["surprise"] = 1
		out := spliceLine(t, lines, 0, hdr)
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("duplicate member refused", func(t *testing.T) {
		dup := strings.Replace(lines[0], `"tenant_id"`, `"tenant_id":"x","tenant_id"`, 1)
		lines[0] = dup
		out := strings.Join(lines, "\n") + "\n"
		if _, err := LoadExportReader(strings.NewReader(out)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	t.Run("leaf_count and signing_key_id populate the view", func(t *testing.T) {
		exp, err := LoadExportReader(strings.NewReader(doc.text))
		if err != nil {
			t.Fatal(err)
		}
		if exp.Header.LeafCount != 4 || exp.Header.SigningKeyID != "ledger-k1" {
			t.Fatalf("leaf_count=%d signing_key_id=%q", exp.Header.LeafCount, exp.Header.SigningKeyID)
		}
	})

	t.Run("v2 header stays lenient", func(t *testing.T) {
		raw := `{"type":"header","schema":"aaes.export/v2","tenant_id":"t","extra":1}` + "\n"
		exp, err := LoadExportReader(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("lenient v2 header refused: %v", err)
		}
		if exp.Header.LeafCount != 0 || exp.Header.SigningKeyID != "" {
			t.Fatalf("v2 header carries v4 members: %+v", exp.Header)
		}
	})
}

// TestV4LeafAfterAnchorRefused enforces the section 4.1 line order: leaves in
// log order, anchors after the leaves.
func TestV4LeafAfterAnchorRefused(t *testing.T) {
	b := newV4Builder(t)
	b.anchors = []v4AnchorSpec{{key: b.signing, treeSize: 2, legacy: true}}
	doc := b.build()
	lines := strings.Split(strings.TrimRight(doc.text, "\n"), "\n")
	// Move the receipt line after the anchor.
	n := len(lines)
	receipt := lines[3]
	out := append(append([]string{}, lines[:3]...), lines[4:]...)
	out = append(out, receipt)
	_ = n
	if _, err := LoadExportReader(strings.NewReader(strings.Join(out, "\n") + "\n")); err == nil ||
		!strings.Contains(err.Error(), "follows an anchor") {
		t.Fatalf("err = %v, want a misplaced-leaf refusal", err)
	}
}

func TestNormalizeExportSchemaAcceptsV4(t *testing.T) {
	if got, ok := NormalizeExportSchema(ExportSchemaV4); !ok || got != ExportSchemaV4 {
		t.Fatalf("v4 = %q %v", got, ok)
	}
}
