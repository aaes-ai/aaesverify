package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestNormalizeExportSchemaAcceptsOnlyCurrent(t *testing.T) {
	if got, ok := NormalizeExportSchema(ExportSchemaV2); !ok || got != ExportSchemaV2 {
		t.Fatalf("v2 = %q %v", got, ok)
	}
	for _, schema := range []string{"aaes.export/v0", "aaes.export/v1", "aaes.export/v99"} {
		if _, ok := NormalizeExportSchema(schema); ok {
			t.Fatalf("unsupported schema accepted: %s", schema)
		}
		doc := `{"type":"header","schema":"` + schema + `"}` + "\n"
		if _, err := NormalizeExportReader(strings.NewReader(doc)); !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("%s: %v", schema, err)
		}
	}
}

func TestNormalizeExportReaderPassesSupportedThroughUnchanged(t *testing.T) {
	doc := `{"type":"header","schema":"aaes.export/v2","extra":1}` + "\n" + `{"type":"entry"}` + "\n"
	out, err := NormalizeExportReader(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte(doc)) {
		t.Fatalf("rewrote a supported export:\n%s", out)
	}
}

func TestNormalizeExportReaderRefusesOversize(t *testing.T) {
	header := []byte(`{"type":"header","schema":"aaes.export/v2"}` + "\n")
	const limit = 64
	body := bytes.Repeat([]byte("x"), limit)
	_, err := normalizeExportReaderLimited(io.MultiReader(bytes.NewReader(header), bytes.NewReader(body)), limit)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversize err = %v", err)
	}
}

func TestNormalizeExportReaderRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   string
		frag string
		is   error
	}{
		{"empty", "", "empty", ErrUnsupportedSchema},
		{"bad json", "{not-json\n", "not an export header", nil},
		{"not header", `{"type":"entry"}` + "\n", "not a header", nil},
		{"unsupported", `{"type":"header","schema":"aaes.export/v99"}` + "\n", "unsupported", ErrUnsupportedSchema},
		{"missing schema", `{"type":"header"}` + "\n", "unsupported export schema", ErrUnsupportedSchema},
		{"non-string type", `{"type":1,"schema":"aaes.export/v1"}` + "\n", "export header", nil},
		{"missing type", `{"schema":"aaes.export/v1"}` + "\n", "export header", nil},
		{"non-string schema", `{"type":"header","schema":1}` + "\n", "unsupported export schema", ErrUnsupportedSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeExportReaderLimited(strings.NewReader(tc.in), MaxExportBytes)
			if err == nil || !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("err = %v, want frag %q", err, tc.frag)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
		})
	}
}

type normalizeErrAfterHeader struct {
	prefix []byte
	once   bool
}

func (r *normalizeErrAfterHeader) Read(p []byte) (int, error) {
	if !r.once {
		r.once = true
		return copy(p, r.prefix), nil
	}
	return 0, errors.New("forced read failure")
}

func TestNormalizeExportReaderReadErrors(t *testing.T) {
	header := []byte(`{"type":"header","schema":"aaes.export/v2"}` + "\n")
	_, err := normalizeExportReaderLimited(&normalizeErrAfterHeader{prefix: header}, MaxExportBytes)
	if err == nil || !strings.Contains(err.Error(), "read export") {
		t.Fatalf("err = %v", err)
	}
	_, err = normalizeExportReaderLimited(&normalizeErrAfterHeader{prefix: nil}, MaxExportBytes)
	if err == nil {
		t.Fatal("expected refusal on scanner error")
	}
	oversized := strings.Repeat("x", MaxLineBytes+1) + "\n"
	_, err = NormalizeExportReader(strings.NewReader(oversized))
	if err == nil || !strings.Contains(err.Error(), "read export") {
		t.Fatalf("oversized line err = %v", err)
	}
}

func TestRawJSONStringRefusesMissingAndNonString(t *testing.T) {
	if _, err := rawJSONString(nil); err == nil {
		t.Fatal("nil RawMessage accepted")
	}
	if _, err := rawJSONString(json.RawMessage(`42`)); err == nil {
		t.Fatal("non-string RawMessage accepted")
	}
}
