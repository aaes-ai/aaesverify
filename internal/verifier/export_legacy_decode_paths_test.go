package verifier

import (
	"strings"
	"testing"
)

func TestDecodeHeaderLineRefusesDuplicateHeader(t *testing.T) {
	raw := []byte(`{"type":"header","schema":"aaes.export/v2","log_id":"l","tenant_id":"t","entry_count":0}`)
	if _, err := decodeHeaderLine(raw, true, 2); err == nil || !strings.Contains(err.Error(), "duplicate header") {
		t.Fatalf("err = %v, want duplicate header refusal", err)
	}
}

func TestDecodeLegacyBodyLineRefusesBrokenEntry(t *testing.T) {
	var exp ExportFile
	err := decodeLegacyBodyLine(&exp, []byte(`{`), lineEntry, 2)
	if err == nil {
		t.Fatal("a broken entry line must be refused")
	}
	if len(exp.Entries) != 0 {
		t.Fatalf("a refused entry must not be appended, got %d", len(exp.Entries))
	}
}

func TestCheckHeaderRefusesUnsupportedSchema(t *testing.T) {
	exp := &ExportFile{Header: HeaderView{Schema: "aaes.export/v9"}}
	res := &Result{}
	checkHeader(exp, res)
	for _, e := range res.Errors {
		if strings.Contains(e, "unsupported export schema") {
			return
		}
	}
	t.Fatalf("expected an unsupported-schema error, got %v", res.Errors)
}
