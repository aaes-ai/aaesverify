package verifier

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadExportRefusesMalformedLines(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		frag string
	}{
		{
			"bad anchor json",
			"{\"type\":\"header\",\"schema\":\"aaes.export/v2\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":0}\n" +
				"{not-json\n",
			"line 2",
		},
		{
			"v1 amount_currency interim",
			"{\"type\":\"header\",\"schema\":\"aaes.export/v1\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":1}\n" +
				"{\"type\":\"entry\",\"tenant_id\":\"t\",\"sequence\":1,\"record_hash\":\"h\",\"intent_id\":\"i\",\"actor_id\":\"a\",\"capability\":\"c\",\"tier\":3,\"allowed\":true,\"amount_currency\":\"USD\",\"occurred_at\":\"2026-09-12T10:00:00Z\",\"linked_at\":\"2026-09-12T10:00:00Z\"}\n",
			"unsupported export schema",
		},
		{
			"v1 bad entry json after keys",
			"{\"type\":\"header\",\"schema\":\"aaes.export/v1\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":1}\n" +
				"{\"type\":\"entry\",\"amount_usd\":1,\"tenant_id\":1}\n",
			"line 2",
		},
		{
			"unknown schema bad entry",
			"{\"type\":\"header\",\"schema\":\"aaes.export/v9\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":1}\n" +
				"{not-json\n",
			"line 2",
		},
		{
			"duplicate header",
			"{\"type\":\"header\",\"schema\":\"aaes.export/v2\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":0}\n" +
				"{\"type\":\"header\",\"schema\":\"aaes.export/v2\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":0}\n",
			"duplicate header",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadExportReader(strings.NewReader(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("err = %v, want frag %q", err, tc.frag)
			}
		})
	}
}

func TestDecodeHelpersRefuseBrokenJSON(t *testing.T) {
	if _, err := decodeHeaderLine([]byte(`{`), false, 1); err == nil {
		t.Fatal("decodeHeaderLine must refuse broken JSON")
	}
	if _, err := decodeAnchorLine([]byte(`{`), 1); err == nil {
		t.Fatal("decodeAnchorLine must refuse broken JSON")
	}
	if _, err := decodeEntryLine([]byte(`{`), "aaes.export/v1", 1); err == nil {
		t.Fatal("decodeEntryLine v1 keys must refuse broken JSON")
	}
	if _, err := decodeEntryLine([]byte(`{`), ExportSchemaV2, 1); err == nil {
		t.Fatal("decodeEntryLine v2 must refuse broken JSON")
	}
	if _, err := decodeEntryLine([]byte(`{`), "aaes.export/v9", 1); err == nil {
		t.Fatal("decodeEntryLine unknown schema must refuse broken JSON")
	}
}

func TestLoadExportReaderSurfacesScannerError(t *testing.T) {
	// A line longer than the scanner buffer surfaces sc.Err.
	huge := strings.Repeat("a", (4<<20)+10)
	doc := "{\"type\":\"header\",\"schema\":\"aaes.export/v2\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":0}\n" + huge + "\n"
	_, err := LoadExportReader(strings.NewReader(doc))
	if err == nil || !strings.Contains(err.Error(), "read export") {
		t.Fatalf("scanner overflow err = %v", err)
	}
}

type errReader struct {
	prefix []byte
	once   bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if !r.once {
		r.once = true
		n := copy(p, r.prefix)
		return n, nil
	}
	return 0, errors.New("forced read failure")
}

func TestLoadExportReaderSurfacesReadError(t *testing.T) {
	header := []byte("{\"type\":\"header\",\"schema\":\"aaes.export/v2\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":0}\n")
	_, err := LoadExportReader(&errReader{prefix: header})
	if err == nil || !strings.Contains(err.Error(), "read export") {
		t.Fatalf("err = %v, want read export", err)
	}
}

func TestLoadExportReaderRefusesBrokenAnchorLine(t *testing.T) {
	doc := "{\"type\":\"header\",\"schema\":\"aaes.export/v2\",\"log_id\":\"l\",\"tenant_id\":\"t\",\"entry_count\":0}\n" +
		"{\"type\":\"anchor\",\"head\":\"nope\"}\n"
	_, err := LoadExportReader(strings.NewReader(doc))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err = %v, want line 2 anchor decode failure", err)
	}
}
