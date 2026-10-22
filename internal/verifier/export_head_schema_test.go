package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// A v4 head keeps a valid signature when only the unsigned header label is
// edited to v2, so the legacy path must refuse a head that signs a schema.
func TestLegacyHeaderRefusesHeadSigningV4Schema(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	entries := []EntryView{{
		TenantID: "tenant-a", Sequence: 1, RecordHash: hash.SHA256Hex([]byte("r1")),
		IntentID: "i1", ActorID: "a1", Capability: "read", Tier: types.R0RiskTier,
		Allowed: true, OccurredAt: now, LinkedAt: now,
	}}
	doc := sealSchemaExport(t, ExportSchemaV2, "tenant-a", entries, pub, priv, now)
	clean, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil || !clean.OK {
		t.Fatalf("unmodified v2 export: %v %v", err, clean.Errors)
	}
	relabelled := resignHeaderHeadSchema(t, doc, ExportSchemaV4, priv)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(relabelled), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !strings.Contains(strings.Join(res.Errors, "\n"), `signed head 0 names schema "aaes.export/v4"`) {
		t.Fatalf("relabelled v4 head accepted on the legacy path: ok=%v errors=%v", res.OK, res.Errors)
	}
}

func resignHeaderHeadSchema(t *testing.T, doc, schema string, priv ed25519.PrivateKey) string {
	t.Helper()
	lines := strings.SplitN(doc, "\n", 2)
	var header map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatal(err)
	}
	var head hash.TreeHead
	if err := json.Unmarshal(header["head"], &head); err != nil {
		t.Fatal(err)
	}
	head.Schema = schema
	head.Signature = ed25519.Sign(priv, HeadPayload(head))
	raw, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	header["head"] = raw
	line, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return string(line) + "\n" + lines[1]
}
