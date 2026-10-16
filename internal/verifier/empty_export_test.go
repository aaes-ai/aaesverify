package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// emptyExportJSONL renders a header-only export whose head commits to nothing.
func emptyExportJSONL(t *testing.T, head hash.TreeHead) string {
	t.Helper()
	hb, err := json.Marshal(map[string]any{
		"type":        "header",
		"schema":      ExportSchemaV2,
		"log_id":      head.LogID,
		"tenant_id":   "test",
		"exported_at": head.SignedAt,
		"entry_count": 0,
		"head":        head,
		"public_key":  hex.EncodeToString(testPub()),
		"pre_anchor":  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(hb) + "\n"
}

// An empty export must not report root_ok or a signature pass that no check
// established: the overall verdict was already a failure, but the per-check
// fields are what an auditor reads.
func TestEmptyExportReportsNoUnverifiedPasses(t *testing.T) {
	head := hash.TreeHead{LogID: hash.DeriveLogID("test"), RootHash: hash.MerkleRoot(nil), SignedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))

	res := VerifyExportReaderResult(strings.NewReader(emptyExportJSONL(t, head)), testPub(), VerifyOptions{})
	if res.OK || res.ChainOK || res.RootOK {
		t.Fatalf("empty export: ok=%v chain_ok=%v root_ok=%v", res.OK, res.ChainOK, res.RootOK)
	}
	if !res.SignatureOK {
		t.Fatalf("a validly signed empty head must report the signature it checked: %v", res.Errors)
	}

	head.Signature = append([]byte(nil), head.Signature...)
	head.Signature[0] ^= 0xff
	res = VerifyExportReaderResult(strings.NewReader(emptyExportJSONL(t, head)), testPub(), VerifyOptions{})
	if res.SignatureOK || res.RootOK {
		t.Fatalf("forged empty head: signature_ok=%v root_ok=%v", res.SignatureOK, res.RootOK)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), ErrSignature.Error()) {
		t.Fatalf("forged empty head errors: %v", res.Errors)
	}
}

func TestEmptyChainStillChecksTheHead(t *testing.T) {
	st := checkChain(nil, hash.TreeHead{}, testPub())
	if !errors.Is(st.chainErr, ErrEmptyLog) || !errors.Is(st.rootErr, ErrRoot) || !errors.Is(st.sigErr, ErrSignature) {
		t.Fatalf("empty chain state: chain=%v root=%v sig=%v", st.chainErr, st.rootErr, st.sigErr)
	}
}

// The retired amount_usd field is refused from a single decode, including an
// explicit null and a line whose other fields are wrongly typed.
func TestEntryLineRefusesLegacyAmountInAnyForm(t *testing.T) {
	for _, raw := range []string{
		`{"type":"entry","amount_usd":null}`,
		`{"type":"entry","amount_usd":1,"tenant_id":1}`,
	} {
		if _, err := decodeEntryLine([]byte(raw), ExportSchemaV2, 2); !errors.Is(err, ErrSchema) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	if _, err := decodeEntryLine([]byte(`{"type":"entry","tenant_id":1}`), ExportSchemaV2, 2); !errors.Is(err, ErrMalformed) {
		t.Fatalf("wrongly typed field: %v", err)
	}
	if _, err := decodeEntryLine([]byte(`{"type":"entry","amount_usd":`), ExportSchemaV2, 2); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated line: %v", err)
	}
}
