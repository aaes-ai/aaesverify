package verifier

import (
	"errors"
	"strings"
	"testing"
)

// A legacy line whose member is repeated, exactly or under encoding/json's
// case folding, must be refused. Without the refusal Go hashed the last
// spelling while jq, Python and spreadsheets showed the first, so the
// visible actor could be changed while the export still verified.
func TestLegacyExportRefusesRepeatedMembers(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	doc := exportJSONL(t, entries, head, pub)
	if res := VerifyExportReaderResult(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true}); !res.OK {
		t.Fatalf("baseline export does not verify: %v", res.Errors)
	}
	lines := strings.Split(strings.TrimRight(doc, "\n"), "\n")
	for _, tc := range []struct {
		name, line, old, new string
	}{
		{"case-folded entry member", "entry", `"actor_id":"agent-1"`, `"actor_id":"decoy-actor","Actor_ID":"agent-1"`},
		{"exact entry member", "entry", `"actor_id":"agent-1"`, `"actor_id":"decoy-actor","actor_id":"agent-1"`},
		{"case-folded allowed flag", "entry", `"allowed":true`, `"allowed":false,"ALLOWED":true`},
		{"case-folded header member", "header", `"tenant_id":"tenant-a"`, `"tenant_id":"tenant-a","Tenant_Id":"tenant-a"`},
		{"case-folded signed head member", "header", `"tree_size":3`, `"tree_size":3,"Tree_Size":3`},
		{"case-folded type discriminator", "entry", `"type":"entry"`, `"type":"entry","Type":"entry"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edited := append([]string(nil), lines...)
			i := 0
			if tc.line == "entry" {
				i = 1
			}
			if !strings.Contains(edited[i], tc.old) {
				t.Fatalf("fixture line %d lacks %s: %s", i, tc.old, edited[i])
			}
			edited[i] = strings.Replace(edited[i], tc.old, tc.new, 1)
			res := VerifyExportReaderResult(strings.NewReader(strings.Join(edited, "\n")+"\n"), pub, VerifyOptions{AllowPreAnchor: true})
			if res.OK || res.Verdict != "FAIL" || !strings.Contains(strings.Join(res.Errors, " "), "duplicate object key") {
				t.Fatalf("repeated member verified or was not named: ok=%v verdict=%s errors=%v", res.OK, res.Verdict, res.Errors)
			}
		})
	}
}

func TestLegacyAnchorLineRefusesRepeatedMembers(t *testing.T) {
	for _, raw := range []string{
		`{"type":"anchor","key_id":"a","Key_ID":"b"}`,
		`{"type":"anchor","head":{"root_hash":"aa","Root_Hash":"bb"}}`,
		`{"type":"anchor","witnesses":[{"witness_id":"w","Witness_ID":"x"}]}`,
	} {
		if _, err := decodeAnchorLine([]byte(raw), 3); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "duplicate object key") {
			t.Fatalf("%s: err = %v, want a malformed duplicate-member refusal", raw, err)
		}
	}
	if _, err := decodeAnchorLine([]byte(`{"type":"anchor","key_id":"a"}`), 3); err != nil {
		t.Fatalf("a well-formed anchor line was refused: %v", err)
	}
}
