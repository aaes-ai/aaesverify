package verifier

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// These direct walker tests retain defensive refusals for callers that supply
// an incomplete stream or invoke an object helper outside an object context.
func TestJSONMemberWalkerDefensiveRefusals(t *testing.T) {
	for _, tc := range []struct {
		name         string
		raw          string
		objectHelper bool
		frag         string
	}{
		{"missing value", `{"a":`, false, "EOF"},
		{"closing delimiter is not a value", `[]`, false, "unexpected JSON delimiter"},
		{"unterminated object key", `{"unfinished`, true, "unexpected EOF"},
		{"non-string object key", `[1]`, true, "object key has type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec := json.NewDecoder(strings.NewReader(tc.raw))
			var err error
			if tc.name == "missing value" {
				err = checkJSONValue(dec, nil, true, false)
			} else {
				if _, err := dec.Token(); err != nil {
					t.Fatal(err)
				}
				if tc.objectHelper {
					err = checkJSONObject(dec, nil, true, false)
				} else {
					err = checkJSONValue(dec, nil, true, false)
				}
			}
			if err == nil || !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("err=%v, want %q", err, tc.frag)
			}
		})
	}
}

func TestJSONMemberShapeSkipsFieldsIgnoredByDecoder(t *testing.T) {
	type typed struct {
		private string
		Ignored string `json:"-"`
		Visible int    `json:"visible"`
	}
	shape := reflect.TypeOf(typed{})
	for _, key := range []string{"private", "Ignored", "-", "missing"} {
		if got := jsonMemberShape(shape, key); got != nil {
			t.Fatalf("ignored member %q acquired a typed shape: %v", key, got)
		}
	}
	if got := jsonMemberShape(shape, "Visible"); got != reflect.TypeOf(int(0)) {
		t.Fatalf("visible alias lost its typed shape: %v", got)
	}
	// Ignored members must not acquire closed-struct semantics, while
	// visible member aliases still conflict.
	if err := checkTypedJSONAliases([]byte(`{"Ignored":{"API":1,"api":2}}`), &typed{}); err != nil {
		t.Fatal(err)
	}
	if err := checkTypedJSONAliases([]byte(`{"visible":1,"Visible":2}`), &typed{}); err == nil {
		t.Fatal("visible field aliases accepted")
	}
}

func TestJSONMemberUnicodeFoldCycleRefusesGreekAliases(t *testing.T) {
	if err := checkDuplicateJSONKeys([]byte(`{"Ω":1,"ω":2}`)); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("Unicode fold cycle accepted conflicting keys: %v", err)
	}
	if got := foldJSONKey("Ωω"); got != "ΩΩ" {
		t.Fatalf("Unicode fold result = %q", got)
	}
}

func TestV4DuplicateMemberAliases(t *testing.T) {
	var typed struct {
		Schema  string
		Receipt struct {
			KeyID        string                      `json:"key_id"`
			ExternalRefs []struct{ Registry string } `json:"external_refs"`
		}
		Inputs []struct {
			Head struct {
				SignedAt string `json:"signed_at"`
			}
		}
	}
	for _, raw := range []string{
		`{"schema":"aaes.export/v4","Schema":"aaes.export/v4"}`,
		`{"schema":"aaes.export/v4","ſchema":"aaes.export/v4"}`,
		`{"schema":"aaes.export/v4","\u017fchema":"aaes.export/v4"}`,
		`{"receipt":{"key_id":"first","Key_id":"second"}}`,
		`{"inputs":[{"head":{"signed_at":"first","ſigned_at":"second"}}]}`,
		`{"receipt":{"external_refs":[{"registry":"first","Registry":"second"}]}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if err := decodeStrictV4([]byte(raw), &typed); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "duplicate object key") {
				t.Fatalf("case-folded member ambiguity accepted: %v", err)
			}
		})
	}
}

func TestV4AliasRefusalAtExportBoundary(t *testing.T) {
	doc := newV4Builder(t).build().text
	for _, pair := range [][2]string{{"schema", "ſchema"}, {"tenant_id", "Tenant_ID"}, {"sequence", "ſequence"}} {
		t.Run(pair[0], func(t *testing.T) {
			marker := `"` + pair[0] + `":`
			altered := strings.Replace(doc, marker, `"`+pair[1]+`":"ignored",`+marker, 1)
			if altered == doc {
				t.Fatal("test did not alter its fixture")
			}
			if _, err := LoadExportReader(strings.NewReader(altered)); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "duplicate object key") {
				t.Fatalf("v4 export accepted member alias: %v", err)
			}
		})
	}
}

func TestMemberKeyFoldingPreservesValuesAndObjectBoundaries(t *testing.T) {
	raw := []byte(`{"first":{"key":"K","label":"ſ"},"second":{"key":"k","label":"s"}}`)
	if err := checkDuplicateJSONKeys(raw); err != nil {
		t.Fatal(err)
	}
	if err := rejectDuplicateMembers(raw); err != nil {
		t.Fatal(err)
	}
	var got struct{ First, Second struct{ Key, Label string } }
	if err := decodeStrictV4(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.First.Key != "K" || got.First.Label != "ſ" || got.Second.Key != "k" || got.Second.Label != "s" {
		t.Fatalf("value strings changed: %+v", got)
	}
}

func TestV4ProfileKeysRetainCaseSensitiveContract(t *testing.T) {
	for _, body := range []string{
		`{"limitations":[],"API":1,"api":2}`,
		`{"limitations":[],"metrics":{"API":{"value":1,"input_ids":["in-1"]},"api":{"value":2,"input_ids":["in-1"]}}}`,
		`{"limitations":[],"findings":[{"code":"c","input_ids":["in-1"],"detail":{"API":1,"api":2}}]}`,
	} {
		raw := summaryLineRawBodyV4(t, body)
		var leaf SummaryLeafViewV4
		if err := decodeStrictV4(raw, &leaf); err != nil {
			t.Fatal(err)
		}
		if err := leaf.ValidateV4(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestV4ProfileKnownMemberAliasesRefused(t *testing.T) {
	for _, body := range []string{
		`{"limitations":[],"Limitations":[]}`,
		`{"limitations":[],"findings":[{"code":"first","Code":"second","input_ids":["in-1"]}]}`,
		`{"limitations":[],"metrics":{"m":{"value":1,"Value":2,"input_ids":["in-1"]}}}`,
	} {
		var leaf SummaryLeafViewV4
		if err := decodeStrictV4(summaryLineRawBodyV4(t, body), &leaf); err != nil {
			t.Fatal(err)
		}
		if err := leaf.ValidateV4(); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "duplicate object key") {
			t.Fatalf("profile minimum member aliases accepted: %v", err)
		}
	}
}
