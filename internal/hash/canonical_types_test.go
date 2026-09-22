package hash

import (
	"encoding/json"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCanonicalJSONCoversScalarAndCompoundForms(t *testing.T) {
	got, err := CanonicalJSON(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if string(got) != "null" {
		t.Fatalf("nil = %s, want null", got)
	}

	tru, err := CanonicalJSON(true)
	if err != nil {
		t.Fatalf("true: %v", err)
	}
	if string(tru) != "true" {
		t.Fatalf("true = %s", tru)
	}
	fal, err := CanonicalJSON(false)
	if err != nil {
		t.Fatalf("false: %v", err)
	}
	if string(fal) != "false" {
		t.Fatalf("false = %s", fal)
	}

	i64, err := CanonicalJSON(int64(42))
	if err != nil {
		t.Fatalf("int64: %v", err)
	}
	if string(i64) != "42" {
		t.Fatalf("int64 = %s", i64)
	}
	u64, err := CanonicalJSON(uint64(99))
	if err != nil {
		t.Fatalf("uint64: %v", err)
	}
	if string(u64) != "99" {
		t.Fatalf("uint64 = %s", u64)
	}

	frac, err := CanonicalJSON(1.5)
	if err != nil {
		t.Fatalf("float: %v", err)
	}
	if string(frac) != "1.5" {
		t.Fatalf("non-integral float = %s, want 1.5 (must not be truncated)", frac)
	}

	ts := time.Date(2026, 9, 13, 8, 0, 0, 123456789, time.UTC)
	quoted, err := CanonicalJSON(ts)
	if err != nil {
		t.Fatalf("time: %v", err)
	}
	if string(quoted) != `"2026-09-13T08:00:00.123456789Z"` {
		t.Fatalf("time = %s", quoted)
	}
}

func TestCanonicalJSONRawMessageRoundTripAndRejectsGarbage(t *testing.T) {
	raw, err := CanonicalJSON(json.RawMessage(`{"b":1,"a":2}`))
	if err != nil {
		t.Fatalf("raw message: %v", err)
	}
	if string(raw) != `{"a":2,"b":1}` {
		t.Fatalf("raw message was not re-canonicalised: %s", raw)
	}
	if _, err := CanonicalJSON(json.RawMessage(`{`)); err == nil {
		t.Fatal("invalid raw JSON was accepted")
	}
}

func TestCanonicalJSONPropagatesNestedErrors(t *testing.T) {
	if _, err := CanonicalJSON([]any{1, math.NaN()}); err == nil {
		t.Fatal("NaN nested in an array was accepted")
	}
	if _, err := CanonicalJSON(map[string]any{"k": math.Inf(-1)}); err == nil {
		t.Fatal("negative infinity nested in an object was accepted")
	}
}

type boom struct{}

func (boom) MarshalJSON() ([]byte, error) {
	return nil, errCanonicalBoom
}

type invalidJSON struct{}

func (invalidJSON) MarshalJSON() ([]byte, error) {
	return []byte(`{`), nil
}

// overflowJSON marshals as a JSON number encoding/json will emit, then refuse
// to unmarshal into any because it overflows float64. That is the round-trip
// path writeCanonical takes for structs: Marshal succeeds, Unmarshal fails.
type overflowJSON struct{}

func (overflowJSON) MarshalJSON() ([]byte, error) {
	return []byte("1e1000000"), nil
}

var errCanonicalBoom = errString("cannot marshal")

type errString string

func (e errString) Error() string { return string(e) }

func TestCanonicalJSONStructRoundTripAndUnsupportedTypes(t *testing.T) {
	type rec struct {
		B int    `json:"b"`
		A string `json:"a"`
	}
	got, err := CanonicalJSON(rec{B: 2, A: "x"})
	if err != nil {
		t.Fatalf("struct: %v", err)
	}
	if string(got) != `{"a":"x","b":2}` {
		t.Fatalf("struct canonical form = %s", got)
	}
	if _, err := CanonicalJSON(make(chan int)); err == nil {
		t.Fatal("a channel was canonicalised")
	}
	if _, err := CanonicalJSON(boom{}); err == nil {
		t.Fatal("MarshalJSON error was swallowed")
	}
	if _, err := CanonicalJSON(invalidJSON{}); err == nil {
		t.Fatal("MarshalJSON that emits invalid JSON was accepted")
	}
	if _, err := CanonicalJSON(overflowJSON{}); err == nil {
		t.Fatal("MarshalJSON that emits a number too large for float64 was accepted")
	}
}

func TestCanonicalJSONPreservesIntegersOutsideFloat64ExactRange(t *testing.T) {
	// 2^53 and 2^53+1 are distinct JSON integers. Decoding them into float64
	// made them the same value, so two signed envelope versions hashed identically.
	const a = "9007199254740992"
	const b = "9007199254740993"
	rawA, err := CanonicalJSON(json.RawMessage(a))
	if err != nil {
		t.Fatalf("raw %s: %v", a, err)
	}
	rawB, err := CanonicalJSON(json.RawMessage(b))
	if err != nil {
		t.Fatalf("raw %s: %v", b, err)
	}
	if string(rawA) != a || string(rawB) != b {
		t.Fatalf("raw integers collapsed: %s vs %s", rawA, rawB)
	}

	type envelope struct {
		Version uint64 `json:"version"`
	}
	left, err := CanonicalJSON(envelope{Version: 9007199254740992})
	if err != nil {
		t.Fatalf("struct a: %v", err)
	}
	right, err := CanonicalJSON(envelope{Version: 9007199254740993})
	if err != nil {
		t.Fatalf("struct b: %v", err)
	}
	if string(left) == string(right) {
		t.Fatal("distinct uint64 envelope versions canonicalised identically")
	}
	if string(left) != `{"version":9007199254740992}` || string(right) != `{"version":9007199254740993}` {
		t.Fatalf("struct integers = %s / %s", left, right)
	}
}

func TestCanonicalJSONNumberSpellingsAreExactAndIndependent(t *testing.T) {
	const n = "9007199254740993"
	const m = "9007199254740992"
	for _, spelling := range []string{n, n + ".0", n + "e0", n + "E0", n + ".00", "90071992547409930e-1"} {
		got, err := CanonicalJSON(json.RawMessage(spelling))
		if err != nil {
			t.Fatalf("%s: %v", spelling, err)
		}
		if string(got) != n {
			t.Fatalf("%s canonicalised to %s, want %s", spelling, got, n)
		}
	}
	decA, err := CanonicalJSON(json.RawMessage(m + ".0"))
	if err != nil {
		t.Fatal(err)
	}
	decB, err := CanonicalJSON(json.RawMessage(n + ".0"))
	if err != nil {
		t.Fatal(err)
	}
	if string(decA) == string(decB) {
		t.Fatal("decimal spellings of 2^53 and 2^53+1 collapsed")
	}
	expA, err := CanonicalJSON(json.RawMessage(m + "e0"))
	if err != nil {
		t.Fatal(err)
	}
	expB, err := CanonicalJSON(json.RawMessage(n + "e0"))
	if err != nil {
		t.Fatal(err)
	}
	if string(expA) == string(expB) {
		t.Fatal("exponent spellings of 2^53 and 2^53+1 collapsed")
	}
	if string(decA) != m || string(expA) != m {
		t.Fatalf("2^53 spellings = %s / %s, want %s", decA, expA, m)
	}
}

func TestCanonicalJSONRejectsTrailingValues(t *testing.T) {
	if _, err := CanonicalJSON(json.RawMessage(`{"a":1} {"a":2}`)); err == nil {
		t.Fatal("trailing JSON value was canonicalised")
	}
	if _, err := CanonicalJSON(json.RawMessage(`{"a":1}x`)); err == nil {
		t.Fatal("trailing suffix was canonicalised")
	}
	got, err := CanonicalJSON(json.RawMessage("{\"a\":1} \n"))
	if err != nil {
		t.Fatalf("trailing whitespace was refused: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Fatalf("whitespace-only suffix changed the value: %s", got)
	}
}

func TestCanonicalJSONRejectsAbsurdExponents(t *testing.T) {
	if _, err := CanonicalJSON(json.RawMessage("1e100001")); err == nil {
		t.Fatal("exponent 100001 was accepted")
	}
	if _, err := CanonicalJSON(json.Number("1e-100001")); err == nil {
		t.Fatal("negative exponent -100001 was accepted")
	}
}

func TestCanonicalJSONCoversSizedNumericTypes(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{int8(-8), "-8"},
		{int16(-16), "-16"},
		{int32(-32), "-32"},
		{uint(7), "7"},
		{uint8(8), "8"},
		{uint16(16), "16"},
		{uint32(32), "32"},
		{float32(1.5), "1.5"},
		{float32(2), "2"},
	} {
		got, err := CanonicalJSON(tc.in)
		if err != nil {
			t.Fatalf("%T(%v): %v", tc.in, tc.in, err)
		}
		if string(got) != tc.want {
			t.Fatalf("%T(%v) = %s, want %s", tc.in, tc.in, got, tc.want)
		}
	}
}

func TestLegacyCanonicalJSONAndHashObject(t *testing.T) {
	got, err := LegacyCanonicalJSON(json.Number("42"))
	if err != nil {
		t.Fatalf("legacy integer number: %v", err)
	}
	if string(got) != "42" {
		t.Fatalf("legacy integer number = %s, want 42", got)
	}
	frac, err := LegacyCanonicalJSON(json.Number("1.50"))
	if err != nil {
		t.Fatalf("legacy fractional number: %v", err)
	}
	if string(frac) != "1.5" {
		t.Fatalf("legacy fractional number = %s, want 1.5", frac)
	}
	if _, err := LegacyCanonicalJSON(json.Number("1e1000")); err == nil {
		t.Fatal("legacy JSON number overflowing float64 was accepted")
	}
	if _, err := LegacyCanonicalJSON(json.Number("not-a-number")); err == nil {
		t.Fatal("legacy JSON number with invalid syntax was accepted")
	}
	if _, err := LegacyCanonicalJSON(json.Number("NaN")); err == nil {
		t.Fatal("legacy JSON number NaN was accepted")
	}

	raw, err := LegacyCanonicalJSON(json.RawMessage(`{"b":1,"a":2}`))
	if err != nil {
		t.Fatalf("legacy raw message: %v", err)
	}
	if string(raw) != `{"a":2,"b":1}` {
		t.Fatalf("legacy raw message was not re-canonicalised: %s", raw)
	}
	if _, err := LegacyCanonicalJSON(json.RawMessage(`{`)); err == nil {
		t.Fatal("legacy invalid raw JSON was accepted")
	}
	if _, err := LegacyCanonicalJSON(overflowJSON{}); err == nil {
		t.Fatal("legacy struct round-trip of a number that overflows float64 was accepted")
	}

	v := map[string]any{"b": 1, "a": "x"}
	sum, err := LegacyHashObject(v)
	if err != nil {
		t.Fatalf("LegacyHashObject: %v", err)
	}
	canon, err := LegacyCanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	if sum != SHA256Hex(canon) {
		t.Fatalf("LegacyHashObject = %s, want SHA-256 of legacy canonical bytes", sum)
	}
	if _, err := LegacyHashObject(math.Inf(1)); err == nil {
		t.Fatal("LegacyHashObject accepted a non-finite float")
	}

	const n = json.Number("9007199254740993")
	legacy, err := LegacyHashObject(n)
	if err != nil {
		t.Fatalf("legacy 2^53+1: %v", err)
	}
	exact, err := HashObject(n)
	if err != nil {
		t.Fatalf("exact 2^53+1: %v", err)
	}
	if legacy == exact {
		t.Fatal("legacy float64 hash collided with exact encoding for 2^53+1")
	}
}

func TestCanonicalNumberDefensiveDigitAndFracBounds(t *testing.T) {
	if _, err := formatCanonicalNumber("xx", parsedJSONNumber{intDigits: "xx"}); err == nil {
		t.Fatal("non-decimal digits were formatted")
	}
	if _, err := formatCanonicalNumber("", parsedJSONNumber{}); err == nil {
		t.Fatal("empty digits were formatted")
	}
	if _, err := formatCanonicalFrac("1e-100001", false, big.NewInt(1), -(maxJSONExp + 1)); err == nil {
		t.Fatal("a fractional expansion longer than the digit bound was accepted")
	}
}

func TestHashObjectMatchesCanonicalSHA256AndRejectsNonFinite(t *testing.T) {
	v := map[string]any{"a": 1, "b": "x"}
	canon, err := CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := HashObject(v)
	if err != nil {
		t.Fatalf("HashObject: %v", err)
	}
	if sum != SHA256Hex(canon) {
		t.Fatalf("HashObject = %s, want SHA-256 of canonical bytes %s", sum, SHA256Hex(canon))
	}
	if _, err := HashObject(math.Inf(1)); err == nil {
		t.Fatal("HashObject accepted a non-finite float")
	}
}

func TestCanonicalJSONNumberSpellings(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"1.50", "1.5"},
		{"-2.5", "-2.5"},
		{"-2", "-2"},
		{"1e2", "100"},
		{"10e-1", "1"},
		{"0.10e2", "10"},
		{"-0", "0"},
		{"0.0", "0"},
		{"1.0e0", "1"},
	} {
		got, err := CanonicalJSON(json.Number(tc.in))
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Fatalf("%q = %s, want %s", tc.in, got, tc.want)
		}
	}
	if _, err := CanonicalJSON(json.Number("10e100000")); err == nil {
		t.Fatal("10e100000 expanded past the digit bound")
	}
	longFrac := "1." + strings.Repeat("0", 100002) + "1"
	if _, err := CanonicalJSON(json.Number(longFrac)); err == nil {
		t.Fatal("a fractional shift past the exponent bound was accepted")
	}
	for _, bad := range []string{"", "-", "01", "1.", "1e", "1e+", "1e-", ".1", "1.2.3", "1ee1"} {
		if _, err := CanonicalJSON(json.Number(bad)); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
	if _, err := LegacyCanonicalJSON(json.Number("")); err == nil {
		t.Fatal("legacy empty JSON number was accepted")
	}
}
