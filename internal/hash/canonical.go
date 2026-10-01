// Package hash provides canonical encoding and SHA-256 primitives.
//
// CanonicalJSON exists so two independent encoders cannot disagree on the bytes
// of the same value: object keys are sorted, integers are emitted exactly, and
// non-finite floats are rejected.
//
// Numeric canonicalisation does not round-trip JSON numbers through float64.
// Every JSON number spelling (integer, decimal, exponent) is normalised with
// exact decimal mantissa/exponent arithmetic, so 9007199254740993,
// 9007199254740993.0 and 9007199254740993e0 are byte-identical, and values
// outside the IEEE-754 53-bit range stay distinct. Native Go float64 values still
// use binary64 formatting because they are already rounded.
//
// LegacyCanonicalJSON / LegacyHashObject freeze the pre-exact behavior
// (json.Unmarshal into float64, then the finite-float formatter). They exist
// only so historical v1 journal records can be re-derived; new seals and v2
// verification use CanonicalJSON.
package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"time"
)

// CanonicalJSON renders v deterministically with exact JSON-number arithmetic.
func CanonicalJSON(v any) ([]byte, error) {
	return canonicalJSON(v, false)
}

// LegacyCanonicalJSON renders v with the historical float64 round-trip. It is
// the frozen encoder for verifying records sealed before exact integers.
func LegacyCanonicalJSON(v any) ([]byte, error) {
	return canonicalJSON(v, true)
}

func canonicalJSON(v any, legacy bool) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v, legacy); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any, legacy bool) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		writeBool(buf, t)
	case json.Number:
		return writeNumber(buf, t, legacy)
	case string:
		b, _ := json.Marshal(t)
		buf.Write(b)
	case int, int8, int16, int32, int64:
		writeSignedInt(buf, t)
	case uint, uint8, uint16, uint32, uint64:
		writeUnsignedInt(buf, t)
	case float32:
		return writeFloat(buf, float64(t))
	case float64:
		return writeFloat(buf, t)
	case time.Time:
		buf.WriteString(strconv.Quote(t.UTC().Format(time.RFC3339Nano)))
	case json.RawMessage:
		return writeRawMessage(buf, t, legacy)
	case []any:
		return writeCanonicalSlice(buf, t, legacy)
	case map[string]any:
		return writeCanonicalMap(buf, t, legacy)
	default:
		return writeCanonicalOther(buf, v, legacy)
	}
	return nil
}

// writeBool writes a JSON boolean literal.
func writeBool(buf *bytes.Buffer, t bool) {
	if t {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
}

// writeNumber writes a JSON number with the exact or the legacy encoder,
// according to the mode the caller chose.
func writeNumber(buf *bytes.Buffer, n json.Number, legacy bool) error {
	if legacy {
		return writeLegacyJSONNumber(buf, n)
	}
	return writeJSONNumber(buf, n)
}

// writeRawMessage decodes embedded JSON and re-encodes it canonically, so raw
// bytes adopt the same rules as the value around them.
func writeRawMessage(buf *bytes.Buffer, raw json.RawMessage, legacy bool) error {
	decoded, err := decodeJSON(raw, legacy)
	if err != nil {
		return fmt.Errorf("hash: raw message is not valid JSON: %w", err)
	}
	return writeCanonical(buf, decoded, legacy)
}

// writeCanonicalSlice writes a slice in order inside JSON array syntax.
func writeCanonicalSlice(buf *bytes.Buffer, list []any, legacy bool) error {
	buf.WriteByte('[')
	for i, e := range list {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, e, legacy); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

// writeCanonicalMap writes object keys in sorted order, because two encoders
// must not disagree on the bytes of the same value.
func writeCanonicalMap(buf *bytes.Buffer, obj map[string]any, legacy bool) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		if err := writeCanonical(buf, obj[k], legacy); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// writeCanonicalOther canonicalises any remaining value by round-tripping it
// through its JSON encoding, so types with json tags canonicalise uniformly.
func writeCanonicalOther(buf *bytes.Buffer, v any, legacy bool) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("hash: unsupported type %T: %w", v, err)
	}
	decoded, err := decodeJSON(b, legacy)
	if err != nil {
		return err
	}
	return writeCanonical(buf, decoded, legacy)
}

func writeFloat(buf *bytes.Buffer, t float64) error {
	if math.IsNaN(t) || math.IsInf(t, 0) {
		return fmt.Errorf("hash: non-finite float cannot be canonicalised")
	}
	if t == math.Trunc(t) && math.Abs(t) < 1e15 {
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	} else {
		buf.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
	}
	return nil
}

// writeJSONNumber emits a JSON number without a float64 round-trip. Every
// spelling (integer, decimal, exponent) is reduced with exact decimal
// arithmetic so distinct integers stay distinct and equivalent spellings
// collide on purpose.
func writeJSONNumber(buf *bytes.Buffer, n json.Number) error {
	canon, err := canonicalJSONNumber(string(n))
	if err != nil {
		return err
	}
	buf.WriteString(canon)
	return nil
}

func writeLegacyJSONNumber(buf *bytes.Buffer, n json.Number) error {
	s := string(n)
	if s == "" {
		return fmt.Errorf("hash: empty JSON number")
	}
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("hash: JSON number %q: %w", s, err)
	}
	return writeFloat(buf, f)
}

func decodeJSON(b []byte, legacy bool) (any, error) {
	if legacy {
		var decoded any
		if err := json.Unmarshal(b, &decoded); err != nil {
			return nil, err
		}
		return decoded, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("hash: trailing JSON after the first value")
		}
		return nil, fmt.Errorf("hash: trailing JSON after the first value: %w", err)
	}
	return decoded, nil
}

// SHA256Hex returns the hex-encoded SHA-256 of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashObject canonicalises v and hashes it.
func HashObject(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(b), nil
}

// LegacyHashObject hashes v with the frozen float64 canonicaliser.
func LegacyHashObject(v any) (string, error) {
	b, err := LegacyCanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(b), nil
}

// Chain links an entry to the previous hash. prevHash may be empty for genesis.
func Chain(prevHash string, entry []byte) string {
	buf := make([]byte, 0, 64+len(entry))
	if prevHash == "" {
		buf = append(buf, []byte("aaes/genesis")...)
	} else {
		buf = append(buf, []byte(prevHash)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, entry...)
	return SHA256Hex(buf)
}
