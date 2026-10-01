package verifier

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxExportBytes bounds one export read through the normalizer so a malformed
// file cannot exhaust memory. cmd/aaesverify and store_versions share this
// limit; the open verifier receives the same definition through sync.
const MaxExportBytes = 1 << 30

// ErrUnsupportedSchema names a file whose schema string no reader accepts.
var ErrUnsupportedSchema = errors.New("verifier: unsupported export schema")

// NormalizeExportSchema maps a schema string to the supported version it
// verifies as. ok is false for every retired or unknown identifier.
func NormalizeExportSchema(schema string) (canonical string, ok bool) {
	switch schema {
	case ExportSchemaV2:
		return ExportSchemaV2, true
	}
	return "", false
}

// NormalizeExportReader validates the current header schema and returns the
// original bytes unchanged. Retired formats are refused, never rewritten.
// One export may not exceed MaxExportBytes.
func NormalizeExportReader(r io.Reader) ([]byte, error) {
	return normalizeExportReaderLimited(r, MaxExportBytes)
}

// normalizeExportReaderLimited is NormalizeExportReader with a caller-chosen
// size bound. Tests use a small limit; production passes MaxExportBytes.
func normalizeExportReaderLimited(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	tr := io.TeeReader(io.LimitReader(r, limit+1), &buf)
	sc := bufio.NewScanner(tr)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read export: %w", err)
		}
		return nil, fmt.Errorf("%w: file is empty", ErrUnsupportedSchema)
	}
	first := bytes.TrimSpace(sc.Bytes())
	var header map[string]json.RawMessage
	if err := json.Unmarshal(first, &header); err != nil {
		return nil, fmt.Errorf("first line is not an export header: %w", err)
	}
	typeStr, err := rawJSONString(header["type"])
	if err != nil {
		return nil, fmt.Errorf("first line is not an export header: %w", err)
	}
	if typeStr != "header" {
		return nil, fmt.Errorf("first line is a %q line, not a header", typeStr)
	}
	schema, err := rawJSONString(header["schema"])
	if err != nil {
		return nil, fmt.Errorf("%w: missing or invalid schema field", ErrUnsupportedSchema)
	}
	_, ok := NormalizeExportSchema(schema)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedSchema, schema)
	}
	if _, err := io.Copy(io.Discard, tr); err != nil {
		return nil, fmt.Errorf("read export: %w", err)
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("export exceeds the %d-byte size limit", limit)
	}
	return buf.Bytes(), nil
}

func rawJSONString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("missing string field")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}
