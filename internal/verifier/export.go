package verifier

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// ExportSchemaV2 is the retained integer-amount JSONL schema.
// The strings are duplicated because this package must not import the producer.
const ExportSchemaV2 = "aaes.export/v2"

// ExportSchemaV3 is the current schema identifier. Callers that bind a sidecar
// to "the export this build writes" should use this constant.
const ExportSchemaV3 = "aaes.export/v3"

const ExportSchema = ExportSchemaV3

// Line types.
const (
	lineHeader = "header"
	lineEntry  = "entry"
	lineAnchor = "anchor"
)

// MaxLineBytes bounds one JSONL line. Entries are a few hundred bytes; the
// limit exists so a malformed file cannot exhaust memory. The normaliser and
// store_versions tests share this bound.
const MaxLineBytes = 4 << 20

// ExportFile is a parsed export.
type ExportFile struct {
	Path    string
	Header  HeaderView
	Entries []EntryView
	Anchors []AnchorView
}

// HeaderView is the export header line.
type HeaderView struct {
	SignatureAlgorithm string        `json:"signature_algorithm,omitempty"`
	Schema             string        `json:"schema"`
	LogID              string        `json:"log_id"`
	TenantID           string        `json:"tenant_id"`
	ExportedAt         time.Time     `json:"exported_at"`
	EntryCount         uint64        `json:"entry_count"`
	Head               hash.TreeHead `json:"head"`
	PublicKey          string        `json:"public_key,omitempty"`
	// PreAnchor is the honest flag for an export written before the first
	// anchor interval. Without it, an anchorless export fails: the format
	// supports anchors, so their absence is incomplete evidence rather than a
	// passing history.
	PreAnchor bool `json:"pre_anchor,omitempty"`
}

// TimestampView mirrors audit.TimestampToken.
type TimestampView struct {
	Authority string    `json:"authority"`
	Digest    string    `json:"digest"`
	Time      time.Time `json:"time"`
	Token     []byte    `json:"token,omitempty"`
	Noop      bool      `json:"noop,omitempty"`
	Verified  string    `json:"verified,omitempty"`
}

// WitnessView mirrors audit.WitnessSignature. PublicKey is present so an
// auditor can check the countersignature without asking AAES for the key.
type WitnessView struct {
	WitnessID string    `json:"witness_id"`
	PublicKey []byte    `json:"public_key,omitempty"`
	Signature []byte    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
	// KeyHolder is an informational custody declaration. Independent verification
	// requires a witness identity pinned by the caller, regardless of this label.
	KeyHolder string `json:"key_holder,omitempty"`
}

// AnchorView mirrors audit.Anchor.
type AnchorView struct {
	Head hash.TreeHead `json:"head"`
	// KeyID and Algorithm name the key that signed Head, when the export records
	// them. They are additive: an export written before key custody existed omits
	// them and the reader falls back to the key supplied out of band. They are
	// carried so a resume can resolve the right verifier after a rotation, and so
	// a mismatch is visible rather than silent - this verifier still checks the
	// head against the supplied key, so an anchor signed by a rotated key fails
	// closed until that key is supplied.
	KeyID     string         `json:"key_id,omitempty"`
	Algorithm string         `json:"algorithm,omitempty"`
	Timestamp *TimestampView `json:"timestamp,omitempty"`
	Witnesses []WitnessView  `json:"witnesses,omitempty"`
}

// exportLine is the union of every line shape. EntryView is embedded so its
// json tags are promoted; the remaining fields are unique to the header,
// anchor and receipt lines.
type exportLine struct {
	Type string `json:"type"`
	EntryView
	SignatureAlgorithm string         `json:"signature_algorithm"`
	Schema             string         `json:"schema"`
	LogID              string         `json:"log_id"`
	ExportedAt         time.Time      `json:"exported_at"`
	EntryCount         uint64         `json:"entry_count"`
	Head               *hash.TreeHead `json:"head"`
	PublicKey          string         `json:"public_key"`
	PreAnchor          bool           `json:"pre_anchor"`
	KeyID              string         `json:"key_id"`
	Algorithm          string         `json:"algorithm"`
	Timestamp          *TimestampView `json:"timestamp"`
	Witnesses          []WitnessView  `json:"witnesses"`
	// AmountUSD only detects the retired floating-point amount field, which
	// fails closed when present on an entry line, even as null.
	AmountUSD json.RawMessage `json:"amount_usd"`
}

// LoadExport reads an exported JSONL log from disk.
func LoadExport(path string) (*ExportFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("verifier: open export: %w", err)
	}
	defer f.Close()
	exp, err := LoadExportReader(f)
	if err != nil {
		return nil, err
	}
	exp.Path = path
	return exp, nil
}

// LoadExportReader parses an exported JSONL log.
func LoadExportReader(r io.Reader) (*ExportFile, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)
	exp := &ExportFile{}
	lineNo := 0
	sawHeader := false
	for sc.Scan() {
		lineNo++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
		}
		switch probe.Type {
		case lineHeader:
			hdr, err := decodeHeaderLine(raw, sawHeader, lineNo)
			if err != nil {
				return nil, err
			}
			sawHeader = true
			exp.Header = hdr
		case lineEntry:
			if !sawHeader {
				return nil, fmt.Errorf("%w: line %d: header must be the first line", ErrMalformed, lineNo)
			}
			entry, err := decodeEntryLine(raw, exp.Header.Schema, lineNo)
			if err != nil {
				return nil, err
			}
			exp.Entries = append(exp.Entries, entry)
		case lineAnchor:
			if !sawHeader {
				return nil, fmt.Errorf("%w: line %d: header must be the first line", ErrMalformed, lineNo)
			}
			a, err := decodeAnchorLine(raw, lineNo)
			if err != nil {
				return nil, err
			}
			exp.Anchors = append(exp.Anchors, a)
		case "":
			return nil, fmt.Errorf("%w: line %d: missing type discriminator", ErrMalformed, lineNo)
		default:
			return nil, fmt.Errorf("%w: line %d: unknown line type %q", ErrMalformed, lineNo, probe.Type)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: read export: %v", ErrMalformed, err)
	}
	if !sawHeader {
		return nil, fmt.Errorf("%w: no header line", ErrMalformed)
	}
	return exp, nil
}

func decodeHeaderLine(raw []byte, sawHeader bool, lineNo int) (HeaderView, error) {
	if sawHeader {
		return HeaderView{}, fmt.Errorf("%w: line %d: duplicate header", ErrMalformed, lineNo)
	}
	var line exportLine
	if err := json.Unmarshal(raw, &line); err != nil {
		return HeaderView{}, fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
	}
	hdr := HeaderView{
		SignatureAlgorithm: line.SignatureAlgorithm,
		Schema:             line.Schema,
		LogID:              line.LogID,
		TenantID:           line.TenantID,
		ExportedAt:         line.ExportedAt,
		EntryCount:         line.EntryCount,
		PublicKey:          line.PublicKey,
		PreAnchor:          line.PreAnchor,
	}
	if line.Head != nil {
		hdr.Head = *line.Head
	}
	return hdr, nil
}

func decodeAnchorLine(raw []byte, lineNo int) (AnchorView, error) {
	var line exportLine
	if err := json.Unmarshal(raw, &line); err != nil {
		return AnchorView{}, fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
	}
	a := AnchorView{KeyID: line.KeyID, Algorithm: line.Algorithm, Timestamp: line.Timestamp, Witnesses: line.Witnesses}
	if line.Head != nil {
		a.Head = *line.Head
	}
	return a, nil
}

// decodeEntryLine reads only the current wire format. Retired schemas and
// the legacy floating-point amount field fail closed, including mixed layouts.
func decodeEntryLine(raw []byte, schema string, lineNo int) (EntryView, error) {
	if schema != ExportSchemaV2 && schema != ExportSchemaV3 {
		return EntryView{}, fmt.Errorf("%w: line %d: %q; re-export as %s", ErrSchema, lineNo, schema, ExportSchema)
	}
	// One decode serves both checks. A syntax error populates nothing, so it
	// still reports as malformed; a type error elsewhere on a line that also
	// carries amount_usd still reports the retired field first.
	var line exportLine
	err := json.Unmarshal(raw, &line)
	if line.AmountUSD != nil {
		return EntryView{}, fmt.Errorf("%w: line %d: legacy amount_usd is not valid in %s", ErrSchema, lineNo, schema)
	}
	if err != nil {
		return EntryView{}, fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
	}
	return line.EntryView, nil
}
