package verifier

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

// ExportSchema is the JSONL schema this package reads. It matches
// audit.ExportSchema; the strings are duplicated because this package must not
// import the producer.
const ExportSchema = "aaes.export/v1"

// Line types.
const (
	lineHeader = "header"
	lineEntry  = "entry"
	lineAnchor = "anchor"
)

// maxLineBytes bounds one JSONL line. Entries are a few hundred bytes; the
// limit exists so a malformed file cannot exhaust memory.
const maxLineBytes = 4 << 20

// ExportFile is a parsed export.
type ExportFile struct {
	Path    string
	Header  HeaderView
	Entries []EntryView
	Anchors []AnchorView
}

// HeaderView is the export header line.
type HeaderView struct {
	Schema     string        `json:"schema"`
	LogID      string        `json:"log_id"`
	TenantID   string        `json:"tenant_id"`
	ExportedAt time.Time     `json:"exported_at"`
	EntryCount uint64        `json:"entry_count"`
	Head       hash.TreeHead `json:"head"`
	PublicKey  string        `json:"public_key,omitempty"`
	// PreAnchor is the honest flag for an export written before the first
	// anchor interval. Without it, an anchorless aaes.export/v1 file fails:
	// the format supports anchors, so their absence is incomplete evidence
	// rather than a passing history.
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
	Schema     string         `json:"schema"`
	LogID      string         `json:"log_id"`
	ExportedAt time.Time      `json:"exported_at"`
	EntryCount uint64         `json:"entry_count"`
	Head       *hash.TreeHead `json:"head"`
	PublicKey  string         `json:"public_key"`
	PreAnchor  bool           `json:"pre_anchor"`
	KeyID      string         `json:"key_id"`
	Algorithm  string         `json:"algorithm"`
	Timestamp  *TimestampView `json:"timestamp"`
	Witnesses  []WitnessView  `json:"witnesses"`
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
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	exp := &ExportFile{}
	lineNo := 0
	sawHeader := false
	for sc.Scan() {
		lineNo++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var line exportLine
		if err := json.Unmarshal(raw, &line); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
		}
		switch line.Type {
		case lineHeader:
			if sawHeader {
				return nil, fmt.Errorf("%w: line %d: duplicate header", ErrMalformed, lineNo)
			}
			if len(exp.Entries) > 0 || len(exp.Anchors) > 0 {
				return nil, fmt.Errorf("%w: line %d: header must be the first line", ErrMalformed, lineNo)
			}
			sawHeader = true
			exp.Header = HeaderView{
				Schema:     line.Schema,
				LogID:      line.LogID,
				TenantID:   line.TenantID,
				ExportedAt: line.ExportedAt,
				EntryCount: line.EntryCount,
				PublicKey:  line.PublicKey,
				PreAnchor:  line.PreAnchor,
			}
			if line.Head != nil {
				exp.Header.Head = *line.Head
			}
		case lineEntry:
			exp.Entries = append(exp.Entries, line.EntryView)
		case lineAnchor:
			a := AnchorView{KeyID: line.KeyID, Algorithm: line.Algorithm, Timestamp: line.Timestamp, Witnesses: line.Witnesses}
			if line.Head != nil {
				a.Head = *line.Head
			}
			exp.Anchors = append(exp.Anchors, a)
		case "":
			return nil, fmt.Errorf("%w: line %d: missing type discriminator", ErrMalformed, lineNo)
		default:
			return nil, fmt.Errorf("%w: line %d: unknown line type %q", ErrMalformed, lineNo, line.Type)
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
