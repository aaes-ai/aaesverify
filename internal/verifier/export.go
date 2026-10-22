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
	// Receipts carries the v4 typed receipt leaves (design section 4.5). It
	// is empty for v2/v3 exports; the v4 line reader populates it. The
	// evidencepack companion binding consumes it for the section 7.4
	// comparison projection.
	Receipts []ReceiptLeafViewV4
	// Approvals and Summaries carry the v4 approval-state and summary leaves
	// (design sections 4.6 and 5). LeavesV4 is every leaf-bearing line in
	// file order — entries included — because the v4 chain and Merkle root
	// cover every leaf type in that order (design section 4.3).
	Approvals []ApprovalLeafViewV4
	Summaries []SummaryLeafViewV4
	LeavesV4  []LeafV4
	Anchors   []AnchorView
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
	// LeafCount and SigningKeyID are v4-only header members (design section
	// 4.1): the count of every leaf-bearing line, and the required keyring
	// reference the final head resolves through. Both are absent in v2/v3.
	LeafCount    uint64 `json:"leaf_count,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
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

// exportByteCounter counts bytes read so LoadExportReader can refuse a stream
// larger than MaxExportBytes. The limit reader stops one byte past the cap.
type exportByteCounter struct {
	r io.Reader
	n int64
}

func (c *exportByteCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// LoadExportReader parses an exported JSONL log. The header's schema member
// fixes the decoder for the WHOLE file before any body line is read (design
// section 6.1): an unknown or retired schema fails immediately with ErrSchema,
// and a v4 header switches every following line to the strict v4 rules.
func LoadExportReader(r io.Reader) (*ExportFile, error) {
	counted := &exportByteCounter{r: io.LimitReader(r, MaxExportBytes+1)}
	sc := bufio.NewScanner(counted)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)
	exp := &ExportFile{}
	lineNo := 0
	sawHeader := false
	sawAnchor := false
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
		if probe.Type == "" {
			return nil, fmt.Errorf("%w: line %d: missing type discriminator", ErrMalformed, lineNo)
		}
		if !sawHeader {
			if probe.Type != lineHeader {
				return nil, fmt.Errorf("%w: line %d: header must be the first line", ErrMalformed, lineNo)
			}
			hdr, err := decodeHeaderFirst(raw, lineNo)
			if err != nil {
				return nil, err
			}
			sawHeader = true
			exp.Header = hdr
			continue
		}
		if probe.Type == lineHeader {
			return nil, fmt.Errorf("%w: line %d: duplicate header", ErrMalformed, lineNo)
		}
		if exp.Header.Schema == ExportSchemaV4 {
			if err := exp.decodeBodyLineV4(raw, probe.Type, lineNo, &sawAnchor); err != nil {
				return nil, err
			}
			continue
		}
		if err := decodeLegacyBodyLine(exp, raw, probe.Type, lineNo); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: read export: %v", ErrMalformed, err)
	}
	if counted.n > MaxExportBytes {
		return nil, fmt.Errorf("export exceeds the %d-byte size limit", MaxExportBytes)
	}
	if !sawHeader {
		return nil, fmt.Errorf("%w: no header line", ErrMalformed)
	}
	return exp, nil
}
