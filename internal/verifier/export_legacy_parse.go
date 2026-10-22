package verifier

import (
	"encoding/json"
	"fmt"
)

// The v2/v3 line decoders. Every legacy line decodes into exportLine.

// decodeLegacyBodyLine decodes one body line under a v2/v3 header. The v4-only
// typed lines (receipt, approval, summary) remain unknown-type refusals here
// (design section 6.2).
func decodeLegacyBodyLine(exp *ExportFile, raw []byte, typ string, lineNo int) error {
	switch typ {
	case lineEntry:
		entry, err := decodeEntryLine(raw, exp.Header.Schema, lineNo)
		if err != nil {
			return err
		}
		exp.Entries = append(exp.Entries, entry)
	case lineAnchor:
		a, err := decodeAnchorLine(raw, lineNo)
		if err != nil {
			return err
		}
		exp.Anchors = append(exp.Anchors, a)
	default:
		return fmt.Errorf("%w: line %d: unknown line type %q", ErrMalformed, lineNo, typ)
	}
	return nil
}

func decodeHeaderLine(raw []byte, sawHeader bool, lineNo int) (HeaderView, error) {
	if sawHeader {
		return HeaderView{}, fmt.Errorf("%w: line %d: duplicate header", ErrMalformed, lineNo)
	}
	var line exportLine
	if err := decodeLegacyLine(raw, &line); err != nil {
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
	if err := decodeLegacyLine(raw, &line); err != nil {
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
	if err := checkTypedJSONAliases(raw, exportLine{}); err != nil {
		return EntryView{}, fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
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

// decodeLegacyLine decodes one v2/v3 line. encoding/json matches member names
// case-insensitively and keeps the last one, so an added "Actor_ID" would be
// hashed while every other JSON reader shows "actor_id". A member repeated
// exactly or under that case folding is refused before the decode.
func decodeLegacyLine(raw []byte, line *exportLine) error {
	if err := checkTypedJSONAliases(raw, line); err != nil {
		return err
	}
	return json.Unmarshal(raw, line)
}
