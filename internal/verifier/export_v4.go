package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// This file and its export_v4_* siblings implement the aaes.export/v4 wire
// foundation of docs/engineering/EXPORT-SCHEMA-V4-DESIGN.md: typed receipt,
// approval and summary leaves alongside the unchanged v2/v3 decision entry.
// The rules that matter here are section 4.2's strict decoding (closed field
// lists, no duplicate member names at any depth, no explicit nulls, no
// trailing JSON) and the required-present / optional-empty presence semantics
// of sections 4.5, 4.6 and 5.

// ExportSchemaV4 is the v4 schema identifier. ExportSchema deliberately
// remains v3 until the v4 producer ships.
const ExportSchemaV4 = "aaes.export/v4"

// V4 line types.
const (
	lineReceiptV4  = "receipt"
	lineApprovalV4 = "approval"
	lineSummaryV4  = "summary"
)

// ReceiptBundleSchemaV1 is the pinned wire schema of the standalone receipt
// proof bundle (design section 4.9).
const ReceiptBundleSchemaV1 = "aaes.receipt-proof/v1"

// SummaryProfileGovernanceAuditV1 is the reserved summary profile whose
// minimum body contract is frozen in design section 5.2.
const SummaryProfileGovernanceAuditV1 = "aaes.governance-audit/v1"

// maxSummaryInputsV4 bounds a summary's typed input list (design section 5.1).
const maxSummaryInputsV4 = 64

// memberFrameV4 is one open container in the rejectDuplicateMembers walk. An
// object frame alternates key/value; expectKey is also true on an empty
// object so its closing brace lands in the delimiter branch rather than
// reading as a key.
type memberFrameV4 struct {
	object    bool
	expectKey bool
	seen      map[string]struct{}
}

// rejectDuplicateMembers token-walks raw and refuses two things a typed
// decoder cannot see: a repeated member name in the same object at ANY
// nesting level, and an explicit JSON null anywhere in the value. Two parsers
// must never be able to select different values for one member, and null is
// never a legal v4 member value — it is neither a required-present zero nor a
// substitute for an omitted optional member. Numbers decode to float64 here;
// the walk is structural only and never re-encodes them.
func rejectDuplicateMembers(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var stack []memberFrameV4
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		var werr error
		if stack, werr = walkMemberTokenV4(stack, tok); werr != nil {
			return werr
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("%w: unbalanced containers", ErrMalformed)
	}
	return nil
}

// walkMemberTokenV4 folds one token into the container stack.
func walkMemberTokenV4(stack []memberFrameV4, tok any) ([]memberFrameV4, error) {
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			return append(stack, memberFrameV4{object: true, expectKey: true, seen: map[string]struct{}{}}), nil
		case '[':
			return append(stack, memberFrameV4{}), nil
		case '}', ']':
			if len(stack) == 0 || (d == '}') != stack[len(stack)-1].object {
				return nil, fmt.Errorf("%w: unbalanced %q", ErrMalformed, string(d))
			}
			stack = stack[:len(stack)-1]
			markValueCompleteV4(stack)
			return stack, nil
		}
	}
	if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("%w: object member name expected", ErrMalformed)
		}
		top := &stack[len(stack)-1]
		if _, dup := top.seen[key]; dup {
			return nil, fmt.Errorf("%w: duplicate member %q", ErrMalformed, key)
		}
		top.seen[key] = struct{}{}
		top.expectKey = false
		return stack, nil
	}
	if tok == nil {
		return nil, fmt.Errorf("%w: explicit null is not a legal v4 member value", ErrMalformed)
	}
	markValueCompleteV4(stack)
	return stack, nil
}

// markValueCompleteV4 records that a scalar or a closed container completed a
// member value, so an enclosing object frame expects the next key.
func markValueCompleteV4(stack []memberFrameV4) {
	if len(stack) > 0 && stack[len(stack)-1].object {
		stack[len(stack)-1].expectKey = true
	}
}

// decodeStrictV4 decodes one v4 wire value under design section 4.2: no
// duplicate member names or explicit nulls (rejectDuplicateMembers), no
// unknown members on any closed struct (DisallowUnknownFields applies to
// every nesting level), and no trailing JSON after the value.
func decodeStrictV4(raw []byte, v any) error {
	if err := checkStrictJSON(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}

// missingV4 reports an absent required-present member. Null never reaches
// here — the token walk refused it — so a nil pointer after decode means the
// member was omitted, and omission of a required member is never a signal to
// apply a default.
func missingV4(member string) error {
	return fmt.Errorf("%w: %s is required and must be present", ErrMalformed, member)
}

// refuseEmptyV4 enforces optional-empty: a member that is present must carry
// a nonempty value, because a present-but-empty optional member is not a
// canonical alternative to omission.
func refuseEmptyV4(member string, p *string) error {
	if p != nil && *p == "" {
		return fmt.Errorf("%w: %s is optional and must be omitted, not present but empty", ErrMalformed, member)
	}
	return nil
}

// refuseZeroTimeV4 is refuseEmptyV4 for optional timestamps.
func refuseZeroTimeV4(member string, p *time.Time) error {
	if p != nil && p.IsZero() {
		return fmt.Errorf("%w: %s is optional and must be omitted, not present but zero", ErrMalformed, member)
	}
	return nil
}

// presenceV4 is one required-present member check: name and whether the
// member appeared on the wire.
type presenceV4 struct {
	name string
	ok   bool
}

// optionalStringV4 is one optional-empty string member check.
type optionalStringV4 struct {
	name string
	p    *string
}

// requiredMembersV4 fails on the first absent member of a required-present
// list, keeping the presence checks themselves to one line per member.
func requiredMembersV4(members []presenceV4) error {
	for _, m := range members {
		if !m.ok {
			return missingV4(m.name)
		}
	}
	return nil
}

// optionalStringsV4 fails on the first present-but-empty optional member.
func optionalStringsV4(members []optionalStringV4) error {
	for _, m := range members {
		if err := refuseEmptyV4(m.name, m.p); err != nil {
			return err
		}
	}
	return nil
}
