package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// The v4 fixtures are built as maps so each refusal case deletes or mutates
// one member of an otherwise valid line. hex64v4 stands in for every hash
// claim; the wire layer checks shape and presence, not hash agreement.
const hex64v4 = "abababababababababababababababababababababababababababababababab"

var (
	v4LinkedAt = "2026-01-02T03:04:06Z"
	v4ZeroTime = "0001-01-01T00:00:00Z"
)

func marshalV4(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

func validReceiptMapV4() map[string]any {
	return map[string]any{
		"receipt_id": "rc-1", "intent_id": "in-1", "tenant_id": "tenant-a",
		"record_hash": "rh-parent", "issued_at": "2026-01-02T03:00:00Z",
		"class": 0, "rail_confirmed": false,
		"confirmed_at": v4ZeroTime, "reported_at": v4ZeroTime, "observed_at": v4ZeroTime,
	}
}

func validReceiptLeafMapV4() map[string]any {
	return map[string]any{
		"type": "receipt", "schema": "aaes.export/v4", "sequence": 42,
		"record_hash": "rh-parent", "linked_at": v4LinkedAt,
		"receipt": validReceiptMapV4(), "chain_hash": hex64v4, "leaf": hex64v4,
	}
}

func validApprovalMapV4() map[string]any {
	return map[string]any{
		"ApprovalID": "ap-1", "TenantID": "tenant-a", "TaskID": "task-1",
		"IntentID": "in-1", "Approver": "alice", "State": 2, "Reason": "",
		"PayloadHash": "ph", "BundleHash": "bh", "EngineVersion": "ev-1",
		"ExpiresAt": "2026-01-03T00:00:00Z", "DecidedAt": "2026-01-02T04:00:00Z",
		"CreatedAt":    "2026-01-02T03:00:00Z",
		"ApproverKind": 0, "ApproverAuthority": 0, "RequesterManagersSource": 0,
	}
}

func validApprovalLeafMapV4() map[string]any {
	return map[string]any{
		"type": "approval", "schema": "aaes.export/v4", "source_sequence": 17,
		"linked_at": v4LinkedAt,
		"approval":  validApprovalMapV4(), "chain_hash": hex64v4, "leaf": hex64v4,
	}
}

// validInputHeadV4 is a complete v4 signed head claim over tenant-a's log.
func validInputHeadV4() map[string]any {
	return map[string]any{
		"algorithm": "ed25519", "schema": "aaes.export/v4",
		"log_id": hash.DeriveLogID("tenant-a"), "index": 7,
		"root_hash": hex64v4, "tree_size": 7,
		"signed_at": "2026-01-02T03:04:05Z", "signature": "AAAA",
	}
}

func validSummaryInputV4() map[string]any {
	return map[string]any{
		"input_id": "in-1", "schema": "aaes.export/v4",
		"tenant_id": "tenant-a", "key_id": "ledger-k2", "head": validInputHeadV4(),
	}
}

func validSummaryBodyMapV4() map[string]any {
	return map[string]any{
		"findings":    []any{map[string]any{"code": "c-1", "input_ids": []any{"in-1"}, "detail": map[string]any{"k": "v"}}},
		"metrics":     map[string]any{"coverage": map[string]any{"value": 0, "input_ids": []any{"in-1"}}},
		"limitations": []any{"none beyond scope"},
	}
}

func validSummaryLeafMapV4() map[string]any {
	return map[string]any{
		"type": "summary", "schema": "aaes.export/v4", "tenant_id": "summary-tenant",
		"summary_id": "sum-1", "profile": "aaes.governance-audit/v1",
		"producer_id": "prod-1", "producer_version": "1.0.0",
		"created_at": "2026-01-02T03:04:05Z",
		"inputs":     []any{validSummaryInputV4()},
		"linked_at":  v4LinkedAt,
		"body":       validSummaryBodyMapV4(),
		"chain_hash": hex64v4, "leaf": hex64v4,
	}
}

func validProofMapV4(index int) map[string]any {
	return map[string]any{
		"index": index, "tree_size": 7,
		"siblings": []any{hex64v4}, "self_siblings": []any{false}, "root_hash": hex64v4,
	}
}

func validParentLeafMapV4() map[string]any {
	return map[string]any{
		"type": "entry", "tenant_id": "tenant-a", "sequence": 1, "record_hash": "rh-parent",
		"intent_id": "in-1", "actor_id": "a-1", "capability": "cap", "tier": 1,
		"allowed": true, "grant_id": "g-1",
		"occurred_at": "2026-01-02T03:00:00Z", "linked_at": "2026-01-02T03:00:01Z",
		"chain_hash": hex64v4, "leaf": hex64v4,
	}
}

func validBundleMapV4() map[string]any {
	return map[string]any{
		"schema": "aaes.receipt-proof/v1", "key_id": "ledger-k2", "head": validInputHeadV4(),
		"parent_leaf": validParentLeafMapV4(), "parent_proof": validProofMapV4(1),
		"receipt_leaf": validReceiptLeafMapV4(), "receipt_proof": validProofMapV4(2),
	}
}

// summaryLineRawBodyV4 renders a valid summary line around a raw body, for
// cases (duplicate member names) a map cannot express.
func summaryLineRawBodyV4(t *testing.T, body string) []byte {
	t.Helper()
	m := validSummaryLeafMapV4()
	delete(m, "body")
	b := marshalV4(t, m)
	s := string(b)
	return []byte(s[:len(s)-1] + `,"body":` + body + "}")
}

func TestDecodeV4PositiveControls(t *testing.T) {
	if _, err := DecodeReceiptLeafV4(marshalV4(t, validReceiptLeafMapV4())); err != nil {
		t.Fatalf("valid receipt leaf refused: %v", err)
	}
	if _, err := DecodeApprovalLeafV4(marshalV4(t, validApprovalLeafMapV4())); err != nil {
		t.Fatalf("valid approval leaf refused: %v", err)
	}
	if _, err := DecodeSummaryLeafV4(marshalV4(t, validSummaryLeafMapV4())); err != nil {
		t.Fatalf("valid summary leaf refused: %v", err)
	}
	if _, err := DecodeReceiptBundleV1(marshalV4(t, validBundleMapV4())); err != nil {
		t.Fatalf("valid receipt bundle refused: %v", err)
	}
}

func TestRejectDuplicateMembersV4(t *testing.T) {
	receiptLine := string(marshalV4(t, validReceiptLeafMapV4()))
	cases := []struct {
		name string
		raw  []byte
	}{
		{"top level", []byte(`{"type":"receipt","type":"receipt","schema":"aaes.export/v4"}`)},
		{"nested receipt", []byte(`{"type":"receipt","receipt":{"receipt_id":"a","receipt_id":"b"}}`)},
		{"external ref element", []byte(`{"type":"receipt","receipt":{"external_refs":[{"registry":"r","registry":"r"}]}}`)},
		{"summary body", summaryLineRawBodyV4(t, `{"limitations":[],"limitations":[]}`)},
		{"summary body finding", summaryLineRawBodyV4(t, `{"findings":[{"code":"a","code":"b","input_ids":["in-1"]}],"limitations":[]}`)},
		{"summary input head", []byte(`{"inputs":[{"head":{"index":1,"index":2}}]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := rejectDuplicateMembers(tc.raw); err == nil || !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed duplicate refusal", err)
			}
		})
	}
	// The same member name in two DIFFERENT objects is not a duplicate:
	// receipt.record_hash and the outer record_hash coexist by design.
	if err := rejectDuplicateMembers([]byte(receiptLine)); err != nil {
		t.Fatalf("same name in different objects refused: %v", err)
	}
}

func TestDecodeStrictV4UnknownMembers(t *testing.T) {
	set := func(m map[string]any, key string, val any, path ...string) map[string]any {
		cur := m
		for _, p := range path {
			cur = cur[p].(map[string]any)
		}
		cur[key] = val
		return m
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"receipt leaf outer", marshalV4(t, set(validReceiptLeafMapV4(), "extra", 1))},
		{"receipt nested", marshalV4(t, set(validReceiptLeafMapV4(), "unknown", 1, "receipt"))},
		{"external ref element", marshalV4(t, set(validReceiptLeafMapV4(), "external_refs", []any{map[string]any{
			"registry": "r", "kind": "k", "value": "v", "source": "registered", "extra": 1}}, "receipt"))},
		{"model usage", marshalV4(t, set(validReceiptLeafMapV4(), "model_usage", map[string]any{
			"input_tokens": 1, "output_tokens": 2, "total_tokens": 3, "settled_minor": 4, "currency": "USD", "extra": 1}, "receipt"))},
		{"approval leaf outer", marshalV4(t, set(validApprovalLeafMapV4(), "extra", 1))},
		{"approval nested", marshalV4(t, set(validApprovalLeafMapV4(), "Zap", 1, "approval"))},
		{"manager entry", marshalV4(t, set(validApprovalLeafMapV4(), "RequesterManagers", []any{map[string]any{
			"ActorID": "m-1", "Kind": 1, "Role": 0, "Primary": true, "Extra": 1}}, "approval"))},
		{"summary leaf outer", marshalV4(t, set(validSummaryLeafMapV4(), "extra", 1))},
		{"summary input", marshalV4(t, set(validSummaryLeafMapV4(), "inputs", []any{set(validSummaryInputV4(), "extra", 1)}))},
		{"summary input head", marshalV4(t, set(validSummaryLeafMapV4(), "inputs", []any{set(validSummaryInputV4(), "extra", 1, "head")}))},
		{"producer signature", marshalV4(t, set(validSummaryLeafMapV4(), "producer_signature", map[string]any{
			"algorithm": "ed25519", "key_id": "k", "signature": "AAAA", "extra": 1}))},
		{"bundle top", marshalV4(t, set(validBundleMapV4(), "extra", 1))},
		{"bundle head", marshalV4(t, set(validBundleMapV4(), "surprise", 1, "head"))},
		{"bundle proof", marshalV4(t, set(validBundleMapV4(), "surprise", 1, "parent_proof"))},
		{"bundle parent leaf", marshalV4(t, set(validBundleMapV4(), "surprise", 1, "parent_leaf"))},
		{"bundle receipt leaf", marshalV4(t, set(validBundleMapV4(), "surprise", 1, "receipt_leaf"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			switch {
			case strings.HasPrefix(tc.name, "receipt"):
				_, err = DecodeReceiptLeafV4(tc.raw)
			case strings.HasPrefix(tc.name, "approval"):
				_, err = DecodeApprovalLeafV4(tc.raw)
			case strings.HasPrefix(tc.name, "summary"):
				_, err = DecodeSummaryLeafV4(tc.raw)
			default:
				_, err = DecodeReceiptBundleV1(tc.raw)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed unknown-member refusal", err)
			}
		})
	}
	// Additional members inside the profile-owned summary body are allowed.
	leaf := validSummaryLeafMapV4()
	leaf["body"] = map[string]any{"limitations": []any{}, "profile_owned": map[string]any{"anything": true}}
	if _, err := DecodeSummaryLeafV4(marshalV4(t, leaf)); err != nil {
		t.Fatalf("profile-owned body member refused: %v", err)
	}
}

func TestDecodeStrictV4TrailingJSON(t *testing.T) {
	line := marshalV4(t, validReceiptLeafMapV4())
	for _, suffix := range []string{" {}", " 42", ` "x"`, " {"} {
		if _, err := DecodeReceiptLeafV4(append(append([]byte{}, line...), suffix...)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("suffix %q: err = %v, want ErrMalformed", suffix, err)
		}
	}
}

func TestDecodeStrictV4RefusesNulls(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"required outer", []byte(`{"type":"receipt","linked_at":null}`)},
		{"optional nested", marshalV4(t, func() map[string]any {
			m := validReceiptLeafMapV4()
			m["receipt"].(map[string]any)["note"] = nil
			return m
		}())},
		{"required nested", marshalV4(t, func() map[string]any {
			m := validApprovalLeafMapV4()
			m["approval"].(map[string]any)["Approver"] = nil
			return m
		}())},
		{"summary body", summaryLineRawBodyV4(t, `{"limitations":null}`)},
		{"producer signature key", marshalV4(t, func() map[string]any {
			m := validSummaryLeafMapV4()
			m["producer_signature"] = map[string]any{"algorithm": "ed25519", "key_id": nil, "signature": "AAAA"}
			return m
		}())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := rejectDuplicateMembers(tc.raw); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed null refusal", err)
			}
		})
	}
}

func TestReceiptLeafV4RequiredPresence(t *testing.T) {
	for _, m := range []string{"type", "schema", "sequence", "record_hash", "linked_at", "receipt", "chain_hash", "leaf"} {
		t.Run("outer/"+m, func(t *testing.T) {
			line := validReceiptLeafMapV4()
			delete(line, m)
			if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	for _, m := range []string{"receipt_id", "intent_id", "tenant_id", "record_hash", "issued_at", "class", "rail_confirmed", "confirmed_at", "reported_at", "observed_at"} {
		t.Run("receipt/"+m, func(t *testing.T) {
			line := validReceiptLeafMapV4()
			delete(line["receipt"].(map[string]any), m)
			if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	// An omitted required member must not silently default, even to zero.
	line := validReceiptLeafMapV4()
	delete(line["receipt"].(map[string]any), "rail_confirmed")
	if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); err == nil {
		t.Fatal("omitted rail_confirmed must not default to false")
	}
}

func TestReceiptLeafV4OptionalEmpty(t *testing.T) {
	for _, m := range []string{
		"execution_state", "task_id", "approval_id", "custody", "grant_id", "effect_id", "effect",
		"result_mode", "result_content_type", "result_digest", "result_resource_id",
		"reported_by", "reported_outcome", "note",
		"resolves_deferral_id", "resolved_record_id", "policy_bundle_hash", "input_hash", "engine_version",
	} {
		t.Run("empty/"+m, func(t *testing.T) {
			line := validReceiptLeafMapV4()
			line["receipt"].(map[string]any)[m] = ""
			if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
		t.Run("null/"+m, func(t *testing.T) {
			line := validReceiptLeafMapV4()
			line["receipt"].(map[string]any)[m] = nil
			if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("empty external_refs", func(t *testing.T) {
		line := validReceiptLeafMapV4()
		line["receipt"].(map[string]any)["external_refs"] = []any{}
		if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("zero observation_expires_at", func(t *testing.T) {
		line := validReceiptLeafMapV4()
		line["receipt"].(map[string]any)["observation_expires_at"] = v4ZeroTime
		if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	// Every external_refs element member is required-present.
	for _, m := range []string{"registry", "kind", "value", "source"} {
		t.Run("external_ref missing "+m, func(t *testing.T) {
			ref := map[string]any{"registry": "r", "kind": "k", "value": "v", "source": "registered"}
			delete(ref, m)
			line := validReceiptLeafMapV4()
			line["receipt"].(map[string]any)["external_refs"] = []any{ref}
			if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	// When model_usage is present, all five members are required-present,
	// including zero values.
	for _, m := range []string{"input_tokens", "output_tokens", "total_tokens", "settled_minor", "currency"} {
		t.Run("model_usage missing "+m, func(t *testing.T) {
			usage := map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "settled_minor": 0, "currency": ""}
			delete(usage, m)
			line := validReceiptLeafMapV4()
			line["receipt"].(map[string]any)["model_usage"] = usage
			if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("model_usage zeros accepted", func(t *testing.T) {
		line := validReceiptLeafMapV4()
		line["receipt"].(map[string]any)["model_usage"] = map[string]any{
			"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "settled_minor": 0, "currency": ""}
		if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); err != nil {
			t.Fatalf("zero-valued model_usage refused: %v", err)
		}
	})
}

// TestReceiptLeafV4RequiredZerosAccepted pins the required-present zeros of
// section 4.5: class 0, rail_confirmed false, the zero value timestamps, and
// the conditional payload_returned false / result_bytes 0 pair.
func TestReceiptLeafV4RequiredZerosAccepted(t *testing.T) {
	// The base fixture already carries class 0, rail_confirmed false and the
	// three zero timestamps; the positive control decodes it.
	line := validReceiptLeafMapV4()
	r := line["receipt"].(map[string]any)
	r["result_mode"] = "inline"
	r["payload_returned"] = false
	r["result_bytes"] = 0
	leaf, err := DecodeReceiptLeafV4(marshalV4(t, line))
	if err != nil {
		t.Fatalf("required zeros refused: %v", err)
	}
	if *leaf.Receipt.Class != 0 || *leaf.Receipt.RailConfirmed || !leaf.Receipt.ConfirmedAt.IsZero() {
		t.Fatalf("zeros did not decode as explicit values: %+v", leaf.Receipt)
	}
}

func TestReceiptResultGroupV4(t *testing.T) {
	mutate := []struct {
		name string
		f    func(r map[string]any)
	}{
		{"result_mode without payload_returned", func(r map[string]any) { r["result_mode"] = "inline" }},
		{"result_mode without result_bytes", func(r map[string]any) {
			r["result_mode"] = "inline"
			r["payload_returned"] = true
		}},
		{"payload_returned without result_mode", func(r map[string]any) { r["payload_returned"] = true }},
		{"result_bytes without result_mode", func(r map[string]any) { r["result_bytes"] = 10 }},
	}
	for _, tc := range mutate {
		t.Run(tc.name, func(t *testing.T) {
			line := validReceiptLeafMapV4()
			tc.f(line["receipt"].(map[string]any))
			if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	// The remaining result members are independently optional-empty: one may
	// appear without its siblings and without result_mode.
	line := validReceiptLeafMapV4()
	line["receipt"].(map[string]any)["result_digest"] = hex64v4
	if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); err != nil {
		t.Fatalf("independent result_digest refused: %v", err)
	}
}

func TestReceiptClassRangeV4(t *testing.T) {
	for _, class := range []int{0, 1, 2, 3, 4} {
		line := validReceiptLeafMapV4()
		line["receipt"].(map[string]any)["class"] = class
		if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); err != nil {
			t.Fatalf("class %d refused: %v", class, err)
		}
	}
	for _, class := range []int{-1, 5, 99} {
		line := validReceiptLeafMapV4()
		line["receipt"].(map[string]any)["class"] = class
		if _, err := DecodeReceiptLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("class %d: err = %v, want ErrMalformed", class, err)
		}
	}
}

func TestApprovalLeafV4RequiredPresence(t *testing.T) {
	for _, m := range []string{"type", "schema", "source_sequence", "linked_at", "approval", "chain_hash", "leaf"} {
		t.Run("outer/"+m, func(t *testing.T) {
			line := validApprovalLeafMapV4()
			delete(line, m)
			if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	for _, m := range []string{
		"ApprovalID", "TenantID", "TaskID", "IntentID", "Approver", "State", "Reason",
		"PayloadHash", "BundleHash", "EngineVersion", "ExpiresAt", "DecidedAt", "CreatedAt",
		"ApproverKind", "ApproverAuthority", "RequesterManagersSource",
	} {
		t.Run("approval/"+m, func(t *testing.T) {
			line := validApprovalLeafMapV4()
			delete(line["approval"].(map[string]any), m)
			if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// TestApprovalLeafV4ZerosAccepted pins the section 4.6 zero encodings:
// ApproverKind 0, ApproverAuthority 0, RequesterManagersSource 0, an empty
// Reason, State 0 (refused later by the section 4.8 persisted-record checks,
// not at the wire), and a manager entry with zero kind/role and Primary
// false. The base fixture already carries the first four.
func TestApprovalLeafV4ZerosAccepted(t *testing.T) {
	line := validApprovalLeafMapV4()
	line["approval"].(map[string]any)["State"] = 0
	line["approval"].(map[string]any)["RequesterManagers"] = []any{
		map[string]any{"ActorID": "m-1", "Kind": 0, "Role": 0, "Primary": false},
	}
	leaf, err := DecodeApprovalLeafV4(marshalV4(t, line))
	if err != nil {
		t.Fatalf("required zeros refused: %v", err)
	}
	if *leaf.Approval.Reason != "" || *leaf.Approval.ApproverKind != 0 {
		t.Fatalf("zeros did not decode as explicit values: %+v", leaf.Approval)
	}
	if *leaf.Approval.RequesterManagers[0].Primary {
		t.Fatal("Primary:false did not decode as an explicit value")
	}
}

func TestApprovalLeafV4Enums(t *testing.T) {
	cases := []struct {
		name string
		key  string
		val  any
	}{
		{"State over range", "State", 5},
		{"ApproverKind over range", "ApproverKind", 3},
		{"ApproverAuthority over range", "ApproverAuthority", 2},
		{"RequesterManagersSource over range", "RequesterManagersSource", 3},
		{"ApproverModelSource off vocabulary", "ApproverModelSource", "bogus"},
		{"ApproverModelSource empty", "ApproverModelSource", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := validApprovalLeafMapV4()
			line["approval"].(map[string]any)[tc.key] = tc.val
			if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	for _, source := range []string{"unknown", "registered"} {
		line := validApprovalLeafMapV4()
		line["approval"].(map[string]any)["ApproverModelSource"] = source
		if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); err != nil {
			t.Fatalf("ApproverModelSource %q refused: %v", source, err)
		}
	}
	// Manager kind and role are closed vocabularies too.
	line := validApprovalLeafMapV4()
	line["approval"].(map[string]any)["RequesterManagers"] = []any{
		map[string]any{"ActorID": "m-1", "Kind": 2, "Role": 0, "Primary": false}}
	if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("manager kind 2: err = %v, want ErrMalformed", err)
	}
	line = validApprovalLeafMapV4()
	line["approval"].(map[string]any)["RequesterManagers"] = []any{
		map[string]any{"ActorID": "m-1", "Kind": 1, "Role": 3, "Primary": false}}
	if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("manager role 3: err = %v, want ErrMalformed", err)
	}
	// source_sequence is a positive global store position.
	line = validApprovalLeafMapV4()
	line["source_sequence"] = 0
	if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("source_sequence 0: err = %v, want ErrMalformed", err)
	}
}

func TestApprovalLeafV4OptionalEmpty(t *testing.T) {
	for _, m := range []string{
		"RequestRecordID", "ApproverSponsor", "ApproverModelProvider", "ApproverModelFamily",
		"ApproverModel", "Requester", "InitiatedBy", "RequesterSponsor",
		"RequesterModelProvider", "RequesterModelFamily", "RequesterModel",
		"Sponsor", "Action", "ApprovalPolicyID",
	} {
		t.Run("empty/"+m, func(t *testing.T) {
			line := validApprovalLeafMapV4()
			line["approval"].(map[string]any)[m] = ""
			if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("empty RequesterManagers", func(t *testing.T) {
		line := validApprovalLeafMapV4()
		line["approval"].(map[string]any)["RequesterManagers"] = []any{}
		if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	// Every manager entry member is required-present.
	for _, m := range []string{"ActorID", "Kind", "Role", "Primary"} {
		t.Run("manager missing "+m, func(t *testing.T) {
			entry := map[string]any{"ActorID": "m-1", "Kind": 1, "Role": 0, "Primary": true}
			delete(entry, m)
			line := validApprovalLeafMapV4()
			line["approval"].(map[string]any)["RequesterManagers"] = []any{entry}
			if _, err := DecodeApprovalLeafV4(marshalV4(t, line)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestSummaryLeafV4Envelope(t *testing.T) {
	refuse := []struct {
		name string
		f    func(m map[string]any)
	}{
		{"zero inputs", func(m map[string]any) { m["inputs"] = []any{} }},
		{"missing inputs", func(m map[string]any) { delete(m, "inputs") }},
		{"duplicate input_id", func(m map[string]any) {
			dup := validSummaryInputV4()
			dup["head"].(map[string]any)["tree_size"] = 8
			m["inputs"] = []any{validSummaryInputV4(), dup}
		}},
		{"duplicate logical state across schemas", func(m map[string]any) {
			// A v3 head over the same (tenant, log_id, index, root, size) as
			// the v4 input: schema selects payload rules but is not evidence
			// identity, so this is one state counted twice.
			legacy := map[string]any{
				"input_id": "in-legacy", "schema": "aaes.export/v3",
				"tenant_id": "tenant-a", "key_id": "ledger-k1",
				"head": map[string]any{
					"algorithm": "ed25519", "log_id": hash.DeriveLogID("tenant-a"),
					"index": 7, "root_hash": hex64v4, "tree_size": 7,
					"signed_at": "2026-01-02T03:04:05Z", "signature": "AAAA",
				},
			}
			m["inputs"] = []any{validSummaryInputV4(), legacy}
		}},
		{"input tenant/log_id mismatch", func(m map[string]any) {
			in := validSummaryInputV4()
			in["tenant_id"] = "tenant-b"
			m["inputs"] = []any{in}
		}},
		{"v4 input head missing schema", func(m map[string]any) {
			in := validSummaryInputV4()
			delete(in["head"].(map[string]any), "schema")
			m["inputs"] = []any{in}
		}},
		{"v3 input head missing algorithm", func(m map[string]any) {
			in := validSummaryInputV4()
			in["schema"] = "aaes.export/v3"
			head := in["head"].(map[string]any)
			delete(head, "schema")
			delete(head, "algorithm")
			head["tree_size"] = 9
			m["inputs"] = []any{in}
		}},
		{"v3 input head carrying schema", func(m map[string]any) {
			in := validSummaryInputV4()
			in["schema"] = "aaes.export/v3"
			m["inputs"] = []any{in}
		}},
		{"v2 input head with algorithm", func(m map[string]any) {
			in := validSummaryInputV4()
			in["schema"] = "aaes.export/v2"
			head := in["head"].(map[string]any)
			delete(head, "schema")
			m["inputs"] = []any{in}
		}},
		{"unknown input schema", func(m map[string]any) {
			in := validSummaryInputV4()
			in["schema"] = "aaes.export/v9"
			m["inputs"] = []any{in}
		}},
		{"missing input key_id", func(m map[string]any) {
			in := validSummaryInputV4()
			delete(in, "key_id")
			m["inputs"] = []any{in}
		}},
		{"zero input tree_size", func(m map[string]any) {
			in := validSummaryInputV4()
			in["head"].(map[string]any)["tree_size"] = 0
			m["inputs"] = []any{in}
		}},
		{"missing input signature", func(m map[string]any) {
			in := validSummaryInputV4()
			delete(in["head"].(map[string]any), "signature")
			m["inputs"] = []any{in}
		}},
		{"period_start without period_end", func(m map[string]any) { m["period_start"] = "2026-01-01T00:00:00Z" }},
		{"period_end without period_start", func(m map[string]any) { m["period_end"] = "2026-01-02T00:00:00Z" }},
		{"period_start after period_end", func(m map[string]any) {
			m["period_start"] = "2026-01-03T00:00:00Z"
			m["period_end"] = "2026-01-02T00:00:00Z"
		}},
		{"zero period_start", func(m map[string]any) {
			m["period_start"] = v4ZeroTime
			m["period_end"] = "2026-01-02T00:00:00Z"
		}},
		{"producer_signature wrong algorithm", func(m map[string]any) {
			m["producer_signature"] = map[string]any{"algorithm": "rsa", "key_id": "k", "signature": "AAAA"}
		}},
		{"producer_signature empty key_id", func(m map[string]any) {
			m["producer_signature"] = map[string]any{"algorithm": "ed25519", "key_id": "", "signature": "AAAA"}
		}},
		{"producer_signature empty signature", func(m map[string]any) {
			m["producer_signature"] = map[string]any{"algorithm": "ed25519", "key_id": "k", "signature": ""}
		}},
		{"producer_signature present-empty public_key", func(m map[string]any) {
			m["producer_signature"] = map[string]any{"algorithm": "ed25519", "key_id": "k", "public_key": "", "signature": "AAAA"}
		}},
		{"producer_signature non-hex public_key", func(m map[string]any) {
			m["producer_signature"] = map[string]any{"algorithm": "ed25519", "key_id": "k", "public_key": "zz", "signature": "AAAA"}
		}},
	}
	for _, tc := range refuse {
		t.Run(tc.name, func(t *testing.T) {
			m := validSummaryLeafMapV4()
			tc.f(m)
			if _, err := DecodeSummaryLeafV4(marshalV4(t, m)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}

	t.Run("65 inputs", func(t *testing.T) {
		m := validSummaryLeafMapV4()
		inputs := make([]any, 0, 65)
		for i := 0; i < 65; i++ {
			in := validSummaryInputV4()
			in["input_id"] = strings.Repeat("x", 1) + string(rune('A'+i))
			in["head"].(map[string]any)["tree_size"] = i + 1
			inputs = append(inputs, in)
		}
		m["inputs"] = inputs
		if _, err := DecodeSummaryLeafV4(marshalV4(t, m)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})

	// Required envelope strings are nonempty and timestamps nonzero.
	for _, mem := range []string{"tenant_id", "summary_id", "profile", "producer_id", "producer_version", "created_at", "linked_at", "body", "chain_hash", "leaf"} {
		t.Run("missing "+mem, func(t *testing.T) {
			m := validSummaryLeafMapV4()
			delete(m, mem)
			if _, err := DecodeSummaryLeafV4(marshalV4(t, m)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}

	t.Run("period and producer signature accepted", func(t *testing.T) {
		m := validSummaryLeafMapV4()
		m["period_start"] = "2026-01-01T00:00:00Z"
		m["period_end"] = "2026-01-01T00:00:00Z"
		m["producer_signature"] = map[string]any{
			"algorithm": "ed25519", "key_id": "producer-1",
			"public_key": hex64v4, "signature": "AAAA",
		}
		if _, err := DecodeSummaryLeafV4(marshalV4(t, m)); err != nil {
			t.Fatalf("valid period and producer signature refused: %v", err)
		}
	})

	t.Run("legacy v2 input accepted", func(t *testing.T) {
		m := validSummaryLeafMapV4()
		v2 := map[string]any{
			"input_id": "in-legacy", "schema": "aaes.export/v2",
			"tenant_id": "tenant-b", "key_id": "ledger-k0",
			"head": map[string]any{
				"log_id": hash.DeriveLogID("tenant-b"), "index": 3, "root_hash": hex64v4,
				"tree_size": 3, "signed_at": "2026-01-02T03:04:05Z", "signature": "AAAA",
			},
		}
		m["inputs"] = []any{validSummaryInputV4(), v2}
		if _, err := DecodeSummaryLeafV4(marshalV4(t, m)); err != nil {
			t.Fatalf("valid v2 input refused: %v", err)
		}
	})
}

func TestSummaryBodyContractV4(t *testing.T) {
	refuse := []struct {
		name string
		body string
	}{
		{"body not an object", `["findings"]`},
		{"findings not an array", `{"findings":{"code":"c"},"limitations":[]}`},
		{"finding missing code", `{"findings":[{"input_ids":["in-1"]}],"limitations":[]}`},
		{"finding empty code", `{"findings":[{"code":"","input_ids":["in-1"]}],"limitations":[]}`},
		{"finding missing input_ids", `{"findings":[{"code":"c"}],"limitations":[]}`},
		{"finding empty input_ids", `{"findings":[{"code":"c","input_ids":[]}],"limitations":[]}`},
		{"finding unknown input id", `{"findings":[{"code":"c","input_ids":["nope"]}],"limitations":[]}`},
		{"metric value not an object", `{"metrics":{"coverage":5},"limitations":[]}`},
		{"metric missing value", `{"metrics":{"coverage":{"input_ids":["in-1"]}},"limitations":[]}`},
		{"metric non-numeric value", `{"metrics":{"coverage":{"value":"high","input_ids":["in-1"]}},"limitations":[]}`},
		{"metric empty input_ids", `{"metrics":{"coverage":{"value":0,"input_ids":[]}},"limitations":[]}`},
		{"metric unknown input id", `{"metrics":{"coverage":{"value":0,"input_ids":["nope"]}},"limitations":[]}`},
		{"limitations missing", `{"findings":[]}`},
		{"limitations not strings", `{"limitations":[1]}`},
		{"limitations not an array", `{"limitations":"none"}`},
	}
	for _, tc := range refuse {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeSummaryLeafV4(summaryLineRawBodyV4(t, tc.body)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}

	allow := []struct {
		name string
		body string
	}{
		{"minimum body", `{"limitations":[]}`},
		{"empty findings and metrics", `{"findings":[],"metrics":{},"limitations":[]}`},
		{"profile-owned members everywhere", `{"findings":[{"code":"c","input_ids":["in-1"],"detail":{"a":1},"extra":true}],"metrics":{"m":{"value":1.5,"input_ids":["in-1"],"unit":"x"}},"limitations":["l"],"future":[1,2]}`},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if _, err := DecodeSummaryLeafV4(summaryLineRawBodyV4(t, tc.body)); err != nil {
				t.Fatalf("body refused: %v", err)
			}
		})
	}

	// An unknown profile is covered cryptographically but uninterpreted: only
	// the object shape applies.
	m := validSummaryLeafMapV4()
	m["profile"] = "aaes.some-future-profile/v9"
	m["body"] = map[string]any{"anything": true}
	if _, err := DecodeSummaryLeafV4(marshalV4(t, m)); err != nil {
		t.Fatalf("unknown profile with object body refused: %v", err)
	}
}

func TestReceiptBundleV1(t *testing.T) {
	refuse := []struct {
		name string
		f    func(m map[string]any)
	}{
		{"wrong schema", func(m map[string]any) { m["schema"] = "aaes.receipt-proof/v0" }},
		{"missing key_id", func(m map[string]any) { delete(m, "key_id") }},
		{"empty key_id", func(m map[string]any) { m["key_id"] = "" }},
		{"missing head", func(m map[string]any) { delete(m, "head") }},
		{"missing parent_leaf", func(m map[string]any) { delete(m, "parent_leaf") }},
		{"missing parent_proof", func(m map[string]any) { delete(m, "parent_proof") }},
		{"missing receipt_leaf", func(m map[string]any) { delete(m, "receipt_leaf") }},
		{"missing receipt_proof", func(m map[string]any) { delete(m, "receipt_proof") }},
		{"head missing algorithm", func(m map[string]any) { delete(m["head"].(map[string]any), "algorithm") }},
		{"head without signed schema", func(m map[string]any) { delete(m["head"].(map[string]any), "schema") }},
		{"head legacy algorithm", func(m map[string]any) { m["head"].(map[string]any)["algorithm"] = "" }},
		{"head zero tree_size", func(m map[string]any) { m["head"].(map[string]any)["tree_size"] = 0 }},
		{"head missing signature", func(m map[string]any) { delete(m["head"].(map[string]any), "signature") }},
		{"parent_leaf wrong type", func(m map[string]any) { m["parent_leaf"].(map[string]any)["type"] = "receipt" }},
		{"receipt leaf invalid", func(m map[string]any) {
			delete(m["receipt_leaf"].(map[string]any)["receipt"].(map[string]any), "class")
		}},
	}
	for _, tc := range refuse {
		t.Run(tc.name, func(t *testing.T) {
			m := validBundleMapV4()
			tc.f(m)
			if _, err := DecodeReceiptBundleV1(marshalV4(t, m)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	// Every proof member is required-present, index 0 included.
	for _, mem := range []string{"index", "tree_size", "siblings", "self_siblings", "root_hash"} {
		t.Run("proof missing "+mem, func(t *testing.T) {
			m := validBundleMapV4()
			delete(m["receipt_proof"].(map[string]any), mem)
			if _, err := DecodeReceiptBundleV1(marshalV4(t, m)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("proof index 0 accepted", func(t *testing.T) {
		m := validBundleMapV4()
		m["parent_proof"] = validProofMapV4(0)
		if _, err := DecodeReceiptBundleV1(marshalV4(t, m)); err != nil {
			t.Fatalf("proof index 0 refused: %v", err)
		}
	})
}

// TestPreimageGoldenReceiptV4 pins the canonical receipt preimage bytes and
// the leaf over them.
func TestPreimageGoldenReceiptV4(t *testing.T) {
	line := `{"type":"receipt","schema":"aaes.export/v4","sequence":42,"record_hash":"rh",` +
		`"linked_at":"2026-01-02T03:04:05Z",` +
		`"receipt":{"receipt_id":"rc-1","intent_id":"in-1","tenant_id":"tenant-a","record_hash":"rh",` +
		`"issued_at":"2026-01-02T03:00:00Z","class":2,"rail_confirmed":true,` +
		`"confirmed_at":"0001-01-01T00:00:00Z","reported_at":"0001-01-01T00:00:00Z","observed_at":"0001-01-01T00:00:00Z"},` +
		`"chain_hash":"` + hex64v4 + `","leaf":"` + hex64v4 + `"}`
	// Hand-built: CJSON sorts object keys, drops the exporter-claim
	// chain_hash and leaf, and keeps the zero timestamps and class 2.
	want := `{"linked_at":"2026-01-02T03:04:05Z",` +
		`"receipt":{"class":2,"confirmed_at":"0001-01-01T00:00:00Z","intent_id":"in-1",` +
		`"issued_at":"2026-01-02T03:00:00Z","observed_at":"0001-01-01T00:00:00Z","rail_confirmed":true,` +
		`"receipt_id":"rc-1","record_hash":"rh","reported_at":"0001-01-01T00:00:00Z","tenant_id":"tenant-a"},` +
		`"record_hash":"rh","schema":"aaes.export/v4","sequence":42,"type":"receipt"}`
	leaf, err := DecodeReceiptLeafV4([]byte(line))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	pre, err := leaf.PreimageV4()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	if string(pre) != want {
		t.Fatalf("preimage mismatch:\n got: %s\nwant: %s", pre, want)
	}
	recomputed, err := leaf.RecomputeLeafV4()
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if recomputed != hash.SHA256Hex([]byte(want)) {
		t.Fatalf("leaf = %s, want SHA256Hex(preimage) = %s", recomputed, hash.SHA256Hex([]byte(want)))
	}
}

// TestPreimageGoldenApprovalV4 pins the canonical approval preimage bytes,
// including the PascalCase member names and the numeric enums.
func TestPreimageGoldenApprovalV4(t *testing.T) {
	line := `{"type":"approval","schema":"aaes.export/v4","source_sequence":17,` +
		`"linked_at":"2026-01-02T03:04:05Z",` +
		`"approval":{"ApprovalID":"ap-1","TenantID":"tenant-a","TaskID":"task-1","IntentID":"in-1",` +
		`"Approver":"alice","State":2,"Reason":"","PayloadHash":"ph","BundleHash":"bh","EngineVersion":"ev1",` +
		`"ExpiresAt":"2026-01-03T00:00:00Z","DecidedAt":"2026-01-02T04:00:00Z","CreatedAt":"2026-01-02T03:00:00Z",` +
		`"ApproverKind":0,"ApproverAuthority":0,"RequesterManagersSource":0},` +
		`"chain_hash":"c","leaf":"l"}`
	want := `{"approval":{"ApprovalID":"ap-1","Approver":"alice","ApproverAuthority":0,"ApproverKind":0,` +
		`"BundleHash":"bh","CreatedAt":"2026-01-02T03:00:00Z","DecidedAt":"2026-01-02T04:00:00Z",` +
		`"EngineVersion":"ev1","ExpiresAt":"2026-01-03T00:00:00Z","IntentID":"in-1","PayloadHash":"ph",` +
		`"Reason":"","RequesterManagersSource":0,"State":2,"TaskID":"task-1","TenantID":"tenant-a"},` +
		`"linked_at":"2026-01-02T03:04:05Z","schema":"aaes.export/v4","source_sequence":17,"type":"approval"}`
	leaf, err := DecodeApprovalLeafV4([]byte(line))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	pre, err := leaf.PreimageV4()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	if string(pre) != want {
		t.Fatalf("preimage mismatch:\n got: %s\nwant: %s", pre, want)
	}
	recomputed, err := leaf.RecomputeLeafV4()
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if recomputed != hash.SHA256Hex([]byte(want)) {
		t.Fatalf("leaf = %s, want SHA256Hex(preimage)", recomputed)
	}
}

// TestPreimageRoundTripV4 proves decode → canonicalise is stable: the same
// line decoded twice yields byte-identical preimages, and the exporter-claim
// chain_hash and leaf never enter the preimage.
func TestPreimageRoundTripV4(t *testing.T) {
	raw := marshalV4(t, validReceiptLeafMapV4())
	first, err := DecodeReceiptLeafV4(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	second, err := DecodeReceiptLeafV4(raw)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	p1, err := first.PreimageV4()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	p2, err := second.PreimageV4()
	if err != nil {
		t.Fatalf("re-preimage: %v", err)
	}
	if !bytes.Equal(p1, p2) {
		t.Fatal("two decodes of one line produced different preimages")
	}
	// Mutating the claims must not move the preimage.
	mutated := validReceiptLeafMapV4()
	mutated["chain_hash"] = strings.Repeat("cd", 32)
	mutated["leaf"] = strings.Repeat("ef", 32)
	other, err := DecodeReceiptLeafV4(marshalV4(t, mutated))
	if err != nil {
		t.Fatalf("decode mutated: %v", err)
	}
	p3, err := other.PreimageV4()
	if err != nil {
		t.Fatalf("preimage mutated: %v", err)
	}
	if !bytes.Equal(p1, p3) {
		t.Fatal("chain_hash/leaf claims leaked into the preimage")
	}
}

// TestSummaryPreimageCanonicalisesBodyV4 proves the body re-canonicalises
// inside the preimage: out-of-order keys sort, and an integer above 2^53
// survives exactly.
func TestSummaryPreimageCanonicalisesBodyV4(t *testing.T) {
	body := `{"limitations":[],"metrics":{"m":{"input_ids":["in-1"],"value":9007199254740993}},` +
		`"findings":[{"input_ids":["in-1"],"code":"c"}],"extra":{"z":1,"a":2}}`
	raw := summaryLineRawBodyV4(t, body)
	leaf, err := DecodeSummaryLeafV4(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	pre, err := leaf.PreimageV4()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	wantBody := `"body":{"extra":{"a":2,"z":1},"findings":[{"code":"c","input_ids":["in-1"]}],` +
		`"limitations":[],"metrics":{"m":{"input_ids":["in-1"],"value":9007199254740993}}}`
	if !strings.Contains(string(pre), wantBody) {
		t.Fatalf("body not re-canonicalised in preimage:\n got: %s\nwant substring: %s", pre, wantBody)
	}
	again, err := DecodeSummaryLeafV4(raw)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	pre2, err := again.PreimageV4()
	if err != nil {
		t.Fatalf("re-preimage: %v", err)
	}
	if !bytes.Equal(pre, pre2) {
		t.Fatal("two decodes of one summary line produced different preimages")
	}
}

// TestSummaryProducerPayloadV4 pins the section 5.4 payload: the summary
// preimage with producer_signature removed.
func TestSummaryProducerPayloadV4(t *testing.T) {
	withSig := validSummaryLeafMapV4()
	withSig["producer_signature"] = map[string]any{"algorithm": "ed25519", "key_id": "producer-1", "signature": "AAAA"}
	signed, err := DecodeSummaryLeafV4(marshalV4(t, withSig))
	if err != nil {
		t.Fatalf("decode signed: %v", err)
	}
	unsigned, err := DecodeSummaryLeafV4(marshalV4(t, validSummaryLeafMapV4()))
	if err != nil {
		t.Fatalf("decode unsigned: %v", err)
	}
	payload, err := signed.SummaryProducerPayloadV4()
	if err != nil {
		t.Fatalf("producer payload: %v", err)
	}
	unsignedPreimage, err := unsigned.PreimageV4()
	if err != nil {
		t.Fatalf("unsigned preimage: %v", err)
	}
	if !bytes.Equal(payload, unsignedPreimage) {
		t.Fatal("producer payload is not the preimage with producer_signature removed")
	}
	signedPreimage, err := signed.PreimageV4()
	if err != nil {
		t.Fatalf("signed preimage: %v", err)
	}
	if bytes.Equal(payload, signedPreimage) {
		t.Fatal("producer payload must exclude producer_signature")
	}
	if strings.Contains(string(payload), "producer_signature") {
		t.Fatal("producer payload still names producer_signature")
	}
}

// TestPreimageV4RejectsUnvalidatedLeaves proves the preimage builders run the
// presence rules rather than canonicalising a leaf the wire would refuse.
func TestPreimageV4RejectsUnvalidatedLeaves(t *testing.T) {
	var receipt ReceiptLeafViewV4
	if _, err := receipt.PreimageV4(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("receipt: err = %v, want ErrMalformed", err)
	}
	var approval ApprovalLeafViewV4
	if _, err := approval.PreimageV4(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("approval: err = %v, want ErrMalformed", err)
	}
	var summary SummaryLeafViewV4
	if _, err := summary.PreimageV4(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("summary: err = %v, want ErrMalformed", err)
	}
}

// TestTreeHeadSchemaOmitemptyV4 locks the additive hash.TreeHead.Schema
// field: legacy heads canonicalise byte-identical without it, and a v4 head
// carries schema inside the signed payload.
func TestTreeHeadSchemaOmitemptyV4(t *testing.T) {
	base := hash.TreeHead{
		Algorithm: "ed25519",
		LogID:     hash.DeriveLogID("tenant-a"),
		Index:     1,
		RootHash:  hex64v4,
		TreeSize:  1,
		SignedAt:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	legacy, err := hash.CanonicalJSON(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "schema") {
		t.Fatalf("legacy head carries schema: %s", legacy)
	}
	base.Schema = ExportSchemaV4
	v4, err := hash.CanonicalJSON(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(v4), `"schema":"aaes.export/v4"`) {
		t.Fatalf("v4 head payload missing signed schema: %s", v4)
	}
}
