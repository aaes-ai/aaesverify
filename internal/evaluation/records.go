// SPDX-License-Identifier: Apache-2.0
package evaluation

// This is a read-only wire-format implementation. It has no producer, policy
// evaluator, store, or signing dependency. See RECORDS.md for the public profile.
import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// Field lists describe the positional record/2 wire preimages. Missing optional
// values use their typed zero value. Unknown fields and null scalar values fail closed.
const intentStrings = "intent_id tenant_id actor_id kind model_provider model_family model model_source caller_task_id task_id effect_key approval_id correlation_id parent_intent_id contract_id capability action resource_id data_class amount_currency amount_at_risk_currency payload_hash identity_source capability_version approval_policy_id budget_grant_id human_free_approval_sponsor defers_intent_id execution_root_task_id execution_constraints_hash"
const intentTimes = "requested_at observation_expires_at human_free_approval_at deferral_expires_at"
const decisionStrings = "matched_rule_id reason"
const recordStrings = "intent_hash decision_hash record_hash policy_bundle_id policy_bundle_hash evaluator_input input_hash engine_version"

type wireObject map[string]any

func typedObject(raw json.RawMessage, groups map[string]string) (wireObject, error) {
	var object map[string]json.RawMessage
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("missing/null wire object")
	}
	if err := decodeUnique(raw, &object); err != nil {
		return nil, err
	}
	out := wireObject{}
	for kind, names := range groups {
		for _, name := range strings.Fields(names) {
			value, exists := object[name]
			if exists {
				delete(object, name)
				if kind != "raw" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return nil, fmt.Errorf("null field %s", name)
				}
			}
			switch kind {
			case "s":
				var v string
				if exists {
					if err := json.Unmarshal(value, &v); err != nil {
						return nil, fmt.Errorf("%s: %w", name, err)
					}
				}
				out[name] = v
			case "b":
				var v bool
				if exists {
					if err := json.Unmarshal(value, &v); err != nil {
						return nil, fmt.Errorf("%s: %w", name, err)
					}
				}
				out[name] = v
			case "u":
				var v uint64
				if exists {
					if err := json.Unmarshal(value, &v); err != nil {
						return nil, fmt.Errorf("%s: %w", name, err)
					}
				}
				out[name] = v
			case "i":
				var v int64
				if exists {
					if err := json.Unmarshal(value, &v); err != nil {
						return nil, fmt.Errorf("%s: %w", name, err)
					}
				}
				out[name] = v
			case "t":
				var v time.Time
				if exists {
					if err := json.Unmarshal(value, &v); err != nil {
						return nil, fmt.Errorf("%s: %w", name, err)
					}
				}
				out[name] = v
			case "raw":
				out[name] = value
			}
		}
	}
	if len(object) != 0 {
		return nil, fmt.Errorf("unsupported wire fields: %v", objectKeys(object))
	}
	return out, nil
}
func objectKeys(m map[string]json.RawMessage) []string {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func (o wireObject) s(k string) string    { return o[k].(string) }
func (o wireObject) u(k string) uint64    { return o[k].(uint64) }
func (o wireObject) t(k string) time.Time { return o[k].(time.Time) }
func values(o wireObject, names string) []any {
	out := []any{}
	for _, k := range strings.Fields(names) {
		out = append(out, o[k])
	}
	return out
}

type sealedWire struct{ record, intent, decision wireObject }

func readSealed(raw json.RawMessage) (sealedWire, error) {
	var out sealedWire
	r, err := typedObject(raw, map[string]string{"s": recordStrings, "t": "sealed_at", "raw": "intent decision"})
	if err != nil {
		return out, err
	}
	i, err := typedObject(r["intent"].(json.RawMessage), map[string]string{"s": intentStrings, "t": intentTimes, "u": "task_revision sequence", "i": "tier amount_minor amount_at_risk_minor", "b": "human_free_approval brokered", "raw": "tombstone external_refs"})
	if err != nil {
		return out, err
	}
	d, err := typedObject(r["decision"].(json.RawMessage), map[string]string{"s": decisionStrings, "t": "decided_at", "b": "allowed requires_approval requires_dual_control requires_step_up defer", "i": "grant_ttl"})
	if err != nil {
		return out, err
	}
	// This evaluation profile has no retention cuts or external-reference sets.
	// Refuse them explicitly instead of hashing a shape we do not implement.
	for _, name := range []string{"tombstone", "external_refs"} {
		v := bytes.TrimSpace(i[name].(json.RawMessage))
		if len(v) == 0 || bytes.Equal(v, []byte("null")) {
			continue
		}
		if name == "external_refs" {
			var refs []json.RawMessage
			if err := json.Unmarshal(v, &refs); err == nil && len(refs) == 0 {
				continue
			}
		}
		return out, fmt.Errorf("unsupported record/2 %s in public evaluation profile", name)
	}

	if i.s("intent_id") == "" || i.s("tenant_id") == "" || r.s("policy_bundle_id") == "" || i.u("sequence") == 0 {
		return out, fmt.Errorf("missing sealed record identity")
	}
	root, constraints := i.s("execution_root_task_id"), i.s("execution_constraints_hash")
	if (root == "") != (constraints == "") || (constraints != "" && !validHash(constraints)) {
		return out, fmt.Errorf("invalid execution constraints commitment")
	}
	pre := append([]any{"aaes/intent/2"}, values(i, "intent_id tenant_id actor_id kind model_provider model_family model model_source caller_task_id task_id task_revision effect_key approval_id correlation_id parent_intent_id contract_id capability action resource_id data_class tier amount_minor amount_currency amount_at_risk_minor amount_at_risk_currency payload_hash requested_at observation_expires_at")...)
	pre = append(pre, nil, i.u("sequence"))
	for _, name := range strings.Fields("identity_source capability_version approval_policy_id budget_grant_id human_free_approval human_free_approval_sponsor human_free_approval_at") {
		pre = append(pre, []any{name, i[name]})
	}
	if i.s("defers_intent_id") != "" {
		pre = append(pre, []any{"defers_intent_id", i["defers_intent_id"]})
	}
	if !i.t("deferral_expires_at").IsZero() {
		pre = append(pre, []any{"deferral_expires_at", i["deferral_expires_at"]})
	}
	if i["brokered"].(bool) {
		pre = append(pre, []any{"brokered", true})
	}
	if root != "" {
		pre = append(pre, []any{"execution_constraints", root, constraints})
	}
	ih, err := hash.HashObject(pre)
	if err != nil {
		return out, err
	}
	dp := append([]any{"aaes/decision/1"}, values(d, "allowed requires_approval requires_dual_control requires_step_up matched_rule_id reason grant_ttl decided_at")...)
	if d["defer"].(bool) {
		dp = append(dp, []any{"defer", true})
	}
	dh, err := hash.HashObject(dp)
	if err != nil {
		return out, err
	}
	rh, err := hash.HashObject([]any{"aaes/record/2", ih, dh, r["policy_bundle_id"], r["engine_version"], i["tenant_id"], i["sequence"], r["sealed_at"], r["policy_bundle_hash"], r["input_hash"]})
	if err != nil {
		return out, err
	}
	if ih != r.s("intent_hash") || dh != r.s("decision_hash") || rh != r.s("record_hash") {
		return out, fmt.Errorf("record/2 re-sealing mismatch (legacy encodings are unsupported)")
	}
	bundle, input, payload := r.s("policy_bundle_hash"), r.s("input_hash"), r.s("evaluator_input")
	if (bundle == "") != (input == "") || (bundle != "" && !validHash(bundle)) || ((input != "" || payload != "") && (input != hash.SHA256Hex([]byte(payload)))) {
		return out, fmt.Errorf("evaluator input/replay commitment mismatch")
	}
	return sealedWire{r, i, d}, nil
}

// VerifyRecords re-seals current record/2 records and binds them one-to-one to
// export projections. The caller must separately authenticate the export. This
// does not verify receipt-chain seals, policy evaluation, or real-world effects.
func VerifyRecords(exportRaw, recordsRaw []byte) (int, error) {
	if len(recordsRaw) > maxFileBytes {
		return 0, fmt.Errorf("sidecar exceeds size limit")
	}
	export, err := verifier.LoadExportReader(bytes.NewReader(exportRaw))
	if err != nil {
		return 0, err
	}
	if export.Header.Schema != verifier.ExportSchemaV3 {
		return 0, fmt.Errorf("sidecar profile requires v3 export")
	}
	records := map[string]sealedWire{}
	receipts := map[string]wireObject{}
	scanner := bufio.NewScanner(bytes.NewReader(recordsRaw))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		var probe map[string]json.RawMessage
		if err := decodeUnique(raw, &probe); err != nil {
			return 0, fmt.Errorf("sidecar line %d: %w", line, err)
		}
		var typ string
		if err := json.Unmarshal(probe["type"], &typ); err != nil {
			return 0, fmt.Errorf("sidecar line type: %w", err)
		}
		if line == 1 {
			h, err := typedObject(raw, map[string]string{"s": "type schema binds log_id tenant_id", "u": "entry_count"})
			if err != nil {
				return 0, err
			}
			if typ != "header" || h.s("schema") != "aaes.records/v1" || h.s("binds") != export.Header.Schema || h.s("log_id") != export.Header.LogID || h.s("tenant_id") != export.Header.TenantID || h.u("entry_count") != export.Header.EntryCount || h.u("entry_count") != uint64(len(export.Entries)) {
				return 0, fmt.Errorf("sidecar header/export identity or count mismatch")
			}
			continue
		}
		if typ != "record" && typ != "receipt" {
			return 0, fmt.Errorf("unexpected sidecar line type %q", typ)
		}
		row, err := typedObject(raw, map[string]string{"s": "type record_hash", "u": "sequence", "raw": typ})
		if err != nil {
			return 0, err
		}
		key := row.s("record_hash")
		if !validHash(key) {
			return 0, fmt.Errorf("invalid sidecar record hash")
		}
		if typ == "record" {
			rec, err := readSealed(row[typ].(json.RawMessage))
			if err != nil {
				return 0, fmt.Errorf("sidecar line %d: %w", line, err)
			}
			if _, exists := records[key]; exists {
				return 0, fmt.Errorf("duplicate sidecar record")
			}
			if key != rec.record.s("record_hash") || row.u("sequence") != rec.intent.u("sequence") {
				return 0, fmt.Errorf("sidecar record wrapper mismatch")
			}
			records[key] = rec
		} else {
			// Only the receipt's binding projection is interpreted. Other receipt
			// fields are authenticated by the evaluation manifest, not by this seal.
			var r map[string]json.RawMessage
			if err := decodeUnique(row[typ].(json.RawMessage), &r); err != nil || r == nil {
				return 0, fmt.Errorf("invalid receipt object")
			}
			projection := map[string]json.RawMessage{}
			for _, name := range strings.Fields("record_hash intent_id tenant_id grant_id policy_bundle_hash input_hash engine_version") {
				if v, ok := r[name]; ok {
					projection[name] = v
				}
			}
			encoded, _ := json.Marshal(projection)
			receipt, err := typedObject(encoded, map[string]string{"s": "record_hash intent_id tenant_id grant_id policy_bundle_hash input_hash engine_version"})
			if err != nil {
				return 0, err
			}
			receipt["sequence"] = row.u("sequence")
			if _, exists := receipts[key]; exists {
				return 0, fmt.Errorf("duplicate sidecar receipt")
			}
			if receipt.s("record_hash") != key {
				return 0, fmt.Errorf("receipt record hash mismatch")
			}
			receipts[key] = receipt
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if line == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(records) != len(export.Entries) {
		return 0, fmt.Errorf("sidecar/export record count mismatch")
	}
	for key, r := range receipts {
		rec, ok := records[key]
		if !ok {
			return 0, fmt.Errorf("orphan sidecar receipt")
		}
		if r.u("sequence") != rec.intent.u("sequence") || r.s("intent_id") != rec.intent.s("intent_id") || r.s("tenant_id") != rec.intent.s("tenant_id") {
			return 0, fmt.Errorf("receipt identity mismatch")
		}
		for _, name := range strings.Fields("policy_bundle_hash input_hash engine_version") {
			if r.s(name) != "" && r.s(name) != rec.record.s(name) {
				return 0, fmt.Errorf("receipt replay commitment mismatch")
			}
		}
	}
	seen := map[string]bool{}
	for _, e := range export.Entries {
		r, ok := records[e.RecordHash]
		if !ok || seen[e.RecordHash] {
			return 0, fmt.Errorf("export record missing or repeated in sidecar binding")
		}
		seen[e.RecordHash] = true
		i := r.intent
		grant := ""
		if receipt, ok := receipts[e.RecordHash]; ok {
			grant = receipt.s("grant_id")
		}
		if e.TenantID != i.s("tenant_id") || e.Sequence != i.u("sequence") || e.IntentID != i.s("intent_id") || e.ActorID != i.s("actor_id") || e.Capability != i.s("capability") || int64(e.Tier) != i["tier"].(int64) || e.Allowed != r.decision["allowed"].(bool) || e.AmountMinor != i["amount_minor"].(int64) || e.AmountCurrency != i.s("amount_currency") || !e.OccurredAt.Equal(r.record.t("sealed_at")) || e.GrantID != grant || e.Tombstone != nil {
			return 0, fmt.Errorf("sidecar/export projection mismatch at sequence %d", e.Sequence)
		}
	}
	return len(records), nil
}

// ReadRecordsFile applies the disclosure reader's size and regular-file checks.
func ReadRecordsFile(path string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return readRegular(filepath.Dir(absolute), filepath.Base(absolute))
}
