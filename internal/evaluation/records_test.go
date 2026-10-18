// SPDX-License-Identifier: Apache-2.0
package evaluation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// Independent synthetic vector: explicit preimages, no producer or reader seal
// function. The real three-framework package adds 27 producer-written vectors.
func syntheticEvidence(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	at := time.Date(2026, 10, 16, 1, 2, 3, 4000, time.UTC)
	zero := time.Time{}
	ih, _ := hash.HashObject([]any{"aaes/intent/2", "intent-1", "tenant-test", "agent-1", "action", "", "", "", "", "", "task-1", uint64(1), "effect-1", "", "", "", "", "read", "read", "", "public", 0, int64(9007199254740993), "USD", int64(0), "", "", at, zero, nil, uint64(1), []any{"identity_source", ""}, []any{"capability_version", ""}, []any{"approval_policy_id", ""}, []any{"budget_grant_id", ""}, []any{"human_free_approval", false}, []any{"human_free_approval_sponsor", ""}, []any{"human_free_approval_at", zero}})
	dh, _ := hash.HashObject([]any{"aaes/decision/1", true, false, false, false, "rule-1", "synthetic", int64(0), at})
	bundle := strings.Repeat("a", 64)
	input := "{}"
	inputHash := hash.SHA256Hex([]byte(input))
	rh, _ := hash.HashObject([]any{"aaes/record/2", ih, dh, "pb_test", "test/1", "tenant-test", uint64(1), at, bundle, inputHash})
	intent := map[string]any{"intent_id": "intent-1", "tenant_id": "tenant-test", "actor_id": "agent-1", "kind": "action", "task_id": "task-1", "task_revision": 1, "effect_key": "effect-1", "capability": "read", "action": "read", "data_class": "public", "tier": 0, "amount_minor": int64(9007199254740993), "amount_currency": "USD", "requested_at": at, "sequence": 1}
	rec := map[string]any{"intent": intent, "decision": map[string]any{"allowed": true, "matched_rule_id": "rule-1", "reason": "synthetic", "decided_at": at}, "intent_hash": ih, "decision_hash": dh, "record_hash": rh, "policy_bundle_id": "pb_test", "policy_bundle_hash": bundle, "evaluator_input": input, "input_hash": inputHash, "engine_version": "test/1", "sealed_at": at}
	entry := map[string]any{"actor_id": "agent-1", "allowed": true, "amount_minor": int64(9007199254740993), "amount_currency": "USD", "capability": "read", "grant_id": "grant-1", "intent_id": "intent-1", "linked_at": at, "occurred_at": at, "record_hash": rh, "sequence": 1, "tenant_id": "tenant-test", "tier": 0}
	pre, err := hash.CanonicalJSON(entry)
	if err != nil {
		t.Fatal(err)
	}
	leaf := hash.SHA256Hex(pre)
	entry["type"] = "entry"
	entry["chain_hash"] = hash.Chain("", pre)
	entry["leaf"] = leaf
	head := hash.TreeHead{Algorithm: "ed25519", LogID: hash.DeriveLogID("tenant-test"), Index: 1, TreeSize: 1, RootHash: hash.MerkleRoot([]string{leaf}), SignedAt: at, PreAnchor: true}
	head.Signature = ed25519.Sign(priv, verifier.HeadPayload(head))
	header := map[string]any{"type": "header", "schema": verifier.ExportSchemaV3, "log_id": "test-log", "tenant_id": "tenant-test", "entry_count": 1, "exported_at": at, "head": head, "pre_anchor": true, "public_key": hex.EncodeToString(pub), "signature_algorithm": "ed25519"}
	export := append(append(encode(t, header), '\n'), append(encode(t, entry), '\n')...)
	sidecar := append(encode(t, map[string]any{"type": "header", "schema": "aaes.records/v1", "binds": verifier.ExportSchemaV3, "log_id": "test-log", "tenant_id": "tenant-test", "entry_count": 1}), '\n')
	sidecar = append(sidecar, append(encode(t, map[string]any{"type": "record", "sequence": 1, "record_hash": rh, "record": rec}), '\n')...)
	sidecar = append(sidecar, append(encode(t, map[string]any{"type": "receipt", "sequence": 1, "record_hash": rh, "receipt": map[string]any{"record_hash": rh, "intent_id": "intent-1", "tenant_id": "tenant-test", "grant_id": "grant-1", "policy_bundle_hash": bundle, "input_hash": inputHash, "engine_version": "test/1"}}), '\n')...)
	return export, sidecar
}

func TestRecordResealingAndBindingMutations(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	export, sidecar := syntheticEvidence(t, pub, priv)
	if res := verifier.VerifyExportReaderResult(bytes.NewReader(export), pub, verifier.VerifyOptions{}); !res.OK {
		t.Fatalf("synthetic export: %v", res.Errors)
	}
	if n, err := VerifyRecords(export, sidecar); err != nil || n != 1 {
		t.Fatalf("clean: %d %v", n, err)
	}
	for _, mutation := range []string{"intent", "decision", "seal", "replay_input", "policy_hash", "sequence", "header_log", "header_count", "receipt_grant", "receipt_tenant", "receipt_sequence", "receipt_replay", "orphan_receipt", "duplicate_record", "duplicate_receipt", "missing_record", "unknown_field", "wrong_case", "null", "overflow", "float", "legacy_money", "unsupported_tombstone", "duplicate_key", "second_header", "empty", "truncated"} {
		t.Run(mutation, func(t *testing.T) {
			// RawMessages preserve the 2^53+1 amount throughout mutation.
			lines := bytes.Split(bytes.TrimSpace(sidecar), []byte("\n"))
			var h, row, receipt map[string]json.RawMessage
			json.Unmarshal(lines[0], &h)
			json.Unmarshal(lines[1], &row)
			json.Unmarshal(lines[2], &receipt)
			var record, intent, decision, r map[string]json.RawMessage
			json.Unmarshal(row["record"], &record)
			json.Unmarshal(record["intent"], &intent)
			json.Unmarshal(record["decision"], &decision)
			json.Unmarshal(receipt["receipt"], &r)
			set := func(m map[string]json.RawMessage, k string, v any) { m[k] = encode(t, v) }
			switch mutation {
			case "intent":
				set(intent, "action", "write")
			case "decision":
				set(decision, "allowed", false)
			case "seal":
				set(record, "record_hash", strings.Repeat("0", 64))
			case "replay_input":
				set(record, "evaluator_input", "{ }")
			case "policy_hash":
				set(record, "policy_bundle_hash", strings.Repeat("b", 64))
			case "sequence":
				set(row, "sequence", 2)
			case "header_log":
				set(h, "log_id", "other")
			case "header_count":
				set(h, "entry_count", 2)
			case "receipt_grant":
				set(r, "grant_id", "forged")
			case "receipt_tenant":
				set(r, "tenant_id", "other")
			case "receipt_sequence":
				set(receipt, "sequence", 2)
			case "receipt_replay":
				set(r, "input_hash", strings.Repeat("b", 64))
			case "orphan_receipt":
				set(receipt, "record_hash", strings.Repeat("b", 64))
				set(r, "record_hash", strings.Repeat("b", 64))
			case "unknown_field":
				set(intent, "future_authority", true)
			case "wrong_case":
				set(intent, "Actor_ID", "agent-1")
			case "null":
				set(intent, "actor_id", nil)
			case "overflow":
				intent["sequence"] = []byte("18446744073709551616")
			case "float":
				intent["amount_minor"] = []byte("9007199254740993.0")
			case "legacy_money":
				set(intent, "amount_usd", 1.0)
			case "unsupported_tombstone":
				set(intent, "tombstone", map[string]any{"from_sequence": 1})
			}
			record["intent"] = encode(t, intent)
			record["decision"] = encode(t, decision)
			row["record"] = encode(t, record)
			receipt["receipt"] = encode(t, r)
			lines = [][]byte{encode(t, h), encode(t, row), encode(t, receipt)}
			switch mutation {
			case "duplicate_record":
				lines = append(lines, lines[1])
			case "duplicate_receipt":
				lines = append(lines, lines[2])
			case "missing_record":
				lines = append(lines[:1], lines[2])
			case "duplicate_key":
				lines[1] = bytes.Replace(lines[1], []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1)
			case "second_header":
				lines = append(lines, lines[0])
			case "empty":
				lines = nil
			case "truncated":
				lines[1] = lines[1][:len(lines[1])-2]
			}
			if _, err := VerifyRecords(export, bytes.Join(lines, []byte("\n"))); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

// A valid producer signature cannot excuse a projection that contradicts the
// sealed record. Re-sign each modified export with the disposable fixture key.
func TestSignedExportMustMatchSealedProjection(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	export, sidecar := syntheticEvidence(t, pub, priv)
	mutations := map[string]any{"actor_id": "other-agent", "intent_id": "other-intent", "capability": "write", "tier": 1, "allowed": false, "amount_minor": int64(9007199254740994), "amount_currency": "EUR", "occurred_at": "2026-10-16T01:02:04.000004Z", "grant_id": "other-grant"}
	for field, value := range mutations {
		t.Run(field, func(t *testing.T) {
			lines := bytes.Split(bytes.TrimSpace(export), []byte("\n"))
			var header, entry map[string]json.RawMessage
			json.Unmarshal(lines[0], &header)
			json.Unmarshal(lines[1], &entry)
			entry[field] = encode(t, value)
			for _, key := range []string{"type", "chain_hash", "leaf"} {
				delete(entry, key)
			}
			pre, err := hash.CanonicalJSON(entry)
			if err != nil {
				t.Fatal(err)
			}
			leaf := hash.SHA256Hex(pre)
			entry["leaf"] = encode(t, leaf)
			entry["chain_hash"] = encode(t, hash.Chain("", pre))
			entry["type"] = encode(t, "entry")
			var head hash.TreeHead
			json.Unmarshal(header["head"], &head)
			head.RootHash = hash.MerkleRoot([]string{leaf})
			head.Signature = ed25519.Sign(priv, verifier.HeadPayload(head))
			header["head"] = encode(t, head)
			changed := append(append(encode(t, header), '\n'), append(encode(t, entry), '\n')...)
			if result := verifier.VerifyExportReaderResult(bytes.NewReader(changed), pub, verifier.VerifyOptions{}); !result.OK {
				t.Fatalf("test export must be valid: %v", result.Errors)
			}
			if _, err := VerifyRecords(changed, sidecar); err == nil || !strings.Contains(err.Error(), "projection mismatch") {
				t.Fatalf("signed projection mismatch not detected: %v", err)
			}
		})
	}
}
