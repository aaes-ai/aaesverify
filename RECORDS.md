# Current sealed-record verification profile

Since v0.3.0, aaesverify supports `--export FILE --records FILE --json` and uses the
same reader in `--evaluation DIR`. The reader uses only the public verifier,
public canonical hashing helpers and Go's standard library. It contains no
platform journal, policy evaluator, producer binary or signing key.

The direct command first verifies the export head, chain and Merkle root. It then
recomputes current `aaes/intent/2`, `aaes/decision/1` and `aaes/record/2` hashes from
the sidecar. It never creates or signs a new evidence record. Here, “re-sealing”
means recomputing and comparing the three stored hashes.

## Supported profile and refusal rules

The sidecar starts with one `type: header`, `schema: aaes.records/v1` line, with
`binds: aaes.export/v3`. Its `log_id`, `tenant_id` and `entry_count` must match the
export, and its count must equal the number of export entries and sealed records.
Each remaining line is a record or receipt. Blank lines, unknown line types,
additional headers, duplicate JSON keys and trailing JSON data fail verification.

This profile supports the current record/2 encoding with integer minor-unit money,
no retention tombstone and no external-reference set. Absent, null or empty
external-reference sets and absent or null tombstones mean no value. Nonempty
external references, nonnull tombstones, legacy seal encodings and unknown record,
intent or decision fields fail closed. They require separate reader support and
qualification vectors. Export-only v2/v3 verification remains available.

Strings, booleans, integer fields and RFC 3339 timestamps are decoded by type.
Missing optional fields use their typed zero values; explicit null scalar values
are refused. Integers never pass through floating point. Unsigned fields are
64-bit; signed integer amounts, durations and tier slots are 64-bit. Times are
canonicalized in UTC by the public canonical JSON implementation. Its zero time
is `0001-01-01T00:00:00Z`.

Each sidecar is bounded to 16 MiB, with a 4 MiB per-line limit. Duplicate record
hashes, duplicate receipt bindings, missing or orphan records/receipts, mismatched
wrapper hashes or sequence numbers, unsafe file paths and nonregular disclosed
files fail verification. The disclosure reader also authenticates every included
file against the original signed evaluation manifest.

## Hash preimages

All hashes below are lowercase SHA-256 over the public canonical JSON encoding of
the specified arrays. Fields retain their declared types. `sequence` and
`task_revision` are unsigned integers; `tier`, money minor units and `grant_ttl`
are signed integers. `grant_ttl` is the recorded integer duration in nanoseconds.

The intent preimage begins with the string `aaes/intent/2`, followed by these
values in order:

```text
intent_id tenant_id actor_id kind
model_provider model_family model model_source
caller_task_id task_id task_revision effect_key approval_id
correlation_id parent_intent_id contract_id capability action resource_id
data_class tier amount_minor amount_currency amount_at_risk_minor
amount_at_risk_currency payload_hash requested_at observation_expires_at
null sequence
```

The `null` slot is the absent tombstone. Seven two-element arrays follow, each
containing the field name and its typed value, including zero values:

```text
identity_source capability_version approval_policy_id budget_grant_id
human_free_approval human_free_approval_sponsor human_free_approval_at
```

Optional extensions follow in this order: `["defers_intent_id", value]` when the
identifier is nonempty; `["deferral_expires_at", value]` when the time is nonzero;
`["brokered", true]` when true; and
`["execution_constraints", execution_root_task_id, execution_constraints_hash]`
when present. The execution constraint pair must be complete and its hash must
be 64 lowercase hexadecimal characters. No policy evaluation is performed.

The decision preimage is:

```text
["aaes/decision/1", allowed, requires_approval, requires_dual_control,
 requires_step_up, matched_rule_id, reason, grant_ttl, decided_at]
```

If `defer` is true, append `["defer", true]` as one additional array element.

The record preimage is:

```text
["aaes/record/2", intent_hash, decision_hash, policy_bundle_id,
 engine_version, intent.tenant_id, intent.sequence, sealed_at,
 policy_bundle_hash, input_hash]
```

All three recomputed hashes must match their stored values. Intent ID, tenant ID
and policy bundle ID must be nonempty, and sequence must be positive. Replay
commitments are either both absent or both present: `policy_bundle_hash` and
`input_hash`. A present policy hash must be 64 lowercase hexadecimal characters.
When evaluator input or its commitment is present, `input_hash` must equal SHA-256
of the exact UTF-8 bytes of the `evaluator_input` string. Whitespace inside that
string is preserved. The referenced policy bundle is omitted from this package;
its rules and the recorded decision are not re-evaluated.

## Binding and trust boundary

Every export entry must name exactly one re-sealed record. Tenant, sequence,
intent ID, actor ID, capability, tier, allowed decision, declared amount/currency
and sealed time must match the export projection. The export's `record_hash`
commits to the complete supported record preimage, including fields absent from
the short export projection. Each receipt must name the same record hash,
sequence, tenant and intent as its record. Present receipt replay commitments
must match the record. The export grant ID must equal the receipt grant ID, or
be empty when no receipt is supplied. Extra or repeated bindings fail.

Successful output includes `sealed_records_resealed: true`,
`sealed_sidecar_binding_verified: true` and `resealed_record_count`.
`receipt_chain_verified` remains false. The reader interprets the receipt's
binding projection; it does not re-seal receipt outcome fields or reconstruct a
complete receipt chain. In evaluation mode, the original manifest signature and
file hash authenticate all disclosed receipt bytes. The direct export/records
command alone does not authenticate receipt outcome assertions.

These checks establish consistency between the supplied records and export.
They do not establish truthful inputs, correct policy decisions, completeness of
unseen calls, real effects or independent attestation. Omitted source and producer
binaries remain unverified, and `full_private_bundle_verified` remains false.
