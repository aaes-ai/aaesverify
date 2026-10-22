# Evaluation disclosure profile

v0.3.0 adds `aaesverify --evaluation DIR --json`. It does not change the
export verifier's v2/v3 rules. The package uses
only the public verifier module and Go's standard library.

An evaluation directory contains the original `evaluation.json` and
`evaluation.sig`, a `disclosure.json`, and thirteen fixed evidence artifacts.
The original manifest schema is `aaes.framework-evaluation/1`. Its signature is
hex-encoded Ed25519 over the exact bytes of the UTF-8 domain
`aaes.framework-evaluation/1\n` followed by the exact manifest bytes.
The bundled key is `evidence/ledger.pub`; `--pubkey` pins a separately obtained key.
The same key verifies the evaluation signature and export head.

`disclosure.json` has schema `aaes.evaluation-disclosure/1`, an `included` list
equal to `internal/evaluation.Files()`, and an `omitted` list equal to every other
artifact named by the signed manifest. Lists have no duplicate members. All
disclosed files must match their original signed hashes. Extra files, missing
files, unsafe paths, symlinks, special files, oversized files and duplicate JSON
object keys in the manifest/disclosure are refused.

The manifest and authenticated `configuration.json` must carry the same simulator
label, in the form `aaes.local-provider/N` with a positive integer version and no
leading zero. Missing, malformed or different labels are refused even when their
signatures and hashes are valid. Successful output reports `provider` and
`provider_metadata_consistent: true`. Earlier packages retain their original
verifiers; v0.3.0 refuses their mismatched version labels.

The fixed profile discloses the case plan, execution plan, results, synthetic
provider calls, configuration, dependency lock, limits, HTTP transcript and
evidence files. It omits source trees, source inventories, producer executables,
private build records and private reports. The original manifest retains their
names and hashes; its bytes and signature are not redacted or replaced.

The verifier checks the v3 export's authenticated head algorithm, signature,
chain, Merkle root and supported witness/timestamp evidence. A successful local
history with no independently pinned witness or TSA reports CONSISTENT. Requiring
independent attestation refuses these histories.

This profile authenticates the records sidecar's bytes as a manifest artifact,
re-seals every supported current record/2 intent, decision and record, and checks
one-to-one binding to the export, including receipt identity and grant projections.
Successful output sets `sealed_records_resealed` and
`sealed_sidecar_binding_verified` to true and reports `resealed_record_count`.
[RECORDS.md](RECORDS.md) specifies the preimages and supported profile.
Receipt-chain seals are outside this profile; `receipt_chain_verified` is false.
Omitted files are never checked, so `full_private_bundle_verified` remains false.
Matching signed source or producer-binary commitments do not establish that their
contents were checked or that the framework execution occurred.

The external package's Python wrapper additionally checks case/result counts and
matching disclosed case-plan bytes, then generates a comparison. Shared suites
1.0.0, 2.0.0 and 3.0.0 have explicit case-ID, kind and native-execution profiles. Suite
2.0.0 and 3.0.0 also check recorded per-case status and provider/request deltas against the
signed plan. Suite 3.0.0 fixes the journal refusal/recovery expectations, checks
signed fault-mode/counter and durable-record observations, and binds the selected
requests to their transcript. Refusals require HTTP 503 with no returned grant
or simulated dispatch; recovery requires a confirmed synthetic execution. The
post-append error can leave an allowed durable record while the failed request
dispatches nothing. Faults are injected at the Record API; physical storage
failures, receipt-write failures and existing grant revocation are outside scope.
These checks authenticate recorded assertions; they do not re-run
frameworks or independently establish fault injection. Recorded test
outcomes, consistency and independent attestation remain separate fields.

These checks do not establish capture completeness, input truth, real-world
execution, independent reproduction, production readiness or certification.
