# Verification profile — `aaes.export/v3`

This document specifies v3 reading as released in v0.3.0. The v0.2.0 binaries
read v2 only. No deployment qualification is claimed. The [v2 specification](SPEC.md) continues to describe retained v2
evidence; the rules below state the precise differences.

## Signed algorithm

The current writer emits `aaes.export/v3`. The header head and every anchor
head must contain `"algorithm":"ed25519"`. This field is part of the canonical
head payload with `signature` removed. It is covered by the head signature,
external timestamp digest and witness countersignatures. Envelope metadata
such as `signature_algorithm` cannot replace it.

The verifier rejects a missing algorithm in a v3 head or anchor, and rejects
any unsupported signed algorithm even if the signature bytes would verify
under Ed25519. Altering or removing a modern signed algorithm breaks its
signature. Changing an unsigned header's schema to v2 cannot repair that
signature. The implementation is in `internal/hash/merkle.go`,
`internal/verifier/chain.go` and `internal/verifier/export_verify.go`.

The current reader accepts retained `aaes.export/v2` evidence. An absent
algorithm on a historical v2 head means the original Ed25519 preimage, with
no added field. The reader verifies those original bytes; it does not rewrite
or re-sign an old export. Normalization preserves the original schema.
Retired v0/v1 exports and unknown versions remain refused.

Two rules apply to v2 evidence as well. A timestamp token without the RFC 5816
signed attributes, or whose ESSCertID does not bind the certificate that verified
it, fails timestamp verification (SPEC.md section 8.2); v0.2.0 accepted such
tokens. A v2 head that carries a signed algorithm other than `ed25519` fails its
signature check. Both rules fail closed.

Entry preimages, integer minor units, chain construction, Merkle construction,
log identity, gap/tombstone checks and trust-pin checks retain the v2 rules.
The v3 [JSON Schema](schemas/export.schema.json) and
[retained v2 schema](schemas/export-v2.schema.json) describe their respective
envelopes. Schema validation alone does not verify signatures or integrity.

## Verification result

The current result document identifies itself as `aaes.verify-result/2` and
reports the export's original schema separately. An unsuccessful check reports
`FAIL`. An otherwise successful complete check reports `CONSISTENT` unless
an independent witness or timestamp has verified against caller-supplied
trust material, in which case it reports `PASS`. Existing successful gap and
shredded-field results remain `OK_WITH_GAPS` and `OK_WITH_SHREDDED_FIELDS`.

Independent witness and timestamp counters retain the v2 verification rules;
a producer-supplied label or embedded key does not establish independence.
Text and JSON consumers must use this result vocabulary rather than treating
`ok: true` as a claim of independent attestation. The slim CLI prints warnings.
An embedded signing key still establishes internal consistency only.

The published v0.2.0 binary predates this vocabulary and prints `PASS` for the
synthetic witnessless v2 sample. Public download instructions identify that
legacy behavior explicitly. This release reports `CONSISTENT` for the
same sample, and its release binaries carry checksums with a keyless signature.

## FIPS mode and certificate bindings

In Go FIPS mode, a CMS `signingCertificate`/ESSCertID SHA-1 binding is refused
before SHA-1 is invoked. It produces a certificate-binding error rather than
a cryptographic runtime panic. ESSCertIDv2 with the existing approved SHA-2
binding remains supported. Standard mode retains historical SHA-1 binding
verification. This behavior is exercised in both implementations' hash tests;
it does not certify a customer operating environment.

## Conformance evidence in this checkout

In the AAES monorepo, `internal/store_versions/testdata/export_v3.jsonl` is a
synthetic export made through the actual current producer with a public
demonstration key; that fixture and the producer tests are not part of this
checkout. Here, `tools/check_cli.py` generates a synthetic v3 export with a
fresh key and runs the release binary against it. Go tests in this checkout
exercise the reader on the preserved v2 fixture, authenticated algorithm
mutation, invalid algorithms, the verdict vocabulary and normalization. The
producer, served console pack and JSON Schema fixture tests run in the AAES
monorepo and are not part of this checkout. These tests establish
the scoped software behavior; they do not establish capture completeness,
key provenance, customer independence or deployment acceptance.
