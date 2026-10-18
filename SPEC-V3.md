# Candidate verification profile — `aaes.export/v3`

This document specifies the candidate source in this checkout. Published
v0.2.0 binaries read v2 only. No v3 binary release or deployment qualification
is claimed. The [v2 specification](SPEC.md) continues to describe retained v2
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
legacy behavior explicitly. Candidate source reports `CONSISTENT` for the
same sample; a future release must publish matching binaries and provenance.

## FIPS mode and certificate bindings

In Go FIPS mode, a CMS `signingCertificate`/ESSCertID SHA-1 binding is refused
before SHA-1 is invoked. It produces a certificate-binding error rather than
a cryptographic runtime panic. ESSCertIDv2 with the existing approved SHA-2
binding remains supported. Standard mode retains historical SHA-1 binding
verification. This behavior is exercised in both implementations' hash tests;
it does not certify a customer operating environment.

## Conformance evidence in this checkout

`internal/store_versions/testdata/export_v3.jsonl` is a synthetic export made
through the actual current producer with a public demonstration key. Go tests
exercise the current producer/reader, preserved v2 fixture, authenticated
algorithm mutation, invalid algorithms, verdict vocabulary, normalization and
served console pack. Python JSON Schema tests validate both actual fixtures
and refuse missing or unsupported v3 head algorithms. These tests establish
the scoped software behavior; they do not establish capture completeness,
key provenance, customer independence or deployment acceptance.
