# Security policy

## Reporting a vulnerability

Report security issues in this verifier, or in the evidence format it implements, through the contact details published at https://aaes.ai/legal/security.html. Do not open a public issue for a vulnerability report.

## Scope

This repository contains the standalone offline verifier for AAES evidence exports. Release v0.3.0 reads `aaes.export/v2`, `aaes.export/v3` and `aaes.export/v4`, verifies trust receipts (`--receipt`), and binds a record/2 sidecar (`--records`) or a disclosed evaluation directory (`--evaluation`) to an export. Findings in scope include incorrect acceptance of malformed or tampered exports, cryptographic verification errors, and canonicalization disagreements that let two readers accept different byte sequences as the same value.

Out of scope: the AAES platform itself, which is closed source and reported through the same channel.

## Trust model notes

Verification is offline, but trust material (the signing public key, TSA roots, pinned witness keys) must be supplied out of band. Embedded keys do not establish their own trust. A PASS result establishes the documented integrity properties only; it does not establish capture completeness, the truth of recorded inputs, or independence from the producer without pinned independent trust material. The specification at https://aaes.ai/spec.html lists exactly what verification does and does not establish.
