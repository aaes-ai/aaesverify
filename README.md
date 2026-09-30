# aaesverify: the offline AAES evidence verifier

`aaesverify` checks an AAES evidence export (`aaes.export/v1`) for integrity, fully offline. It runs locally without contacting AAES. It is released under the Apache License 2.0; see `LICENSE`.

## What it verifies

- Every entry's canonical bytes hash to the leaf the export claims.
- The hash chain links genesis to head in sequence order; the first disagreement is reported by position.
- The recomputed Merkle root over the exported leaves equals the root in the signed tree head.
- The tree head signature verifies under an Ed25519 public key supplied out of band; a head whose `log_id` is empty or does not match the export's tenant fails closed.
- Every anchor commits to a prefix of the same tree with a valid signature.
- Independence quantities are reported separately from integrity: how many external timestamps verified against caller-supplied TSA roots, and how many independent witnesses countersigned against caller-pinned witness keys.

## What it does not establish

A valid signature establishes that the holder of the supplied key signed the head. A trusted timestamp can provide evidence about when a commitment existed, and a pinned witness can attest to a commitment under its witness policy. Neither, separately or together, proves capture completeness or excludes conflicting histories; detecting equivocation additionally requires comparison of commitments and a defined consistency and witness policy. `--require-independent` is a verifier policy gate, not proof that these broader properties hold: it fails the export unless at least one independent witness or at least one independent timestamp verifies against caller-supplied trust material. Verification also says nothing about truth of recorded inputs, correctness of a recorded decision, or downstream execution.

## Design constraint that narrows the trust surface

The verification package may import only the Go standard library and two small internal packages (hashing and shared types). It never imports the producer. The constraint is enforced by tests that walk the package source and its transitive closure. A verifier that shares code with the producer shares its bugs and its incentives. The same argument applies to the shared hashing and type code the restriction permits: the constraint reduces common-mode defects, but it does not make the verifier a fully independent implementation. A second, independently written reader is the stronger check, and the published specification (https://aaes.ai/spec.html) exists to make one possible.

## Build and run

```sh
go build -o aaesverify ./cmd/aaesverify
./aaesverify --export export.jsonl --pubkey key.pub
```

Optional flags: `--tsa-roots <roots.pem>`, `--witness-trust <witnesses.json>`, `--require-independent`, and `--json`. Verification is offline, but trust material must be supplied separately: the signing public key and, when applicable, TSA roots and pinned witness keys. Embedded keys do not establish their own trust.

Exit 0 and `result: PASS` mean the integrity checks passed against the supplied key; it is not an assurance verdict.

## Demonstration vectors

The public sample pack at https://aaes.ai/library/verification.html provides:

- `sample-export.jsonl`: a synthetic export containing 16 entry lines, which must pass.
- `tamper-demo.sh`: flips one byte in a copy and requires the verifier to refuse it. These are demonstration vectors, not a complete conformance suite; diagnostic expectations must match the tested verifier version.
- `SHA256SUMS.txt`: checksums for every file.

The format specification is at https://aaes.ai/spec.html, with machine-readable JSON Schemas under https://aaes.ai/spec/v1/.

## Source layout

This repository contains only what an examiner needs, copied from the closed-source AAES monorepo without history:

- `cmd/aaesverify/` (the binary)
- `internal/verifier/` (verification logic)
- `internal/hash/` (canonical JSON, SHA-256, Merkle)
- `internal/types/` (shared types, only what the verifier imports)

Nothing else. The producer, gateway, journal, policy, credentials, directory, audit, and connector packages are deliberately absent; the import-constraint tests prove they are not reachable from the verification package.

## The rest of AAES

This repository is the verification surface only; it deliberately contains nothing else. The platform itself reaches a customer through separate artifacts:

- a public container image — `docker pull ghcr.io/aaes-ai/aaes:v0.2.0` — cosign-signed keyless by the release workflow, carrying the complete deployment set;
- the TypeScript SDK on npm — `npm install @aaes-ai/sdk`;
- the Python SDK on PyPI — `python3 -m pip install aaes-sdk` (import name `aaes`).

The AAES source repository is private, so the Go SDK (`github.com/aaes-ai/aaes/sdk/go`) is fetched with repository access. Platform evaluation packages are supplied by request; see https://aaes.ai/developers/evaluation.html.
