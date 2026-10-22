# v0.3.0 release checks

v0.3.0 adds v3 exports, retained v2 reading, v4 reading under caller-pinned
keys, trust-receipt verification, current record/2 re-sealing and binding, and
the fixed evaluation-disclosure profile. It follows the `v0.3.0-rc.1`
prerelease. This file lists the checks a release runs; the release page and
its signed checksums record the result for each tag.

`tools/check_cli.py` executes clean and negative v2/v3, sidecar-binding and
synthetic-disclosure checks against the actual built binary. Each run generates
its disclosure vector with `go test` from `internal/evaluation`: one synthetic
record signed with a fresh key. It is not a framework evaluation or an independent
reproduction. The signing private key is never saved, and no key file is committed.
Go tests additionally check semantic mismatches with otherwise valid signatures.

The suite 3.0.0 distribution remains separately versioned evidence: 41 checks per
framework, 123 recorded checks, and 81 re-sealed records across three histories.
Its original `external-v3-candidate.5` binary and signed artifacts retain their
identities. A new release binary can verify that immutable package using its
`verify.py --verifier PATH` override. Source and producer execution remain outside
the external verification claim.

## Checks before publication

1. Check the public-source mirror and producer/reader preimage golden; review
   source, license, fixtures, schemas and dependencies for confidential material.
2. Test and vet the isolated source archive, run host race tests and a bounded
   parser fuzz run, execute the public CLI smoke checks, and verify the suite
   package using the new binary. Build twice to check byte reproducibility.
3. Cross-compile all six targets. Record compilation and execution separately.
   Local compilation does not satisfy native CI on another target.
4. Complete the required GLM 5.3 engineering review and resolve findings. A local
   agent review is not that review and no offline substitute is claimed.
5. Run native CI on macOS, Linux and Windows, each on amd64 and arm64. Each job
   runs Go tests/vet, public Python tests and actual binary v2/v3/record/disclosure
   checks. Keep exact source-revision and toolchain records.
6. Review the exact public commit and candidate version, then tag and publish
   only with owner authorization. The workflow's publication job requires a
   manual workflow dispatch, `publish_release=true`, a version-tag ref and the
   `release` environment, which must be configured to admit only `v*` tags.
   The job signs `SHA256SUMS.txt` keyless with cosign, verifies the bundle
   against the workflow identity and publishes the bundle with the release.
   Prereleases do not replace the latest stable release.
7. Attach the reviewed suite distribution and its checksum/index metadata as
   separate release assets. Download and verify the published bytes, then align
   website links, hashes and compatibility labels in one deployment.

A release does not establish independent attestation. The current histories report
CONSISTENT. Physical storage failures, receipt-write failures, existing-grant
revocation, capture completeness and real external effects remain outside the
suite. Receipt-chain seals and omitted proprietary source are not verified.
