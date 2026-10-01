# Contributing

The goal is a small, reproducible offline verification surface that other
implementations can read. Open issues or pull requests for interoperability,
malformed-input refusals, canonical-byte vectors and independent readers.
Report vulnerabilities privately as described in SECURITY.md.

Run `go test -count=1 ./...` and `go vet ./...`. Native CI exercises macOS,
Linux and Windows on amd64 and arm64. The golden vectors pin zero amounts,
EUR, JPY and tombstones. The public sample tests clean, modified, wrong-key,
retired-schema and unsupported independence outcomes.

Changes to signed bytes require a new explicit wire identifier and updated
vectors, specification and readers. Do not infer schema from entry contents or
silently rewrite a retired header. Companion format identifiers have their own
version histories. Keep the verifier import closure limited to the standard
library and the existing hash/types subset.

Do not imply that adding fixtures constitutes a complete conformance suite or
an independent security assessment. State precisely what a test establishes.
