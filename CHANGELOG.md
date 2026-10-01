# Changelog

## v0.2.0 — 2026-10-01

- Adopt `aaes.export/v2` as the sole supported export format, with integer
  minor units and explicit currency. Reject v0/v1 and mixed legacy amounts.
- Remove the floating-point v1 preimage and header-alias rewriting.
- Include current synthetic v2 vectors, an open specification and contribution
  guidance for independent readers.
- Add native six-platform tests and tagged binary releases with checksums and
  source-revision metadata. Expose build identity with `--version`.
- Preserve separately supplied trust, independence reporting, receipt binding,
  bounded input and fail-closed signature/log-identity checks.

Previous source tags remain historical and unsupported by the current reader.
