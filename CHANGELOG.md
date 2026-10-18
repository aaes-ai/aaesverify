# Changelog

## v0.3.0-rc.1 — unpublished candidate

- Accept export v3 with the authenticated head algorithm and retain v2 reading;
  continue refusing v0/v1 and unsupported schemas.
- Add current record/2 re-sealing, evaluator-input commitments and one-to-one
  export/receipt projection binding.
- Authenticate the fixed evaluation-disclosure profile and consistent versioned
  simulator metadata. Check shared suites 1.0.0, 2.0.0 and 3.0.0 in the public
  comparison wrapper, including signed journal refusal/recovery observations.
- Add native binary smoke checks for v3, records and disclosures, in addition to
  the retained v2 checks. Each run generates its single-record synthetic vector
  with a fresh key; no key file is committed. It is separate from the recorded
  three-framework suite.
- Add `aaes.trust-receipt/v1` verification and `aaesverify --receipt`. Receipt
  mode requires `--pubkey`, verifies the recomputed entry leaf, inclusion proof,
  log identity and head signature, and reports `CONSISTENT`. It refuses unknown
  JSON fields, forged entries or proofs, altered fixed claims and tombstone
  entries. A verified receipt establishes that the decision record was committed
  to the signed log under the given key; it does not establish that the action
  executed or that the record set is complete.
- Refuse non-empty `Effect` and `EffectID` in legacy `VerifyReceipt` because
  those outcome fields are not covered by the signature.
- Timestamp verification requires the RFC 5816 signed attributes on the
  token's SignerInfo: contentType id-ct-TSTInfo, a messageDigest over the
  TSTInfo, and an ESSCertID or ESSCertIDv2 whose certHash (and issuerSerial,
  when present) names the certificate that verified the signature (SPEC.md
  section 8.2). Tokens signed directly over the TSTInfo are refused. This also
  applies to retained v2 exports.
- Refuse an unsupported algorithm inside any signed head, whatever the export's
  schema label says.
- `--records` and `--evaluation` report the same verdict as export mode, so gaps
  and shredded fields are no longer reported as plain CONSISTENT.
- `usage` caps report size at 16 MiB and refuses an `--export` that does not
  verify instead of taking its ledger key on trust. `--evaluation` without
  `--pubkey` prints an unpinned-signer warning.
- Keep omitted source, receipt-chain verification, completeness, real effects and
  independent attestation outside the claims established by local consistency.

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
