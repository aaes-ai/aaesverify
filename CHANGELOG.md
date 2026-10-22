# Changelog

## v0.3.0 — 2026-10-22

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
  entries. A carried anchor head must be signed by the same key, name the same
  log and cover the receipt's leaf; the summary says when it is the same tree
  state as the proof. A verified receipt establishes that the decision record
  was committed to the signed log under the given key; it does not establish
  that the action executed or that the record set is complete.
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
- Refuse a v2 or v3 export whose signed header or anchor head names a schema.
  The header label is not signed, so a v4 head under an edited v2/v3 label
  would otherwise skip the v4 verdict rules.
- `--records` and `--evaluation` report the same verdict as export mode, so gaps
  and shredded fields are no longer reported as plain CONSISTENT.
- `usage` caps report size at 16 MiB and refuses an `--export` that does not
  verify instead of taking its ledger key on trust. `--evaluation` without
  `--pubkey` prints an unpinned-signer warning.
- Keep omitted source, receipt-chain verification, completeness, real effects and
  independent attestation outside the claims established by local consistency.
- Refuse an export line that repeats a member name, exactly or under
  `encoding/json`'s case-insensitive matching (for example `actor_id` and
  `Actor_ID`). The same refusal applies to usage reports. Go kept the last
  spelling while other JSON readers showed the first, so a third party could
  change a displayed value while the export still verified.
- For an `aaes.export/v4` file, `--pubkey` is the trust anchor: an embedded key
  that differs is refused instead of being used. Add `--keyring` and
  `--expected-final` for v4 files. The text summary prints the verifier's scoped
  v4 verdict (for example `UNPINNED_CONSISTENCY`) instead of CONSISTENT.
- The text summary names gap ranges and shredded-field counts, as the AAES
  platform CLI does. Both CLIs now share the summary code.
- Compute anchor prefix roots in one pass, so an export with many anchor lines
  no longer takes quadratic time. Usage-report sums refuse 64-bit overflow.

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
