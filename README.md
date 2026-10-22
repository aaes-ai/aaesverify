# aaesverify

The public, Apache-2.0 offline reader for AAES evidence exports. It runs on
your machine without contacting AAES or any network service. The current
release is **v0.3.0**. It reads `aaes.export/v3` and retained `aaes.export/v2`
evidence, reads `aaes.export/v4` under the keying rules in
[SPEC.md](SPEC.md) section 6, verifies `aaes.trust-receipt/v1` decision
receipts, re-seals current record/2 records and checks evaluation disclosures.
Earlier export formats are retired and rejected. The software release number
and wire-format numbers are independent.

A successful check without a witness or timestamp verified against
caller-supplied trust reports CONSISTENT. PASS additionally requires that
independent attestation.

`--evaluation DIR` authenticates original manifests and disclosed artifact
hashes, checks v3 exports, re-seals current record/2 records and binds them to
export entries. Omitted proprietary files and receipt-chain seals remain
unverified. See [EVALUATION-DISCLOSURE.md](EVALUATION-DISCLOSURE.md) and
[RECORDS.md](RECORDS.md). Shared suite 3.0.0 records 123/123 selected synthetic
checks across three frameworks; external verification checks recorded evidence
and does not rerun the omitted proprietary producer.
[RELEASE-CANDIDATE.md](RELEASE-CANDIDATE.md) lists the checks each release runs.

## Download or build

Download the binary for your OS and architecture from
[the v0.3.0 release](https://github.com/aaes-ai/aaesverify/releases/tag/v0.3.0).
The release contains macOS, Linux and Windows builds for amd64 and arm64,
`SHA256SUMS.txt`, and build information tied to the tagged source revision.
Checksums detect changed bytes. From v0.3.0, releases also carry
`SHA256SUMS.txt.cosign.bundle`, a keyless Sigstore signature made by this
repository's release workflow. Check it before trusting the checksums:

```sh
cosign verify-blob --bundle SHA256SUMS.txt.cosign.bundle \
  --certificate-identity "https://github.com/aaes-ai/aaesverify/.github/workflows/verify.yml@refs/tags/v0.3.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
```

The signature ties the checksums to that workflow at that tag. It does not
replace authenticating the publisher through channels you trust.

To build the tagged source with Go 1.27 or later:

```sh
git clone --branch v0.3.0 https://github.com/aaes-ai/aaesverify.git
cd aaesverify
go test ./...
go build -trimpath -ldflags="-X main.version=v0.3.0" -o aaesverify ./cmd/aaesverify
./aaesverify --version
python3 -B tools/check_cli.py ./aaesverify
```

The v0.2.0 release remains available for v2-only evidence. It does not read v3
or v4 exports, receipts, records or disclosures.

## Verify

```sh
./aaesverify --export export.jsonl --pubkey key.pub
```

Obtain the signing public key separately through a channel trusted for the
deployment under review. A key embedded in an export cannot authenticate itself.
The public synthetic sample is in `cmd/aaesverify/testdata/sample-export.jsonl`:

```sh
./aaesverify --export cmd/aaesverify/testdata/sample-export.jsonl \
  --pubkey cmd/aaesverify/testdata/sample-pubkey.txt --json
```

The sample has 16 entries and no independent witness or timestamp. Its key is
public demonstration material, not a trusted production key.

Follow the [offline-verification walkthrough](https://aaes.ai/demos.html#verification)
alongside the [public sample pack](https://aaes.ai/library/verification.html#verify-locally).
The written walkthrough explains the clean-export result, the specified tamper
test, and the trust assumptions. Video recordings will be added to that page.

Optional flags: `--tsa-roots`, `--witness-trust`, `--require-independent`,
`--allow-pre-anchor`, `--json`, and `--version`. A v4 export also takes
`--keyring` for rotated keys and `--expected-final` for the final head the
examiner expects; without `--expected-final` a v4 result is at most
`UNPINNED_CONSISTENCY`. `--require-independent`
rejects evidence without a witness or timestamp verified against caller-supplied
trust material. It does not configure those services. A header-only, unsigned
`pre_anchor` declaration requires explicit `--allow-pre-anchor` opt-in.
Exports are bounded to 1 GiB and lines to 4 MiB.

Exit codes: 0 means the integrity checks passed, 1 means refusal or a failed
check, and 2 means usage or trust-file loading failure.

To verify an `aaes.trust-receipt/v1` decision receipt:

```sh
./aaesverify --receipt receipt.json --pubkey key.pub
```

Receipt mode requires `--pubkey`. The verifier recomputes the entry leaf, checks
the inclusion proof and head signature, derives the log id from the entry
tenant, and requires the fixed decision-only claims. It refuses unknown JSON
fields and tombstone entries. A successful check reports `CONSISTENT`: the
decision record was committed to the signed log under the supplied key. This
does not prove that the action executed or that the record set is complete.
A receipt does not show that the record was not later removed.

A carried anchor head must verify under the supplied key, name the same log and
cover the receipt's leaf. When it has the same tree size as the receipt head it
must be that head, and the summary then reports the same tree state. Anchor
witnesses and timestamps are not checked in receipt mode, and neither is the
full chain. Use `--export` for full-chain checks and independent timestamp or
witness evidence. Receipt mode performs no layout or ordering checks, which are
not well-defined for compacted logs; ordering claims require full export
verification.

## Usage reports

```sh
./aaesverify usage --usage-key <hex public key> usage-2026-10.json
```

`aaesverify usage` checks an `aaes.usage-report/1` file offline: its schema,
its Ed25519 signature, the chain of usage-key rotation statements and the sums
across tenants. `--usage-key` pins the key the deployment registered at
onboarding; without it the report is checked against its own embedded key,
which shows internal consistency only. `--export` names an export of the same
deployment, and a report signed by that export's ledger key is refused. A valid
signature shows which deployment produced a report. It does not show that the
counts are complete.

## What it checks

The reader recomputes canonical entry hashes, the chain, the Merkle root and
Ed25519 head signatures. Anchors must commit to prefixes of the same history.
Timestamp and witness independence is reported separately. Signed log identity
must match the tenant under review. A receipt must bind its entry, intent,
grant and record identity to its leaf.

These checks do not establish capture completeness, input truth, correct policy
decisions, successful provider execution or the absence of conflicting histories.
Compare separately retained commitments under a defined consistency and witness
policy to investigate equivocation. A PASS is an integrity result, not an
assurance or certification verdict.

## Open format and other implementations

[SPEC.md](SPEC.md) preserves the released v2 verification profile.
[SPEC-V3.md](SPEC-V3.md) specifies the v3 extension and result vocabulary. The public
[JSON Schema](schemas/export.schema.json) documents the v3 envelope; the
[retained v2 schema](schemas/export-v2.schema.json) describes older evidence. The
[manifest schema](schemas/evidence-pack-manifest.schema.json) describes the
separate pack inventory. Both ship under this repository's Apache-2.0 license.
This is an openly documented implementation profile, not a claim of adoption
as an ISO, IETF or other external standard. Independent readers and conformance
contributions are welcome through [CONTRIBUTING.md](CONTRIBUTING.md).

The verifier imports only the Go standard library, `internal/hash` and the
`internal/types` subset it decodes (money, risk tiers, actions, effects, and
the actor, role, manager and approval enums). Import-closure tests enforce this boundary.
Sharing hash/types code with the producer creates common-mode risk. This reader
is not an independently written second implementation.

`aaes.records/v1` and `aaes.evidence-pack/1` are separate companion formats,
not legacy exports. `--export FILE --records FILE` re-seals current record/2
records and binds them under [RECORDS.md](RECORDS.md). The v0.2.0 binaries do
not provide this feature.

## License and release policy

Source and release binaries are Apache-2.0 under [LICENSE](LICENSE). They do not
require an AAES evaluation agreement. The AAES platform is distributed separately.
Only the current export format and current verifier release are supported.
Published Git history remains a record of earlier source releases.
See [SECURITY.md](SECURITY.md) for vulnerability reporting.
