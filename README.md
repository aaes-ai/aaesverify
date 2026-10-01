# aaesverify

The public, Apache-2.0 offline reader for **`aaes.export/v2`** evidence.
It runs on your machine without contacting AAES or any network service.
The current supported software release is **v0.2.0**. Earlier export formats
are retired and rejected. The software release number and wire-format number
are independent.

## Download or build

Download the binary for your OS and architecture from
[the v0.2.0 release](https://github.com/aaes-ai/aaesverify/releases/tag/v0.2.0).
The release contains macOS, Linux and Windows builds for amd64 and arm64,
`SHA256SUMS.txt`, and build information tied to the tagged source revision.
Checksums detect changed bytes. Authenticate the publisher and signing key
through channels you trust before relying on them.

To build the tagged source with Go 1.27 or later:

```sh
git clone --branch v0.2.0 https://github.com/aaes-ai/aaesverify.git
cd aaesverify
go test ./...
go build -trimpath -ldflags="-X main.version=v0.2.0" -o aaesverify ./cmd/aaesverify
./aaesverify --version
```

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

Optional flags: `--tsa-roots`, `--witness-trust`, `--require-independent`,
`--allow-pre-anchor`, `--json`, and `--version`. `--require-independent`
rejects evidence without a witness or timestamp verified against caller-supplied
trust material. It does not configure those services. A header-only, unsigned
`pre_anchor` declaration requires explicit `--allow-pre-anchor` opt-in.
Exports are bounded to 1 GiB and lines to 4 MiB.

Exit codes: 0 means the integrity checks passed, 1 means refusal or a failed
check, and 2 means usage or trust-file loading failure.

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

[SPEC.md](SPEC.md) describes the implemented verification profile. The public
[JSON Schema](https://aaes.ai/spec/v2/export.schema.json) documents the v2 envelope.
This is an openly documented implementation profile, not a claim of adoption
as an ISO, IETF or other external standard. Independent readers and conformance
contributions are welcome through [CONTRIBUTING.md](CONTRIBUTING.md).

The verifier imports only the Go standard library, `internal/hash` and the
small `internal/types` subset. Import-closure tests enforce this boundary.
Sharing hash/types code with the producer creates common-mode risk. This reader
is not an independently written second implementation.

`aaes.records/v1` and `aaes.evidence-pack/1` are separate companion formats,
not legacy exports. This slim reader has no `--records` flag and does not
perform platform sidecar binding.

## License and release policy

Source and release binaries are Apache-2.0 under [LICENSE](LICENSE). They do not
require an AAES evaluation agreement. The AAES platform is distributed separately.
Only the current export format and current verifier release are supported.
Published Git history remains a record of earlier source releases.
See [SECURITY.md](SECURITY.md) for vulnerability reporting.
