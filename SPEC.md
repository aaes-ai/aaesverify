# Open verification specification — `aaes.export/v2`

**Status:** published specification of the verification surface, grounded in the
code it describes. **Audience:** a third party — a customer's auditor, a
regulator's examiner, a witness operator — who must be able to verify AAES
evidence **without trusting AAES**, including by reimplementing the checks in
another language.

This specification describes the current wire format and the checks a second
implementation must reproduce. It is not an assessment or certification.
Only `aaes.export/v2` is supported. Retired v0/v1 exports must be regenerated
from the original journal using the current writer, never relabelled.

Every rule below names the source file that implements it. Where this document
and the code disagree, **the code is wrong about itself and this document is
wrong about the code: treat the disagreement as a defect and report it.** The
reference implementation is `internal/verifier/` — a package that may
import only the Go standard library, `internal/hash` and `internal/types`, a
constraint the build enforces (`TestNoForbiddenImports` and the
closure-walking `TestNoForbiddenImportsInTheClosure`). A verifier that shares
code with the producer shares its bugs and its incentives; that is why the
reference verifier is small, stdlib-only and readable in an afternoon.

Nothing in this document is a claim that any particular deployment has
witnesses, a TSA, or even a signer. Section 12 states what verification does
**not** prove.

---

## 1. Primitives and notation

- `SHA256(b)` — the SHA-256 digest of byte string `b`.
- `HEX(b)` — lowercase hexadecimal encoding of `b`, no separators.
- `SHA256Hex(b) = HEX(SHA256(b))` — a 64-character lowercase ASCII string.
  All hashes in the format are these hex strings, and where a hash string is
  an input to a further hash, it is hashed **as its ASCII hex bytes**, never
  as decoded binary (`internal/hash/canonical.go`, `SHA256Hex`).
- `CJSON(v)` — canonical JSON encoding of `v`, defined in section 2.
- Ed25519 — RFC 8032 signatures; public keys are 32 bytes, signatures 64 bytes.
- All timestamps in canonical bytes are RFC 3339 with nanosecond precision in
  UTC (`2006-01-02T15:04:05.999999999Z07:00`, Go's `time.RFC3339Nano` after
  `.UTC()`).

## 2. Canonical JSON (`CJSON`)

Two independent encoders must not disagree on the bytes of the same value, so
every hashed or signed object is encoded with the canonicaliser in
`internal/hash/canonical.go` and `canonical_number.go`:

1. **Objects:** keys sorted bytewise (UTF-8 byte order), emitted as
   `"key":value` with no whitespace, no duplicate keys, `,` between members.
2. **Strings:** JSON string encoding exactly as Go's `encoding/json` emits it:
   control characters, `"` and `\` escaped; `<`, `>`, `&` emitted as
   `\u003c`, `\u003e`, `\u0026`; U+2028/U+2029 escaped; all other non-ASCII
   emitted as raw UTF-8.
3. **Numbers:** exact decimal arithmetic, no float64 round-trip. Integer,
   decimal and exponent spellings of the same value normalise to one byte
   string: `9007199254740993`, `9007199254740993.0` and `9007199254740993e0`
   are byte-identical, and integers beyond the IEEE-754 53-bit range stay
   distinct. Trailing fractional zeros are removed; a zero fraction and a
   zero exponent disappear. Export amounts use signed 64-bit integer minor units with a stated currency.
   The export preimage contains no floating-point amount field. NaN and
   ±Inf are rejected, not encoded.
4. **Booleans and null:** `true`, `false`, `null`.
5. **Arrays:** in order, `,`-separated, no whitespace.
6. **Times:** RFC 3339 Nano, UTC, quoted string (see section 1).
7. **Byte slices:** standard base64 (RFC 4648, with padding) as a JSON string
   — the `encoding/json` rule for `[]byte`. Signatures and keys in signed or
   hashed payloads canonicalise as base64 strings.

A reimplementation that gets any of these seven rules wrong will compute
different bytes and therefore different hashes. That is the intended failure
mode: disagreeing verifiers fail loudly, never silently agree.

There is a frozen legacy variant (`LegacyCanonicalJSON`, float64 round-trip)
that exists only to re-derive historical v1 journal records. It is **not**
part of this specification; `aaes.export/v2` uses `CJSON` exclusively.

## 3. Entries and the entry preimage

One entry is one journal record as the ledger sees it
(`aaes/internal/audit/audit.go`, type `Entry`). The transparency log stores
hashes and provenance only — never prompts, payloads or secrets. The following
fields define the **entry preimage**:

| Field | JSON name | Type | Notes |
|---|---|---|---|
| tenant id | `tenant_id` | string | required; every entry's tenant must equal the export header's |
| sequence | `sequence` | uint64 | strictly increasing; sequences start at 1 |
| record hash | `record_hash` | string | hex digest of the sealed journal record |
| intent id | `intent_id` | string | |
| actor id | `actor_id` | string | may carry the `enc:v1:` marker (section 9) |
| capability | `capability` | string | |
| tier | `tier` | int | risk tier (`types.RiskTier`, a JSON number) |
| allowed | `allowed` | bool | |
| grant id | `grant_id` | string | |
| amount minor units | `amount_minor` | int64, optional | omitted when zero, currency-specific minor units |
| amount currency | `amount_currency` | string, optional | omitted when empty, otherwise the explicit currency |
| occurred at | `occurred_at` | time | |
| linked at | `linked_at` | time | |
| tombstone | `tombstone` | object, optional | omitted entirely when absent (section 10) |

An unpriced entry omits both amount fields. An entry with a zero amount and a
non-empty currency omits `amount_minor` but retains `amount_currency`. A
nonzero amount retains both. The preimage has 11 base fields, plus each
nonzero/non-empty amount field and an optional tombstone. The removed
`amount_usd` field is invalid, including in a mixed v2 entry.

A tombstone, when present, has fields `from_sequence`, `to_sequence`,
`reason`, `authorised_by`, optional `policy_id`, `record_count`,
`receipt_count`, and `removed_at`. It is **inside** the preimage, so the head
signature covers it: a tombstone that could be added or widened without
breaking the chain would be a way to explain away a deletion.

```
preimage_i = CJSON(entry_i)        # the fields above, applying omission rules
leaf_i     = SHA256Hex(preimage_i)
```

The producer (`audit.Entry.Preimage`) and the verifier
(`verifier.EntryView.preimage`) build these bytes from struct definitions that
must agree field for field; `TestVerifierAgreesOnEntryPreimage` fails the
build if they drift. A third party needs only the field table above and
section 2.

## 4. The hash chain

The chain binds order. Genesis uses a domain constant, and the previous link
is hashed as its ASCII hex bytes (`hash.Chain`):

```
chain_0 = SHA256Hex("aaes/genesis" || 0x00 || preimage_0)
chain_i = SHA256Hex(chain_{i-1}   || 0x00 || preimage_i)   # chain_{i-1} as ASCII hex
```

Reversing, dropping or inserting an entry changes every later chain hash.
Verification walks the whole export from genesis and recomputes every link
(`verifier/chain.go`, `checkChain`); a partial window cannot match the head
root, which is deliberate: a log that can show you an arbitrary slice is not
a log.

## 5. The Merkle tree

The tree commits the set of leaves to one root. **This is not the RFC 6962
tree shape.** The semantics are RFC 6962-style (append-only, signed tree
heads, inclusion proofs); the construction is AAES's own, frozen in
`internal/hash/merkle.go`, and a published root will not match an
RFC 6962 implementation's root over the same leaves. Do not "fix" this with
a CT library.

```
leaf_node(l)  = SHA256Hex("leaf:" || l)              # l is the ASCII hex leaf
node(l, r)    = SHA256Hex("node:" || l || ":" || r)  # l, r ASCII hex, ':' separator
```

Construction: pair nodes left to right; a level with an odd number of nodes
duplicates its last node before pairing, **at every level**. Repeat to one
node. The root of an empty tree is the constant `SHA256Hex("aaes/empty")`.

### 5.1 Inclusion proofs

`hash.ProveInclusion` emits, for the leaf at `index` in a tree of `tree_size`:

- `siblings[]` — the audit path, bottom level first. At a duplicate-last
  position the sibling is recorded as the empty string.
- `self_siblings[]` — one boolean per level: true where the node was paired
  with itself.
- `root_hash` — the root the path claims.

Verification (`hash.VerifyInclusion`) is stricter than recomputing hashes,
and a conforming implementation must reproduce all of it:

1. `tree_size > 0` and `index < tree_size`.
2. `len(siblings) == len(self_siblings) == depth`, where `depth` is the number
   of times `tree_size` must be halved (ceiling division, overflow-safe) to
   reach 1. A proof for a smaller tree must not verify against a larger one.
3. Walk up: at each level derive the self-sibling condition from the geometry
   (`width` odd and `index == width-1`) and require the proof's flag to match
   it — the flag is checked, not believed. At a self-sibling level the
   recorded sibling must be the empty string and the verifier substitutes the
   node it just computed; at any other level the sibling must be non-empty.
4. Pair as `node(h, sib)` when the running index is even, `node(sib, h)` when
   odd; halve index and width per level.
5. The walk must finish at width exactly 1 and the computed node must equal
   `root_hash`.

`VerifyInclusionAgainst` additionally binds the proof to a trusted tree head:
the proof's `tree_size` and `root_hash` must equal the head's, so a proof
cannot name a different size or root than the head committed to.

### 5.2 Consistency proofs — deliberately not used

`hash.ProveConsistency`/`VerifyConsistency` exist in the frozen API
(`docs/INTERFACES.md` §5) but have **no production caller**. The property an
auditor relies on — each anchor's signed root is the root of a genuine prefix
of this export's entries — is established by recomputation at verification
time (section 7.2), not by a carried proof object.

## 6. Tree heads and the head signature

A tree head (`hash.TreeHead`) is a signed commitment to one log state:

| Field | JSON name | In signed payload |
|---|---|---|
| log id | `log_id` | yes — always present, never omitted |
| index | `index` | yes — equals the last entry's sequence |
| root hash | `root_hash` | yes |
| tree size | `tree_size` | yes — equals the entry count |
| signed at | `signed_at` | yes |
| signature | `signature` | **no** — omitted from the payload |

```
head_payload = CJSON(head with signature removed)
signature    = Ed25519.Sign(signing_key, head_payload)     # 64 bytes
```

`audit.HeadPayload` and `verifier.HeadPayload` build the same bytes
(`TestVerifierAgreesOnHeadPayload`). The signature verifies with plain
Ed25519 verification over `head_payload` (`audit/sign.go`,
`verifier/chain.go`); wrong key length or signature length is a failure, not
a fallback.

### 6.1 The log id — which log signed this

```
log_id = "aaes/log-id/1/" || HEX(SHA256("aaes/log-id/1/" || tenant_id))
```

`hash.DeriveLogID` is the one helper both sides call, and it is deterministic
in the tenant id alone — not in a display name, not in deployment config —
so an offline verifier can recompute it from nothing but the export header.
`log_id` sits **inside** the signed payload and deliberately has no
`omitempty`: removing it is a visible signature break, not a quiet return to
a legacy encoding. Without it, a head signed by one log's key — witness
countersignatures included — could be replayed as an anchor of a different
log run under the same key.

Verification requires, for the published head and every anchor head:
`log_id` non-empty (empty is `ErrLegacyHead`: pre-log-id material, refused by
name) and `log_id == DeriveLogID(header.tenant_id)` (else
`ErrLogIDMismatch`). The header itself is **not** covered by the head
signature, so the header's tenant label is trusted only after it agrees with
every entry's `tenant_id` — entries are covered, because they are inside the
hash chain.

### 6.2 Which key

Verification runs against a public key the auditor holds **out of band**
(`aaesctl verify --pubkey`: hex or base64, optional `ed25519:` prefix, 32
bytes — `verifier/keys.go`). The export header may also carry `public_key`
(hex) plus the additive `signing_key_id` / `signature_algorithm` pair. The
rules (`verifier/export_verify.go`, `resolveKey`):

- A supplied key that disagrees with the embedded key is `ErrKeyMismatch`, a
  hard failure — never a fallback to whichever key works.
- No supplied key: the embedded key is used and the result records
  `key_source: "embedded"` with the warning that this proves **internal
  consistency only**.
- Neither: `ErrNoPublicKey`; `signature_ok` is false. Reporting a signature
  check as passed when no check ran is the same class of error as an unsealed
  receipt.

## 7. Anchors: timestamps and witnesses

An anchor (`audit.Anchor`) is a signed tree head plus whatever independent
evidence was available when it was emitted: an optional external timestamp
(section 8) and zero or more witness countersignatures (section 7.3). In the
export an anchor line additionally carries `key_id` and `algorithm` naming
the head's signing key — additive fields a reader that does not know them
ignores, and that make a rotated key visible rather than silently failing.

### 7.1 The digest that is anchored

```
head_digest = SHA256(head_payload)       # raw 32 bytes; recorded hex
```

`audit.HeadDigest`: the SHA-256 of the signed head payload is what goes to a
timestamp authority and what a timestamp's `digest` field records.

### 7.2 Anchor verification

For each anchor (`verifier/export_anchor.go`, `checkExportAnchor`), in order:

1. The head signature verifies under the resolved key (section 6.2).
2. The head's `log_id` names this log (section 6.1) — otherwise a signed head
   from another log under the same key could be spliced in.
3. `tree_size == 0` is rejected outright: an anchor over the empty tree
   commits to no entries, its root is a constant every log shares, and its
   witnesses attested to nothing about this history.
4. `tree_size <= entry count`, and the root recomputed over the export's own
   first `tree_size` leaves equals the anchor's `root_hash`. This prefix
   recomputation is what makes an anchor a claim about **this** history.
5. A failed anchor is recorded and the walk continues, so one result names
   every bad anchor rather than only the first.

### 7.3 Witness countersignatures

A witness is a party that is not AAES, keeps its own copy of the tree heads
it has seen, and refuses to countersign a head inconsistent with what it saw
before. One countersignature (`audit.WitnessSignature`):

| Field | JSON name | Notes |
|---|---|---|
| witness id | `witness_id` | one witness is one name |
| public key | `public_key` | carried so the verifier never asks AAES for it |
| signature | `signature` | `Ed25519.Sign(witness_key, head_payload)` over the anchor's head |
| signed at | `signed_at` | |
| key holder | `key_holder` | `"external"`, `"aes-held"` or `"unreported"` |

The countersigned bytes are exactly the `head_payload` of section 6 — the
witness signs the same canonical bytes AAES signed, log id included, so a
countersignature is bound to one log's one tree state.

**The honesty rule, stated plainly:** `key_holder` is a *producer
declaration, not a trust root*. A signature is real whoever holds the key; a
key AAES generated produces a real countersignature and proves nothing about
independence. The producer-side count (`audit.Anchor.IndependentWitnessCount`)
uses the declaration, and a witness that says nothing counts as zero. The
offline verifier is stricter (`verifier/witness_identity.go`): a
countersignature counts as **independent** only when

1. it verifies under the carried public key,
2. the witness id maps to a key the **caller supplied out of band**
   (`aaesctl verify --witness-trust`, a JSON object mapping witness ids to
   hex/base64 Ed25519 keys obtained independently of the export),
3. the carried key equals that pinned key,
4. the pinned key is not the ledger's own signing key, and
5. the anchor covers the **final** published head (same log id, index, tree
   size and root — `signed_at` excluded, because anchors are re-signed when
   emitted). A countersignature over an earlier prefix verifies and stays
   visible in `witnesses_verified`, but only a countersignature over the
   final head is independent evidence for this export.

Distinctness is over identities: one public key cannot establish two
witnesses, and one witness id cannot be counted twice
(`verifier/independence.go`). An empty signature (the noop witness) is
skipped, not counted.

### 7.4 Freshness, and what it does not mean

A witness countersignature proves the witness saw that head by its own
`signed_at`; an RFC 3161 token proves the TSA's claimed `genTime`. Neither
proves the *wall-clock* time is true — a compromised or sloppy authority can
backdate within its own clock. The format carries the authority's claimed
time; trusting that claim is a procurement decision (which TSA, which
witness), not a cryptographic one.

## 8. RFC 3161 timestamp tokens

Two separate checks exist, and the vocabulary keeps them separate.

### 8.1 Intake (producer side, `audit.RFC3161Timestamp`)

At submission time the ledger's client POSTs an RFC 3161 TimeStampReq
(`application/timestamp-query`, HTTPS only) and accepts the response only
when **PKIStatus is granted (0) or grantedWithMods (1), the TSTInfo message
imprint equals the submitted SHA-256 digest, and the echoed nonce equals the
nonce sent**. The stored token's `verified` field then reads exactly:

```
pki-status,message-imprint,nonce; cms-signature not verified
```

That string is a deliberate boundary statement: intake does **not** verify
the TSA's CMS signature. When no TSA is configured the deployment uses the
noop timestamper, which records `noop: true` and proves nothing — the two
modes are distinguishable in the export (`noop:true` vs a DER token), and a
noop must never be read as independent evidence.

### 8.2 Offline verification (`audit.VerifyRFC3161Token`, stdlib only)

The stored token is the complete DER `TimeStampResp`. Full verification —
also what `aaesctl verify --tsa-roots` runs on every non-noop token in an
export — accepts only when **all** of the following hold
(`aaes/internal/audit/rfc3161_verify.go`, with the verifier-side twin in
`verifier/timestamp.go`):

1. **Parse.** The response is DER with no trailing bytes; PKIStatus is 0 or
   1; the token is a ContentInfo of type `signedData`; the encapsulated
   content is a TSTInfo (`id-ct-TSTInfo`) and parses.
2. **Binding.** The TSTInfo message imprint algorithm is SHA-256
   (`2.16.840.1.101.3.4.2.1`) and the imprinted bytes equal the digest that
   was submitted; at intake the nonce must also match. In an export the nonce
   is not persisted, so the verifier establishes binding through the export
   itself: the anchor's `timestamp.digest` must equal
   `HEX(SHA256(head_payload))` of its own head (a digest that does not cover
   the head fails the whole anchor, witnesses included), the token's imprint
   must equal that digest, and the recorded `time` must equal the token's
   `genTime` to the second. Failures are `ErrRFC3161Binding`.
3. **CMS signature.** Only SHA-256-digest SignerInfos are acceptable: CMS
   SignedData with SHA-256 digests, signed by ECDSA P-256, RSA or Ed25519;
   when signedAttrs are present the messageDigest attribute must equal
   SHA-256 of the encapsulated TSTInfo. The SignerInfos SET is searched for a
   signer whose signature verifies under a certificate the token carries
   (matched via the SignerInfo SID); an empty SET is refused. Other algorithm
   combinations are refused, not approximated — `ErrRFC3161Signature`.
   Verification order is binding → signature → purpose → chain, so a trust
   error is only reachable for a token whose signature already verifies.
4. **Purpose.** If the signer certificate carries any EKU at all, the list
   must include `id-kp-timeStamping` (or `any`); a certificate with no EKU
   extension is valid for any purpose under X.509, and that fact is stated
   rather than hidden. Refusal is `ErrRFC3161Policy`.
5. **Configured trust.** The signer must chain — with the token's other
   certificates as intermediates, requiring the timestamping EKU — to a root
   the **caller configured** (`--tsa-roots`, a PEM bundle acquired separately
   from any token). Nil or empty roots are an error, never "trust anything";
   a signer that does not chain is `ErrRFC3161Untrusted`, an explicit error,
   never a silent pass.

### 8.3 The status vocabulary

`RFC3161Status(rootsSupplied, err)` maps every outcome onto four values — the
same vocabulary the evidence bundle consumes:

| Status | Meaning |
|---|---|
| `absent` | no timestamp was ever supplied |
| `configured-but-unverified` | a token exists but verification was not performed (e.g. no roots configured) |
| `verified` | the full five-step pass above |
| `invalid` | verification was attempted and failed — any failure, never a silent pass |

### 8.4 Honest limitations of the stdlib CMS profile

Stated in the code, repeated here so no reader has to trust a marketing
sentence:

- **SHA-256 only.** CMS digest algorithms other than SHA-256 are refused.
  This is a real interop boundary: the dev-stage smoke tests of 2026-09-19
  (`docs/security/TSA-SMOKE-TESTS.md`) found that FreeTSA signs its CMS
  SignerInfo with SHA-512 and the verifier rejects the token by design,
  while `openssl ts -verify` accepts it. A provider that does not sign with
  SHA-256 is not usable with this verifier today; widening the digest
  allowlist is a gate-4 (specialist review) decision, not a deployment
  option.
- **No revocation checking.** CRL/OCSP is never consulted. A compromised TSA
  key that has been revoked but not yet expired still chains.
- **No ESSCertID/ESSCertIDv2 binding.** The signer is matched by SignerInfo
  SID against certificates the token carries.
- **No policy-OID evaluation.** Go's stdlib cannot evaluate RFC 3161
  certificate-policy OIDs; the TSTInfo policy OID is recorded, not evaluated.
- **No countersignature or unsigned-attribute processing.** This is not full
  RFC 5652, and was never claimed to be.

## 9. Encrypted fields and crypto-shredding

Field sealing (`aaes/internal/journalcrypt/journalcrypt.go`, opt-in, off by
default) rewrites the personal-identifier fields of a journal record to
AES-256-GCM ciphertext under a per-tenant key **before** the record is
sealed. The sealed representation is what every hash covers.

The rule that makes verification survive shredding:

> **Hashes are computed over the stored bytes, and the stored bytes are the
> ciphertext.** An examiner recomputes hashes over exactly what remains;
> tamper detection and offline verification are byte-for-byte the same
> discipline with or without encryption.

Format details a verifier needs:

- A protected value carries the marker **`enc:v1:`** followed by
  base64url (no padding) of `nonce || ciphertext`. The `v1` segment is the
  field encoding's schema version: a future encoding uses a new marker so old
  readers fail loudly. The verifier duplicates the marker constant and a
  cross-package test fails the build if the two drift.
- Protected intent fields: `actor_id`, `task_id`, `correlation_id`,
  `human_free_approval_sponsor`; protected receipt field: `reported_by`.
  Everything structural — ids, tenant, capability, tier, amounts, policy
  references, timestamps, tombstones, every hash — stays plaintext.
- Destroying the tenant's key (`aaesctl tenant shred-key`) deletes the wrapped
  key file, leaves a shred marker, and is itself sealed as a governance
  record under capability **`journal.key-shred`**, written **before** the key
  is removed — a crash leaves an over-explaining record, not a silent
  destruction.

Verifier behavior (`verifier/shredding.go`): the chain, leaves, root and
signatures verify over the ciphertext exactly as stored; shredded fields
report as **unrecoverable but hashed**. Concretely, the verifier counts
entries whose actor id carries `enc:v1:` (`protected_entries`), lists every
sealed key-destruction record (`shred_events`), and adds warnings — **never
errors**. An unreadable-after-shredding field is a recorded erasure, not a
chain failure. The headline result reads `OK with shredded fields`, not a
bare PASS. What the verifier cannot tell you is whether the key file is
actually gone: the sealed record is evidence the destruction was *recorded*;
the key directory is a fact about the deployment, not the export.

## 10. Tombstones and gaps

A tombstone (section 3) is the log's own record of one retention removal, and
it is the **only** thing that makes a missing sequence range legal
(`verifier/gaps.go`):

- A tombstone is well-formed only if it names a real range
  (`from_sequence >= 1`, `to_sequence >= from_sequence`) that **precedes the
  tombstone's own sequence** (a tombstone cannot explain itself away), and
  states a non-empty reason, a non-empty authorizing operator or policy, and
  a removal time. A malformed tombstone is an error and never counts as
  coverage.
- Every sequence range absent from the export must be named by at least one
  well-formed tombstone. A range removed without one is recorded as "a
  deleted record, not retention" and fails verification.
- The first entry at sequence 0 is refused: sequences start at 1, and a 0
  would blind the gap walk to a missing sequence 1.
- A tombstone that names a range the export still contains produces a warning
  (the log was linked before the removal; the removal is recorded but nothing
  is missing from this export).

A gapped export that verifies is rendered `OK with gaps (N range(s) removed
under retention: a..b, ...)`, never a bare PASS: "I verified what you gave
me" and "you gave me everything" are different claims, and the tool exists to
keep them apart.

## 11. The export format (`aaes.export/v2`)

The export is the artifact an auditor receives: one tenant's complete log
from the first entry to the head, the signed head, and every anchor, as JSON
Lines (`aaes/internal/audit/export.go`, `WriteExport`; parsed by
`verifier/export.go`). Line-oriented so an auditor can diff, grep and shard
it. `docs/engineering/EXPORT-SCHEMA.md` documents the same line shapes with
example lines; this document is the verification-semantics authority, and the
two must not disagree.

- One JSON object per line, `\n`-terminated, UTF-8. Blank lines are skipped.
  A line longer than 4 MiB is malformed (entries are a few hundred bytes; the
  bound exists so a malformed file cannot exhaust memory).
- Line 1 is the **header**, exactly once, before any other line:
  `{"type":"header","schema":"aaes.export/v2","log_id","tenant_id",
  "exported_at","entry_count","head":{…},"public_key"(hex, optional),
  "signature_algorithm"(optional),"signing_key_id"(optional),
  "pre_anchor"(optional)}`.
  A duplicate, misplaced or absent header is malformed; an unknown `type` is
  malformed.
- One **entry line** per entry, in sequence order: `{"type":"entry",` the
  supported preimage fields `,"chain_hash":"…","leaf":"…"}`. `chain_hash` and
  `leaf` are the exporter's **claims**; the verifier recomputes both from the
  preimage fields and cross-checks. Missing or disagreeing values are errors.
  The line bytes in the file are never hashed — verification re-canonicalises
  parsed values per section 2.
- One **anchor line** per anchor: `{"type":"anchor","head":{…},"key_id"?,
  "algorithm"?,"timestamp"?,"witnesses"?}`. Timestamp and witness shapes are
  sections 8 and 7.3; the timestamp `token` is the base64 DER TimeStampResp.

Header checks that need no key: schema string is exactly `aaes.export/v2`;
`entry_count` equals the number of entry lines; every entry's `tenant_id`
equals the header's (the header is unsigned, so disagreement is treated as a
relabelled export); the head's `log_id` is non-empty and equals
`DeriveLogID(header.tenant_id)`.

`pre_anchor` is the honest flag for a snapshot taken before the first anchor
interval: the format supports anchors, so an export with **no** anchors,
timestamps or witnesses is incomplete evidence and fails unless
`pre_anchor: true` declares it — and `WriteExport` sets the flag from an
empty anchor list, so a producer cannot omit it and stripping anchors from a
later export cannot gain it. When the published head also carries
`pre_anchor` inside its signed payload, verification trusts that declaration
without `--allow-pre-anchor`; an older export whose signature does not cover
the flag still requires that opt-in.

The schema identifier is versioned (`aaes.export/v2`). Any change to the
rules in sections 2–10 is a new schema string, never a silent re-reading of
this one.

## 12. What verification does NOT prove

The honest-limitations section, because a PASS that overclaims is worse than
none. Verification of an `aaes.export/v2` export, even fully independent,
does **not** establish:

1. **That AAES did not write the history.** With the signing key, AAES can
   produce any internally consistent tree head it likes. A signature alone
   proves "whoever holds this key signed this head". Only an external
   timestamp from a third party **and** at least one independent witness
   close that gap, and the result reports how many of each were present
   instead of implying more than the file proves.
2. **Witness independence from a label.** `key_holder` is a declaration by
   the producer. Independence exists only against witness keys the *verifier*
   obtained out of band (`--witness-trust`), pinned to ids, distinct from the
   ledger key, over the final head. Even then it proves the pinned key
   countersigned; that the *organization* behind the key is genuinely
   independent of AAES is a procurement and contractual fact, not a
   cryptographic one.
3. **True wall-clock time.** A TSA token binds the digest to the TSA's
   *claimed* time; the TSA's clock accuracy and honesty are trust decisions.
   A noop token proves nothing and says so.
4. **TSA key hygiene.** No revocation checking: a revoked-but-unexpired TSA
   certificate still chains. No ESSCertID binding; no policy-OID evaluation;
   SHA-256 CMS digests only (section 8.4).
5. **Completeness of the world.** Verification covers the entries the export
   contains. Gaps are legal only under tombstones; but an event the journal
   never recorded — an action AAES was bypassed for, a connector that lied
   upstream — leaves no trace to verify. The ledger is evidence about what
   went through AAES, not about everything that happened.
6. **That plaintext identifiers survive.** Shredded fields are ciphertext
   nobody can read after the key is destroyed; hashes still verify, and the
   destruction record proves recording, not the act.
7. **Key provenance.** `--pubkey` proves the head verifies under the key you
   supplied; where you got that key is your out-of-band problem. The embedded
   key proves internal consistency only.
8. **Anything about the future.** An export has a date. Entries appended
   after the head are not covered; anchors are cadence-bound (default 15
   minutes), so very recent history is covered only by the chain and the head
   signature until the next anchor lands.

## 13. Conformance checklist

Your implementation conforms to this specification if, given an
`aaes.export/v2` file, a public key, and optionally TSA roots and pinned
witness keys, it:

**Encoding and hashing**

- [ ] Implements `CJSON` per section 2 — including exact decimal number
      arithmetic, Go-compatible string escaping, RFC 3339 Nano UTC times and
      base64 byte slices — and reproduces the published leaf/chain/head bytes
      of the reference vectors it tests against.
- [ ] Computes `leaf`, `chain` (with the `aaes/genesis` domain and the 0x00
      separator), `leaf_node`/`node` (with `leaf:` / `node:` prefixes) and the
      empty-tree constant `SHA256Hex("aaes/empty")` exactly as sections 3–5.
- [ ] Builds the Merkle tree with duplicate-last at **every** level, and does
      not substitute an RFC 6962 construction.

**Chain and tree**

- [ ] Recomputes every entry's chain link from genesis, requires strictly
      increasing sequences starting at 1, and treats recomputed `chain_hash`
      or `leaf` disagreements as failures.
- [ ] Recomputes the root over all recomputed leaves and requires
      `tree_size == entry count`, `root_hash == recomputed root` and
      `index == last sequence`.
- [ ] Verifies inclusion proofs with the full strictness of section 5.1:
      exact depth, geometry-derived self-sibling check, empty-sibling rule,
      final width 1, and binding to a trusted head's size and root.

**Heads and anchors**

- [ ] Builds `head_payload` as `CJSON` of the head minus `signature`, verifies
      Ed25519 over it, and refuses wrong key/signature lengths.
- [ ] Requires every signed head's `log_id` to be non-empty and equal to
      `DeriveLogID(tenant_id)`, and every entry's tenant to equal the
      header's.
- [ ] For each anchor: verifies the signature, rejects `tree_size == 0`,
      requires `tree_size <= entry count`, and recomputes the prefix root over
      the export's own leaves.
- [ ] Uses a caller-supplied key when given, hard-fails on disagreement with
      an embedded key, and marks embedded-key verification as internal
      consistency only.

**Witnesses and timestamps**

- [ ] Verifies witness countersignatures as Ed25519 over `head_payload`, and
      counts independence only for caller-pinned keys, distinct from the
      ledger key, over the final head, deduplicated by id and by key.
- [ ] Verifies RFC 3161 tokens per section 8.2 — binding (imprint, and nonce
      where available; in exports, digest-covers-head and genTime agreement),
      SHA-256-only CMS, EKU rule, configured roots mandatory — and maps
      outcomes onto `absent` / `configured-but-unverified` / `verified` /
      `invalid`, never a silent pass.
- [ ] Refuses empty trust stores, empty imprints, non-noop tokens without
      roots, and never counts a noop token as independent.

**Format and honesty**

- [ ] Enforces the export's structural rules (single first header, known line
      types, entry count, 4 MiB line bound) and treats unknown line types as
      malformed.
- [ ] Applies the tombstone rules of section 10: a missing range without a
      well-formed tombstone is a failure, not a gap.
- [ ] Reports shredded fields and key-destruction records as warnings, never
      errors, and never renders a gapped or shredded export as a bare PASS.
- [ ] Distinguishes "verified against supplied key/roots/pins" from "verified
      against material in the file" in its output, and fails closed when
      independence is required but absent.

## 14. Worked examples

Build the public checkout with Go 1.27 or later:

```sh
go test ./...
go build -o aaesverify ./cmd/aaesverify
./aaesverify --export cmd/aaesverify/testdata/sample-export.jsonl \
  --pubkey cmd/aaesverify/testdata/sample-pubkey.txt --json

# Retain the deployment's signing public key through a separately trusted channel.
./aaesverify --export acme.jsonl --pubkey ledger.pub

# Supply timestamp roots and witness pins separately, and require attestation.
./aaesverify --export acme.jsonl --pubkey ledger.pub \
  --tsa-roots tsa-roots.pem --witness-trust witnesses.json --require-independent
```

The witness-trust file maps witness IDs to `ed25519:<hex or base64 key>` strings
obtained directly from the witness through a trusted channel. See
`cmd/aaesverify/main.go` for parsing and `internal/verifier/` for verification.
The synthetic sample's publicly reproducible key is not a production trust root.

Exit codes: 0 means integrity passed (including gap or shredded-field warnings);
1 means refusal or a failed check, including an unsatisfied independence policy;
2 means usage or trust-file loading failure. Omitting `--pubkey` uses the embedded key and prints an internal-consistency
warning. That key cannot authenticate its own origin; supply `--pubkey` from a
separately trusted channel for deployment evidence. Its single
signing-key CLI fails closed on rotated-key history requiring another key.
Receipt verification is a library operation. Sidecar-to-record binding and
operator proof/inspection commands belong to the separate AAES platform tools.

## 15. Source of truth

| Rule | Public implementation |
|---|---|
| Canonical JSON | `internal/hash/canonical.go`, `canonical_number.go` |
| Chain, leaf/node hashes, tree, proofs, log id | `internal/hash/merkle.go`, `canonical.go`, `logid.go` |
| Entry preimage | `internal/verifier/verifier.go` |
| Head payload and signature | `internal/verifier/chain.go` |
| Export parse and verification | `internal/verifier/export.go`, `export_verify.go`, `export_anchor.go` |
| Gaps and shredding reports | `internal/verifier/gaps.go`, `shredding.go` |
| RFC 3161 token checks | `internal/verifier/timestamp.go`, `rfc3161_verify.go` |
| Witness pinning and independence | `internal/verifier/witness_identity.go`, `independence.go` |
| CLI and trust-file parsing | `cmd/aaesverify/main.go` |

Producer paths mentioned elsewhere are provenance references to the separate
platform implementation, not dependencies of this public checkout.

Cross-package agreement is test-enforced where it matters: preimage
(`TestVerifierAgreesOnEntryPreimage`), head payload
(`TestVerifierAgreesOnHeadPayload`), tree construction
(`TestTreeMatchesHashMerkleRoot`, sizes 1–512), the `enc:v1:` marker
(`TestVerifierMarkerAgreement`), and the verifier's import closure. A drift
between producer and verifier is a build failure, not a silent fork — and a
drift between this document and either is a defect to report.
