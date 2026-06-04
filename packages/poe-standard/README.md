# @cardanowall/poe-standard — the Label 309 wire-format library

The wire-format library for [Label 309](https://cips.cardano.org/) Proof-of-Existence records: the
record schema, the canonical-CBOR encoder, the pure structural validator, and the canonical
error-code catalogue. Pure functions over bytes — no I/O, no network, no clock.

## What it is

This package owns the **bytes**. It builds the exact canonical CBOR that goes on chain under Cardano
metadata label 309, and it decides whether an arbitrary byte string is a structurally valid Label 309
record. It is the **structural validator** of the three Label 309 verifier roles: a pure function over
CBOR bytes, with no cryptographic signature checks, no chain resolution, and no decryption — those
belong to the verifier layer in [`@cardanowall/sdk-ts`](https://www.npmjs.com/package/@cardanowall/sdk-ts)
and its byte-parity twins.

Everything here is deterministic and side-effect-free, which is what makes a Label 309 proof
independently checkable: the same bytes always encode to the same record and validate to the same
result, in any implementation, against shared test vectors.

## Install

The Label 309 TypeScript packages are pre-1.0 and not yet published to npm. Build from the workspace:

```sh
pnpm install
pnpm --filter @cardanowall/poe-standard typecheck
```

Once published, the install will be:

```sh
# once published
npm install @cardanowall/poe-standard
```

## Quick start

### Encode a content-first record

```ts
import { encodePoeRecord, type PoeRecord } from '@cardanowall/poe-standard';

// The content hash is the primary claim; everything else is metadata about it.
const digest = new Uint8Array(32); // the 32-byte SHA-256 digest of your content
const record: PoeRecord = {
  v: 1,
  items: [{ hashes: { 'sha2-256': digest } }],
};

// Canonical CBOR (RFC 8949 §4.2.1 deterministic encoding) for submission
// under Cardano metadata label 309.
const bytes: Uint8Array = encodePoeRecord(record);
```

### Validate any record's bytes — never throws

```ts
import { validatePoeRecord } from '@cardanowall/poe-standard';

const result = validatePoeRecord(bytes);
if (result.ok) {
  // result.record is the decoded PoeRecord.
  // result.info / result.warnings carry non-fatal issues (e.g. an
  // unsupported-but-tolerated signature algorithm id).
  console.log('valid', result.record.v);
} else {
  // result.issues is a list of { code, path, message, severity }.
  for (const issue of result.issues) {
    console.error(`${issue.code} at ${issue.path.join('.')}: ${issue.message}`);
  }
}
```

`validatePoeRecord` never throws: every failure — malformed/non-canonical CBOR, schema mismatch,
registry violation, bad URI, malformed signature entry — is returned as data in a discriminated
`ValidateResult` union. The result is sorted, stable, and identical across the TS/Python/Rust
implementations.

### Build the bytes a record-level signature covers

```ts
import { encodeRecordBodyForSigning, type PoeRecord } from '@cardanowall/poe-standard';

const record: PoeRecord = { v: 1, items: [{ hashes: { 'sha2-256': digest } }] };

// record_body = the full record map MINUS sigs. Producers prepend the Label 309
// domain-separation prefix and wrap the result in a COSE Sig_structure before
// signing with Ed25519 (see @cardanowall/crypto-core for the COSE helper).
const body: Uint8Array = encodeRecordBodyForSigning(record);
```

## Records on chain: chunk → validate

The Cardano ledger caps every metadata byte string and text string at 64 bytes, so a Label 309 record
is stored as an **array of ≤64-byte CBOR-bytes chunks** under label 309, and the metadata map itself
is wrapped in the Conway tag-259 form. A verifier reassembles the chunk array (and unwraps tag-259)
before calling `validatePoeRecord` — the validator operates on the single reconstructed record byte
string. The chunking helpers are exported from the root:

```ts
import { chunkBytes, bytesChunkArrayConcat } from '@cardanowall/poe-standard';

const chunks = chunkBytes(bytes); // Uint8Array[] of ≤64-byte chunks, for label 309
const whole = bytesChunkArrayConcat(chunks); // reassemble before validate
```

`chunkUri` / `reconstructChunkedUri` do the same for the chunked URI arrays carried in
`items[i].uris` and `merkle[i].uris`, splitting on UTF-8 codepoint boundaries.

## API overview

The package root re-exports every group. Subpath imports are available for `./schema`, `./encoder`,
`./validator`, and `./error-codes`.

**Encode** (`@cardanowall/poe-standard/encoder`)

- `encodePoeRecord(record)` — canonical CBOR for chain submission.
- `encodeRecordBodyForSigning(record)` — the `record_body` (full map minus `sigs`) that record-level
  COSE_Sign1 signatures sign over.

**Validate** (`@cardanowall/poe-standard/validator`)

- `validatePoeRecord(bytes)` — the structural pipeline: canonical decode → schema parse → cross-field
  domain checks. Returns a discriminated `ValidateResult`; never throws.
- `validateCidProfile(cid)` — offline IPFS CID-profile parser (CIDv0 and the Label 309 CIDv1 multibase
  / multicodec / multihash profile).
- `type ValidateResult`, `type ValidationIssue`.

**Error codes** (`@cardanowall/poe-standard/error-codes`)

- `STRUCTURAL_ERROR_CODES` — the codes the structural validator emits (Part A).
- `VERIFIER_ERROR_CODES` — the verifier-layer codes (Part B), re-exported so downstream verifiers
  dispatch on a single union without round-tripping through the SDK.
- `ERROR_CODES` — their union; `SEVERITY` / `severityOf(code)` map each to `'error' | 'warning' |
'info'`. Codes are SCREAMING_SNAKE_CASE and byte-exact across implementations.
- `type ErrorCode`, `type StructuralErrorCode`, `type VerifierErrorCode`, `type Severity`.

**Schema + types** (`@cardanowall/poe-standard/schema`)

- Zod schemas for the full v1 wire surface: `PoeRecordSchema`, `ItemEntrySchema`,
  `MerkleCommitSchema`, `EncryptionEnvelopeSchema`, `SlotSchema`, `PassphraseBlockSchema`,
  `Argon2idParamsSchema`, `HashesMapSchema`, `HashDigestSchema`, `SigEntrySchema`,
  `SupersedesSchema`, `VersionLiteralSchema`, and the `ChunkedBytesArraySchema` / `UriChunkArraySchema`
  chunk-array schemas.
- Inferred types: `PoeRecord`, `ItemEntry`, `MerkleCommit`, `EncryptionEnvelope`, `Slot`,
  `PassphraseBlock`, `Argon2idParams`, `HashesMap`, `UriChunkArray`, `ChunkedBytesArray`, `SigEntry`,
  `Supersedes`.
- Extension-key helpers: `TOP_LEVEL_BASE_KEYS`, `isExtensionKey`, `EXTENSION_KEY_VENDOR_RE`,
  `EXTENSION_KEY_COMPANION_RE`.

**Chunking** (re-exported from the root)

- `chunkBytes` / `bytesChunkArrayConcat` — split/reassemble chunked byte strings (COSE_Sign1,
  COSE_Key blobs).
- `chunkUri` / `reconstructChunkedUri` — split/reassemble chunked URI arrays on UTF-8 boundaries.
- `type ReconstructUriResult`.

For the exhaustive surface, see `src/index.ts`.

## The record shape

A `PoeRecord` is content-first and storage-agnostic. The smallest valid record is a single item
committed by its content digest; a record may also (or instead) carry one or more Merkle
list-commitments, an optional `supersedes` link, optional record-level `sigs`, and an optional
sealed-PoE encryption envelope per item:

```ts
const record: PoeRecord = {
  v: 1,
  items: [
    {
      hashes: { 'sha2-256': digest, 'blake2b-256': altDigest },
      // Optional plural storage list (chunked URI arrays): ar:// , ipfs://
      // Optional `enc` sealed-PoE envelope (slots or passphrase key path)
    },
  ],
  // merkle: [{ alg: 'rfc9162-sha256', root, leaf_count }],
  // supersedes: prevTxId32,
  // sigs: [{ cose_sign1: [...] }],
};
```

The validator enforces the Label 309 registries (hash algorithms, AEAD, KEM, Merkle commitment, and
passphrase-KDF), rejects unauthenticated ciphers by name, pins each KEM's recipient-slot shape, and
guards against publishing private key material on chain.

## Cross-implementation parity

The encoder and validator are byte-identical across the Label 309 implementations —
`@cardanowall/poe-standard` (TS), the Python twin, and the Rust crate — validated against the same
shared canonical-CBOR known-answer test vectors. Encoding the same record yields byte-identical CBOR
in every implementation; validating the same bytes yields the same ordered list of issue codes with
the same severities. That parity is what lets a proof published by one tool verify under any other.

## Standard / service independence

A Label 309 proof is verifiable from transaction metadata, the optional content bytes, and a public
blockchain explorer — no issuer server is required. This package is the structural half of that
guarantee: given the reassembled record bytes, `validatePoeRecord` decides structural validity
offline, with no trust in the publisher, the gateway, or any domain. Signature verification, chain
resolution, and sealed-PoE decryption (the public and recipient verifier roles) build on top of it
in the SDKs.

## Relation to the other packages

- **`@cardanowall/crypto-core`** — closed-catalogue cryptographic primitives (hash, KDF, signature,
  KEM, AEAD, CBOR, COSE, sealed-PoE, Merkle). Supplies the canonical CBOR codec and COSE decoder this
  package builds on.
- **`@cardanowall/poe-standard`** — this package: the Label 309 wire format (schema, encoder, structural
  validator, error codes).
- **`@cardanowall/sdk-ts`** — the browser + Node SDK: the standalone verifier (all three roles), the
  gateway-agnostic HTTP client, off-host signing, and seed-derived identity helpers.
- **`@cardanowall/sdk-py`** — the Python SDK: a byte-identical parity twin of `sdk-ts`.
- **`cardanowall`** (Rust crate) — the Rust SDK twin; the `cardanowall` CLI binary builds on it.

## License

Apache-2.0
