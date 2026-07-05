# @cardanowall/crypto-core — closed-catalogue cryptographic primitives for Label 309

Low-level, independently auditable building blocks for [Label 309](https://cips.cardano.org/)
Proof-of-Existence tooling: hash, KDF, signature, KEM, AEAD, canonical CBOR, COSE_Sign1,
deterministic seed derivation, multi-recipient sealed-PoE construction, envelope discovery,
RFC 9162 Merkle trees, and age-style recipient encoding.

## What it is

`crypto-core` is the bottom layer of the Label 309 package family. It is a **closed catalogue**:
it exposes only the named, vetted algorithms the Label 309 wire format references — there is no
general-purpose "bring your own algorithm" surface. Every construction is byte-pinned against
known-answer test vectors so an independent implementation can reproduce identical bytes.

The package is portable and standalone — it produces and consumes bytes and depends on no
gateway, operator, or server. It is the TypeScript reference; a byte-identical Python parity
twin (`@cardanowall/sdk-py`) and a Rust twin (the `cardanowall` crate) track the same
conformance vectors. The higher-level wire-format library (`@cardanowall/poe-standard`) and
the SDKs (`@cardanowall/sdk-ts`, `@cardanowall/sdk-py`) are built on top of these primitives.

Hybrid post-quantum is first-class: the X-Wing KEM (`mlkem768x25519`, ML-KEM-768 + X25519 per
draft-connolly-cfrg-xwing-kem) is a supported sealed-PoE branch alongside classical X25519, and
every seed-derived identity carries an X-Wing keypair so it can always _receive_ hybrid records.

## Install

```sh
npm install @cardanowall/crypto-core
```

It ships as ESM, targets modern Node.js and browsers, and uses Web Crypto / `crypto.getRandomValues`
for randomness. The cryptography is built on the audited [`@noble/*`](https://paulmillr.com/noble/)
primitives plus `@noble/post-quantum`, `cbor2`, and `hash-wasm`.

## Usage

Import from the package root, or cherry-pick a subpath export (`@cardanowall/crypto-core/hash`,
`/seed-derive`, `/sealed-poe`, `/merkle`, …).

### Hash content for a Proof-of-Existence

```ts
import { dualHash } from '@cardanowall/crypto-core';

const { sha256, blake2b256 } = dualHash(new TextEncoder().encode('hello world'));
// sha256 and blake2b256 are 32-byte Uint8Arrays
```

For large content, stream it without buffering the whole input:

```ts
import { dualHashStream } from '@cardanowall/crypto-core';

const { sha256, blake2b256 } = await dualHashStream(fileChunkAsyncIterable);
```

### Derive an identity and sign

```ts
import { deriveEd25519KeypairFromSeed, signEd25519, verifyEd25519 } from '@cardanowall/crypto-core';

const seed = crypto.getRandomValues(new Uint8Array(32)); // 32-byte identity seed
const { secretKey, publicKey } = deriveEd25519KeypairFromSeed(seed);

const message = new TextEncoder().encode('attest this');
const signature = signEd25519({ seed: secretKey, message });
const ok = verifyEd25519({ publicKey, message, signature }); // true
```

`deriveX25519KeypairFromSeed` and `deriveMlKem768X25519KeypairFromSeed` derive the encryption
keypairs from the same 32-byte seed using fixed Label 309 HKDF labels — so one passphrase-protected
seed yields a complete, deterministic identity.

### Seal a record to multiple recipients and unwrap it

```ts
import {
  deriveX25519KeypairFromSeed,
  dualHash,
  eciesSealedPoeWrap,
  eciesSealedPoeUnwrap,
} from '@cardanowall/crypto-core';

const recipient = deriveX25519KeypairFromSeed(crypto.getRandomValues(new Uint8Array(32)));
const plaintext = new TextEncoder().encode('secret payload');

// The item's plaintext-hash claim is bound into the envelope's slots MAC, so
// wrap and unwrap are handed the same `hashes` map (algorithm id → digest).
const { sha256 } = dualHash(plaintext);
const hashes = { 'sha2-256': sha256 };

// Default KEM is classical X25519; pass kem: 'mlkem768x25519' for the hybrid PQ branch.
const { envelope, ciphertext } = eciesSealedPoeWrap({
  plaintext,
  hashes,
  recipientPublicKeys: [recipient.publicKey],
});

const result = eciesSealedPoeUnwrap({
  envelope,
  ciphertext,
  hashes,
  recipientSecretKey: recipient.secretKey,
});

if (result.matched) {
  // result.plaintext recovers the original bytes
} else {
  // result.reason is 'WRONG_RECIPIENT_KEY' | 'TAMPERED_HEADER' | 'TAMPERED_CIPHERTEXT'
}
```

Recipients holding a rotated identity (current key plus archived keys, across both KEMs) pass the
whole `recipientKeyBundle` instead of a single key; the trial-decrypt loop is constant-time over the
slot count by default. `eciesSealedPoeTrialDecrypt` recovers the content key and slot index _without_
the off-chain ciphertext — the operation an inbox scanner runs to discover readable records before
fetching their blobs.

### Address a recipient as an age-style string

```ts
import {
  encodeAgeX25519Recipient,
  encodeAgeXWingRecipient,
  parseAgeRecipient,
} from '@cardanowall/crypto-core';

const classical = encodeAgeX25519Recipient(recipient.publicKey); // "age1…"
const hybrid = encodeAgeXWingRecipient(xwingPublicKey); // "age1pqc…"

const parsed = parseAgeRecipient(classical);
// { kem: 'x25519' | 'mlkem768x25519', publicKey: Uint8Array } — routed on the bech32 prefix
```

## API overview — the primitive catalogue

Each group is also a subpath export. Names below are the actual exported symbols.

| Group         | Catalogue                                                                                                                                                                |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `hash`        | `sha256` (FIPS 180-4), `blake2b256` / `blake2b224` (RFC 7693, CIP-19), `dualHash` / `dualHashStream`, `merkleSha2256Root` and inclusion-proof helpers (RFC 9162)         |
| `kdf`         | `hkdfSha256` (RFC 5869), `argon2idV13` (RFC 9106), `pbkdf2Sha256` (RFC 8018)                                                                                             |
| `sig`         | `signEd25519` / `verifyEd25519` / `getPublicKeyEd25519` (RFC 8032, strict non-cofactored verification), identity-link challenge builder                                  |
| `kem`         | `x25519Keygen` / `x25519PublicKey` / `x25519Ecdh` (RFC 7748, low-order-point rejection); `mlkem768x25519Keygen` / `…Encapsulate` / `…Decapsulate` (X-Wing hybrid PQ KEM) |
| `aead`        | `chacha20Poly1305*` (RFC 8439), `xchacha20Poly1305*`, `aes256Gcm*`                                                                                                       |
| `cbor`        | `encodeCanonicalCbor` / `decodeCanonicalCbor` (RFC 8949 §4.2.1) plus a permissive outer-wire decoder                                                                     |
| `cose`        | `coseSign1Label309Build` / `coseSign1Label309Verify`, `encodeCoseSign1` / `decodeCoseSign1`, `buildLabel309SigStructure` (COSE_Sign1, RFC 9052)                          |
| `seed-derive` | `deriveEd25519KeypairFromSeed`, `deriveX25519KeypairFromSeed`, `deriveMlKem768X25519KeypairFromSeed` — deterministic long-term identity keys from one 32-byte seed       |
| `discovery`   | `derivePassphraseDiscoveryTag` (Argon2id → HMAC), `deriveWebauthnDiscoveryTagFromPrf` — envelope-discovery tags                                                          |
| `sealed-poe`  | `eciesSealedPoeWrap` / `eciesSealedPoeUnwrap` / `eciesSealedPoeTrialDecrypt`, the slots codec, and `RecipientKeyBundle` (age-style ECIES with AEAD-bound slots)          |
| `merkle`      | `encodeLeavesList` / `decodeLeavesList` — canonical-CBOR codec for the off-chain Merkle leaves-list artefact                                                             |
| `recipient`   | `encodeAgeX25519Recipient` / `encodeAgeXWingRecipient` / `parseAgeRecipient`, bech32 codec                                                                               |
| `util`        | `compareCt` (constant-time comparison), `hexToBytes`                                                                                                                     |

See `src/index.ts` and each submodule's `index.ts` for the exhaustive surface.

## Cross-implementation parity

`crypto-core` is the TypeScript reference. Its outputs are byte-identical to the Python twin
(`@cardanowall/sdk-py`) and the Rust twin (the `cardanowall` crate) across a shared set of
known-answer test vectors — public standards-derived vectors (RFC 7748, RFC 8032, RFC 8439,
RFC 8949, RFC 9106, FIPS 180-4) alongside the Label 309 record, envelope, sealed-PoE, and
seed-derivation vectors. A divergence between any two implementations turns the parity check red.
This is what lets a record sealed or signed by one implementation be opened or verified by any
other, on any platform.

## Standard / service independence

These primitives carry no notion of a publisher or a server. A sealed PoE is opened, a record
signature is verified, and a Merkle proof is checked entirely from bytes the caller already holds —
the on-chain metadata, the optional content (or ciphertext) blob, and a recipient's own private
key. There is no issuer server in the loop at any step. `cardanowall.com` is one example deployment
of Label 309 tooling; nothing here depends on it.

## Relation to the other packages

- **`@cardanowall/crypto-core`** (this package) — the closed-catalogue primitives; portable and
  independently auditable building blocks.
- **`@cardanowall/poe-standard`** — the Label 309 wire-format library: record schema, canonical-CBOR
  encoder, pure structural validator, and the error-code catalogue.
- **`@cardanowall/sdk-ts`** — the browser + Node TypeScript SDK: the standalone verifier, the
  gateway-agnostic HTTP client, off-host signing, and seed-derived identity helpers.
- **`@cardanowall/sdk-py`** — the Python SDK: a byte-identical parity twin of `sdk-ts`.
- **`cardanowall`** (Rust crate) — the Rust SDK twin; blocking HTTP, secure-by-default.

## License

Apache-2.0
