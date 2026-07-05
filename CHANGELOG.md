# Changelog

All notable changes to the Label 309 TypeScript SDKs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** These packages are pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.10.0] - 2026-07-05

### Breaking

- `sdk-ts`: the sealed helper is now two-phase and the one-shot loses `quoteId`. `publishSealed(cfg, { items, recipients, maxUsdMicros })` seals a multi-item record and quotes the exact size internally under an optional USD cap; there is no separate `quote` step and no `quoteId`. `publishMerkle(cfg, { leaves, leafAlg?, maxUsdMicros? })` likewise quotes internally (no `quoteId`) and returns the published `recordBytes`.
- `sdk-ts`: the inclusion-certificate `verification.requires_trust_in_cardanowall` field is renamed `requires_issuer_trust`.

### Added

- `sdk-ts`: two-phase sealed publishing. `sealPrepare` encrypts every item offline and returns the portable, fingerprinted `prepared_seal_json_v1` artifact (`preparedSealToJson` / `preparedSealFromJson`); `submitSealed` runs the online half (internal exact-size quote, refresh-if-stale, upload, publish). A publish that fails after a paid upload throws `SubmitSealedError` carrying validated `UploadReceipt`s, so a retry resumes without re-encrypting or re-paying storage. `quotePreparedSeal` previews the price; `sealedRecord` / `encodeSealedRecord` are the air-gap seams. `SealedSubmission` returns the record bytes, URIs, receipts, and quote.
- `sdk-ts`: `publishMerkle` carries an optional `leafAlg` through to the leaves list.

### Changed

- `sdk-ts`: `preparedSealFromJson` accepts only the exact canonical serialization of `prepared_seal_json_v1` — non-canonical encodings (a null optional member, a non-integer `scheme`, a duplicate key, reordered keys) are rejected identically across the TypeScript, Python, and Rust SDKs.
- `crypto-core` and `poe-standard`: released with the coordinated 0.10.0 SDK minor; no functional changes.

## [0.9.0] - 2026-07-03

### Added

- `sdk-ts`: `client.poe.wait(poeId, { target, timeoutMs, signal })` — follows the gateway's `GET /poe/events/{poe_id}` SSE stream over the injected `fetch` until the record reaches the requested state. Spec-correct SSE parsing (buffered `id` commits, 64 KiB line / 256 KiB event caps), reconnect backoff with `last-event-id` resume, `Retry-After` on 429, and status normalization; a failed record rejects with `PoeFailedError`, a deadline rejects with `PoeWaitTimeoutError` carrying the last snapshot.
- `sdk-ts`: `estimate` module (`@cardanowall/sdk-ts/estimate`) — exact upper-bound record-size arithmetic for item, Merkle, and sealed record shapes, for quoting before the final record bytes exist. Strings are charged at UTF-8 byte length, the accumulation is precision-safe on absurd inputs, and the arithmetic is pinned to the same cross-SDK parity constants as the Python and Rust implementations.
- `sdk-ts`: `chunkBytes` option on `publishSealed` / `publishMerkle`, forwarded to the resumable upload session.

### Changed

- `crypto-core` and `poe-standard`: version alignment with the coordinated 0.9.0 release; no functional changes.

## [0.8.0] - 2026-07-02

### Changed

- `sdk-ts`: the `webhook` purpose rejection in `/fetch` now states the actual requirement. The error message and comments explain that a user-supplied URL needs a DNS-pinning SSRF guard, which this package deliberately does not provide, instead of pointing at a `fetchWebhook` function that does not exist in the published package. Behavior, error handling, and types are unchanged.
- `sdk-ts`: the README's `/fetch` export list is corrected; the package never exported `assertWebhookUrlSafe`.
- `crypto-core` and `poe-standard`: version alignment with the coordinated 0.8.0 release; no functional changes.

## [0.7.1] - 2026-06-18

### Fixed

- `sdk-ts`: Arweave content retrieval now fetches through the `turbo-gateway.com` fast-finality gateway and follows the gateway's same-domain sandbox-subdomain redirects. The redirect follow is SSRF-safe: it only targets the same registrable domain, re-checks the deny-host list on every hop, requires `https`, and caps the chain at three hops. The dead default gateways `ar-io.net` and `g8way.io` are removed.

### Changed

- `crypto-core` and `poe-standard`: version alignment with the coordinated 0.7.1 release; no functional changes.

## [0.7.0] - 2026-06-16

### Added

- `sdk-ts`: a new `@cardanowall/sdk-ts/certificate` namespace (also re-exported as `certificate` from the package root) for Label 309 **inclusion certificates** — a self-contained, standalone-verifiable proof that one or more content hashes were committed as leaves of an RFC 9162 SHA-256 Merkle tree whose root was published on Cardano under metadata label 309. `buildInclusionCertificate` computes and self-verifies per-target proofs and emits the JSON certificate; `verifyInclusionCertificate` re-verifies a certificate purely from its own bytes; `encodeCoseInclusionProof` / `encodeIetfInclusionProof` emit the COSE / RFC 9162-aligned CBOR proof and the bare IETF inclusion-proof byte string. The CBOR proof is byte-identical across the TypeScript, Python, and Rust SDKs.
- `crypto-core`: streaming sealed-PoE construction — `sealStream` encrypts content as a segmented `chacha20-poly1305-stream64k` ciphertext while reporting progress, and `unwrapStream` performs the matching streaming open, so large payloads no longer need to be held in memory whole.

### Breaking

- `sdk-ts`: `Label309Client` no longer hardcodes the `/api/v1` path segment. The configured `baseUrl` now carries the full versioned API root (e.g. `https://gateway.example.com/api/v1`) and the client appends only bare resource suffixes. Update your client configuration to include the version segment.
- `sdk-ts`: `records.verify()` has been removed. A Label 309 verdict must never require trusting a gateway, so the hosted server-side verify call is gone; run this SDK's standalone verifier — it fetches the transaction metadata from a public explorer and verifies locally — instead.

### Changed

- `poe-standard`: version alignment with the coordinated 0.7.0 release; no functional changes.

## [0.6.0] - 2026-06-13

### Added

- `crypto-core`: `streamSealedLength(plaintextLength)` returns the exact sealed-PoE STREAM ciphertext length — the plaintext length plus one 16-byte tag per 64 KiB chunk — without performing the seal, so a producer can size and quote an upload before the content-encryption key exists.

### Security

- `sdk-ts`: `records.verify()` builds the request body field by field and transmits only `fetch_content`. An untyped call site can no longer pass extra properties — including decryption credentials — through to the gateway.

### Fixed

- `poe-standard`: mixed-case CIDv1 URIs are rejected. The multibase body is decoded verbatim against the case its prefix advertises (`b`/`B` base32, `f`/`F` base16) instead of being case-folded, so a non-canonical CID no longer validates.

## [0.5.0] - 2026-06-12

### Breaking

- `records.verify()` no longer accepts `decryption` entries. Recipient verification — decrypting sealed items and re-checking plaintext hashes — is a local operation of the verifier; the HTTP client never transmits decryption credentials to any gateway. Hosted verify endpoints act as public verifiers only.

### Fixed

- `verify_uris` was never accepted by conforming gateways; the verify request now carries the correct `fetch_content` flag.

### Changed

- `crypto-core` and `poe-standard`: version alignment with the coordinated 0.5.0 release; no functional changes.

## [0.4.0] - 2026-06-11

### Changed

- **BREAKING (wire format):** The sealed-PoE construction is finalized: nonce-salted key derivation, a content-hash-bound slot transcript, segmented STREAM content encryption (`chacha20-poly1305-stream64k`), an in-ciphertext passphrase commitment, and passphrase normalization pinned to Unicode 16.0 NFKC. Records sealed by earlier releases do not decrypt or verify under 0.4.0, and vice versa.
- **BREAKING (wire format):** Record fields are de-chunked: `kem_ct` is a single byte string, URIs are plain text strings, and COSE fields are single byte strings. The only remaining chunking is the ledger-imposed ≤64-byte segmentation of the whole record body for transport.
- **BREAKING (verifier):** `sdk-ts`'s verifier returns a four-state verdict (`valid` | `pending` | `unverifiable` | `failed`) and a reworked report schema (camelCase fields, positional `items`/`merkle` results, severity-tagged issues). It enforces transaction-hash and auxiliary-data binding, never fabricates confirmation depth, never follows redirects, and treats a deny-host violation as terminal on the resolve path and per-attempt on the content path. Bytes that fail a URI's own content address are attributed to the provider as `URI_PROVIDER_INTEGRITY_MISMATCH`, distinct from a content-hash failure.
- `poe-standard`'s structural validator accepts options — supported critical extensions, verifier role, resource bounds, and a passphrase-parameter ceiling — and its error-code registry now holds 76 codes.
- Conformance vectors regenerated under the finalized wire format; transaction vectors are fully bound (transaction hash and auxiliary-data hash).

### Added

- Identity-seed string encoding in `crypto-core` (re-exported by `sdk-ts`): `encodeIdentitySeed` / `parseIdentitySeed` for the checksummed `L309-SEED-1…` form (HRP `l309-seed-`, rendered uppercase), with raw-hex input accepted; pinned by a cross-SDK conformance vector.
- New conformance families: carriage, Cardano, KDF, Unicode normalization, seed encoding, and recipient-scan negatives.

## [0.3.0] - 2026-06-06

### Changed

- **BREAKING (wire format):** Implemented the finalized sealed-PoE scheme-1 construction: `slots_mac` now authenticates a header-bound slots transcript hash, content is encrypted under an HKDF-derived `payload_key` (never the CEK directly) with structured AAD on both the recipient-slots and passphrase paths, and the X-Wing per-slot KEK salt binds the reassembled `kem_ct` and the recipient public key. Envelopes sealed under 0.2.0 do not decrypt under 0.3.0.
- **BREAKING:** `crypto-core`'s `slotsToMacCbor()` is replaced by the new `transcript` module (`canonicalizeSlots`, `computeSlotsHash`, `adContentSlots`, `adContentPassphrase`, `slotsPayloadKey`, `passphrasePayloadKey`, `xwingKekSalt`).
- Hardened recipient decryption: explicit all-zero X25519 shared-secret rejection folded into a constant-time `kem_ok` bit, CEK-conflict detection across matching slots, per-slot KEK-uniqueness checks, and slot-count / envelope-size bounds enforced before any cryptographic work.
- Passphrase decryption pins the `cardano-poe-pw-norm-v1` normalization profile (NFKC, Unicode 16.0 `White_Space` collapse, trim) and enforces a 4096-byte pre-KDF input cap.

### Added

- `poe-standard` error codes `ENC_SLOTS_DUPLICATE_KEM_MATERIAL`, `ENC_SLOTS_TOO_MANY`, and `ENC_ENVELOPE_TOO_LARGE`, with structural-validator checks that mirror the decrypt-layer bounds.
- Conformance coverage for the finalized construction: transcript, hybrid-KEK-salt, and passphrase-path KATs plus duplicate-KEM-material negatives, shared with the Python and Rust SDKs.

## [0.2.0] - 2026-06-04

### Changed

- **BREAKING:** Public API symbols renamed `Cip309*` → `Label309*` (e.g. `Cip309Client` → `Label309Client`, `buildCip309SigStructure` → `buildLabel309SigStructure`), matching the standard's rename to **Label 309**. Update imports accordingly. No wire-format or cryptographic changes — records remain byte-identical and verify unchanged.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 TypeScript SDKs: `@cardanowall/crypto-core`, `@cardanowall/poe-standard`, and `@cardanowall/sdk-ts`.
- Byte-parity with the Python and Rust SDKs against the shared conformance vectors.
