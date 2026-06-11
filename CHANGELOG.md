# Changelog

All notable changes to the Label 309 TypeScript SDKs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** These packages are pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

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
