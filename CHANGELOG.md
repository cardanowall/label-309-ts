# Changelog

All notable changes to the CIP-309 TypeScript SDKs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** These packages are pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial public release of the CIP-309 TypeScript SDKs:
  `@cardanowall/crypto-core` (cryptographic primitives), `@cardanowall/poe-standard`
  (CIP-309 record schema, canonical-CBOR encoder, structural validator), and
  `@cardanowall/sdk-ts` (standalone verifier, gateway-agnostic HTTP client,
  off-host signing, seed-derived identity helpers).
- Byte-parity with the Python and Rust SDKs, proven against the shared
  cross-implementation conformance vectors.
