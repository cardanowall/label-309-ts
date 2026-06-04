# Changelog

All notable changes to the Label 309 TypeScript SDKs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** These packages are pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-04

### Changed

- **BREAKING:** Public API symbols renamed `Cip309*` → `Label309*` (e.g. `Cip309Client` → `Label309Client`, `buildCip309SigStructure` → `buildLabel309SigStructure`), matching the standard's rename to **Label 309**. Update imports accordingly. No wire-format or cryptographic changes — records remain byte-identical and verify unchanged.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 TypeScript SDKs: `@cardanowall/crypto-core`, `@cardanowall/poe-standard`, and `@cardanowall/sdk-ts`.
- Byte-parity with the Python and Rust SDKs against the shared conformance vectors.
