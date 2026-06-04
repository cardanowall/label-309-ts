// Public hash namespace for the Label 309 SDK.
//
// Re-exports the closed-catalogue digest primitives from
// `@cardanowall/crypto-core/hash` so SDK consumers can build their own Merkle
// leaves (`sha2256(bytes)`) or content hashes without importing the private
// crypto-core package directly. Both algorithms are registered in the
// Label 309 hash registry:
//
//   - `sha2256` — SHA-256 (default content/leaf hash).
//   - `blake2b256` — Blake2b-256 (alternative; both ride under `dualHash`).
//
// `dualHash` returns `{sha256, blake2b256}` for callers that publish under
// both algorithm identifiers in the same record.

export { sha256 as sha2256 } from '@cardanowall/crypto-core/hash';
export { blake2b256 } from '@cardanowall/crypto-core/hash';
export { dualHash } from '@cardanowall/crypto-core/hash';
export type { DualHashOutput } from '@cardanowall/crypto-core/hash';
