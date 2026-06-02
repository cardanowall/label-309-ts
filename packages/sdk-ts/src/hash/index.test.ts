// Smoke test for the public `@cardanowall/sdk-ts/hash` namespace.
//
// Asserts the re-exports resolve and emit the canonical SHA-256 / Blake2b-256
// digests for the empty input — both are widely-quoted reference values, so a
// regression in the re-export wiring (wrong module, wrong digest size) shows
// up immediately.

import { describe, expect, it } from 'vitest';

import { sha2256, blake2b256, dualHash } from './index';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
// Blake2b-256(empty); reference vector from RFC 7693 §A and the noble-hashes
// test corpus.
const BLAKE2B256_EMPTY = '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8';

describe('@cardanowall/sdk-ts/hash re-export barrel', () => {
  it('sha2256(empty) matches the canonical digest', () => {
    expect(bytesToHex(sha2256(new Uint8Array(0)))).toBe(SHA256_EMPTY);
  });

  it('blake2b256(empty) matches the canonical digest', () => {
    expect(bytesToHex(blake2b256(new Uint8Array(0)))).toBe(BLAKE2B256_EMPTY);
  });

  it('dualHash returns both digests for the same input', () => {
    const both = dualHash(new Uint8Array(0));
    expect(bytesToHex(both.sha256)).toBe(SHA256_EMPTY);
    expect(bytesToHex(both.blake2b256)).toBe(BLAKE2B256_EMPTY);
  });
});
