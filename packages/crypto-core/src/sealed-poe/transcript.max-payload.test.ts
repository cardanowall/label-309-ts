// The single-shot XChaCha20-Poly1305 maximum-payload guard.
//
// XChaCha20-Poly1305 is a single-shot AEAD: one (key, nonce) invocation can
// drive at most (2^32 - 1) 64-byte ChaCha20 keystream blocks before the 32-bit
// block counter wraps (the first block is consumed by the Poly1305 one-time
// key). That caps the plaintext at (2^32 - 1) * 64 = 2^38 - 64 bytes. The wrap
// path rejects an over-bound plaintext, and every unwrap path rejects an
// over-bound ciphertext, BEFORE the AEAD primitive is invoked, so a counter
// overflow keystream collision can never be reached. These tests pin the
// constant and exercise both sides of the boundary.
//
// The bounds are byte-length predicates over a `number`, not over a real
// buffer, so the rejection branch is exercised by passing the boundary lengths
// directly — no multi-hundred-gigabyte allocation is needed (or possible).

import { describe, expect, it } from 'vitest';

import {
  MAX_SEALED_CIPHERTEXT,
  MAX_SEALED_PLAINTEXT,
  SealedPayloadTooLargeError,
  assertCiphertextWithinBound,
  assertPlaintextWithinBound,
} from './transcript';

describe('sealed-poe maximum-payload guard', () => {
  it('pins MAX_SEALED_PLAINTEXT to (2^32 - 1) * 64 = 2^38 - 64', () => {
    expect(MAX_SEALED_PLAINTEXT).toBe((2 ** 32 - 1) * 64);
    expect(MAX_SEALED_PLAINTEXT).toBe(2 ** 38 - 64);
    expect(MAX_SEALED_PLAINTEXT).toBe(274877906880);
  });

  it('pins the ciphertext bound to the plaintext bound plus the 16-byte Poly1305 tag', () => {
    expect(MAX_SEALED_CIPHERTEXT).toBe(MAX_SEALED_PLAINTEXT + 16);
    expect(MAX_SEALED_CIPHERTEXT).toBe(274877906896);
  });

  it('rejects a plaintext length at the bound', () => {
    expect(() => assertPlaintextWithinBound(MAX_SEALED_PLAINTEXT)).toThrow(
      SealedPayloadTooLargeError,
    );
  });

  it('rejects a plaintext length above the bound', () => {
    expect(() => assertPlaintextWithinBound(MAX_SEALED_PLAINTEXT + 1)).toThrow(
      SealedPayloadTooLargeError,
    );
  });

  it('accepts a plaintext length one byte below the bound', () => {
    expect(() => assertPlaintextWithinBound(MAX_SEALED_PLAINTEXT - 1)).not.toThrow();
  });

  it('rejects a ciphertext length at the bound', () => {
    expect(() => assertCiphertextWithinBound(MAX_SEALED_CIPHERTEXT)).toThrow(
      SealedPayloadTooLargeError,
    );
  });

  it('rejects a ciphertext length above the bound', () => {
    expect(() => assertCiphertextWithinBound(MAX_SEALED_CIPHERTEXT + 1)).toThrow(
      SealedPayloadTooLargeError,
    );
  });

  it('accepts a ciphertext length one byte below the bound', () => {
    expect(() => assertCiphertextWithinBound(MAX_SEALED_CIPHERTEXT - 1)).not.toThrow();
  });
});
