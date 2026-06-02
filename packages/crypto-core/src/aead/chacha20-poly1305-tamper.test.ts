import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { chacha20Poly1305Decrypt, chacha20Poly1305Encrypt } from './chacha20-poly1305';
import { AeadVerificationError } from './errors';

function seedBytes(label: string, length: number): Uint8Array {
  const hash = sha256(new TextEncoder().encode(label));
  return hash.slice(0, length);
}

const KEY = seedBytes('cardanowall-aead-tamper-key-2-5', 32);
const NONCE = seedBytes('cardanowall-aead-tamper-nonce-2-5', 12);
const AAD = new TextEncoder().encode('cardano-poe-kek-v1');
const PLAINTEXT = new TextEncoder().encode(
  'sealed-poe tamper-test plaintext - 2-5 - deterministic',
);

const CIPHERTEXT_WITH_TAG = chacha20Poly1305Encrypt({
  key: KEY,
  nonce: NONCE,
  aad: AAD,
  plaintext: PLAINTEXT,
});

function flipByte(arr: Uint8Array, index: number): Uint8Array {
  const out = new Uint8Array(arr);
  const v = out[index];
  if (v === undefined) throw new Error(`flipByte: index ${index} out of bounds`);
  out[index] = v ^ 0x01;
  return out;
}

describe('chacha20Poly1305Decrypt — tamper resistance (AeadVerificationError on any mutation)', () => {
  it('round-trips the unmutated ciphertext successfully (sanity)', () => {
    const recovered = chacha20Poly1305Decrypt({
      key: KEY,
      nonce: NONCE,
      aad: AAD,
      ciphertext: CIPHERTEXT_WITH_TAG,
    });
    expect(recovered).toEqual(PLAINTEXT);
  });

  it('throws AeadVerificationError when the ciphertext body is mutated (byte 0)', () => {
    expect(() =>
      chacha20Poly1305Decrypt({
        key: KEY,
        nonce: NONCE,
        aad: AAD,
        ciphertext: flipByte(CIPHERTEXT_WITH_TAG, 0),
      }),
    ).toThrow(AeadVerificationError);
  });

  it('throws AeadVerificationError when the Poly1305 tag is mutated (last byte)', () => {
    expect(() =>
      chacha20Poly1305Decrypt({
        key: KEY,
        nonce: NONCE,
        aad: AAD,
        ciphertext: flipByte(CIPHERTEXT_WITH_TAG, CIPHERTEXT_WITH_TAG.length - 1),
      }),
    ).toThrow(AeadVerificationError);
  });

  it('throws AeadVerificationError when the nonce is mutated', () => {
    expect(() =>
      chacha20Poly1305Decrypt({
        key: KEY,
        nonce: flipByte(NONCE, 5),
        aad: AAD,
        ciphertext: CIPHERTEXT_WITH_TAG,
      }),
    ).toThrow(AeadVerificationError);
  });

  it('throws AeadVerificationError when the AAD is mutated', () => {
    expect(() =>
      chacha20Poly1305Decrypt({
        key: KEY,
        nonce: NONCE,
        aad: flipByte(AAD, 0),
        ciphertext: CIPHERTEXT_WITH_TAG,
      }),
    ).toThrow(AeadVerificationError);
  });

  it('throws AeadVerificationError when the key is mutated', () => {
    expect(() =>
      chacha20Poly1305Decrypt({
        key: flipByte(KEY, 0),
        nonce: NONCE,
        aad: AAD,
        ciphertext: CIPHERTEXT_WITH_TAG,
      }),
    ).toThrow(AeadVerificationError);
  });

  it('throws AeadVerificationError when ciphertext is truncated by 1 byte', () => {
    expect(() =>
      chacha20Poly1305Decrypt({
        key: KEY,
        nonce: NONCE,
        aad: AAD,
        ciphertext: CIPHERTEXT_WITH_TAG.slice(0, CIPHERTEXT_WITH_TAG.length - 1),
      }),
    ).toThrow(AeadVerificationError);
  });

  it('error has code "aead_verification_failed" on any mutation', () => {
    try {
      chacha20Poly1305Decrypt({
        key: KEY,
        nonce: NONCE,
        aad: AAD,
        ciphertext: flipByte(CIPHERTEXT_WITH_TAG, 0),
      });
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(AeadVerificationError);
      expect((err as AeadVerificationError).code).toBe('aead_verification_failed');
    }
  });
});
