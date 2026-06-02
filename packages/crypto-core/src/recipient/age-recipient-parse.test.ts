// Tests for parseAgeRecipient — the decode side of the age recipient codec.
//
// Decoding must be the exact inverse of the encoders: parsing a recipient string
// recovers the raw public key and the KEM its HRP implies. X25519 cases are
// pinned to the same public keys the sibling kat test uses (derived from the
// three canonical identity seeds); the X-Wing case re-derives the 1216-byte key
// from the seed, encodes it, and round-trips it back through the parser.

import { describe, expect, it } from 'vitest';

import { deriveMlKem768X25519KeypairFromSeed } from '../seed-derive/derive';
import { bech32EncodeNoLimit } from './bech32';
import {
  encodeAgeX25519Recipient,
  encodeAgeXWingRecipient,
  parseAgeRecipient,
} from './age-recipient';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// X25519 public keys derived from the all-zero / all-0xff / 0xdeadbeef… seeds —
// identical to the constants the age-recipient kat test pins.
const X25519_VECTORS: ReadonlyArray<{ seed: Uint8Array; publicHex: string }> = [
  {
    seed: new Uint8Array(32),
    publicHex: 'c527cc01603c30c38718de8bfbca6af5063693c14ebb5dcc42b3f7389dfe6547',
  },
  {
    seed: new Uint8Array(32).fill(0xff),
    publicHex: '367e677010b246efdd40e99d7a54fa73ceca3f161d074cab6bf3b7ba04c6c42a',
  },
  {
    seed: hexToBytes('deadbeef'.repeat(8)),
    publicHex: 'e2499ff278f507ed0c48ceea07675d31da7ddf888ddad7d3cdc84b89871ff766',
  },
];

describe('parseAgeRecipient', () => {
  it('round-trips encode → parse for both KEMs', () => {
    const x25519Pub = new Uint8Array(32).fill(7);
    const xwingPub = new Uint8Array(1216).fill(9);

    const x = parseAgeRecipient(encodeAgeX25519Recipient(x25519Pub));
    expect(x.kem).toBe('x25519');
    expect(x.publicKey).toEqual(x25519Pub);

    const q = parseAgeRecipient(encodeAgeXWingRecipient(xwingPub));
    expect(q.kem).toBe('mlkem768x25519');
    expect(q.publicKey).toEqual(xwingPub);
  });

  it('decodes an X25519 recipient back to the pinned public key', () => {
    for (const { publicHex } of X25519_VECTORS) {
      const parsed = parseAgeRecipient(encodeAgeX25519Recipient(hexToBytes(publicHex)));
      expect(parsed.kem).toBe('x25519');
      expect(bytesToHex(parsed.publicKey)).toBe(publicHex);
    }
  });

  it('decodes a real derived X-Wing key, round-tripping through encode', () => {
    for (const { seed } of X25519_VECTORS) {
      const { publicKey } = deriveMlKem768X25519KeypairFromSeed(seed);
      expect(publicKey.length).toBe(1216);
      const parsed = parseAgeRecipient(encodeAgeXWingRecipient(publicKey));
      expect(parsed.kem).toBe('mlkem768x25519');
      expect(parsed.publicKey).toEqual(publicKey);
    }
  });

  it('tolerates surrounding whitespace on a pasted recipient', () => {
    const s = encodeAgeX25519Recipient(new Uint8Array(32).fill(1));
    expect(parseAgeRecipient(`  ${s}\n`).publicKey).toEqual(new Uint8Array(32).fill(1));
  });

  it('rejects an empty string', () => {
    expect(() => parseAgeRecipient('')).toThrow();
  });

  it('rejects a corrupted checksum', () => {
    const s = encodeAgeX25519Recipient(new Uint8Array(32).fill(2));
    const broken = s.slice(0, -1) + (s.endsWith('q') ? 'p' : 'q');
    expect(() => parseAgeRecipient(broken)).toThrow();
  });

  it('rejects a mixed-case string', () => {
    const s = encodeAgeX25519Recipient(new Uint8Array(32).fill(3));
    const mixed = s.slice(0, 12).toUpperCase() + s.slice(12);
    expect(() => parseAgeRecipient(mixed)).toThrow(/mixed-case/);
  });

  it('rejects a checksum-valid string under an unrecognized HRP', () => {
    const s = bech32EncodeNoLimit('xyz', new Uint8Array(32).fill(4));
    expect(() => parseAgeRecipient(s)).toThrow(/unrecognized recipient prefix/);
  });

  it('rejects a correct HRP carrying the wrong key length', () => {
    // A checksum-valid age1pqc string whose payload is 32 bytes (not 1216).
    const wrong = bech32EncodeNoLimit('age1pqc', new Uint8Array(32).fill(5));
    expect(() => parseAgeRecipient(wrong)).toThrow(/1216-byte/);
  });
});
