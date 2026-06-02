import { describe, expect, it } from 'vitest';

import { CROCKFORD_ENCODED_LENGTH_FOR_UUID, decodeBytes, encodeBytes } from './crockford-base32';

const KNOWN_ZERO = new Uint8Array(16);
const KNOWN_FF = new Uint8Array(16).fill(0xff);

describe('crockford-base32', () => {
  describe('encodeBytes', () => {
    it('encodes 16 zero bytes to 26 zero symbols', () => {
      const out = encodeBytes(KNOWN_ZERO);
      expect(out).toBe('0'.repeat(CROCKFORD_ENCODED_LENGTH_FOR_UUID));
    });

    it('encodes 16 0xff bytes to 25 "z"s plus a trailing "w" (top 3 bits of last symbol set, bottom 2 are zero-pad)', () => {
      const out = encodeBytes(KNOWN_FF);
      expect(out).toHaveLength(CROCKFORD_ENCODED_LENGTH_FOR_UUID);
      // 16 × 0xff = 128 bits all set. Append 2 zero pad bits → 130 bits.
      // First 25 symbols (125 bits) are all `11111` = `z`. The last symbol's
      // 5 bits are `11100` = 28 = `w` in the alphabet
      // `0123456789abcdefghjkmnpqrstvwxyz`.
      expect(out.slice(0, 25)).toBe('z'.repeat(25));
      expect(out[25]).toBe('w');
    });

    it('throws when input is not exactly 16 bytes', () => {
      expect(() => encodeBytes(new Uint8Array(15))).toThrow(/16 bytes/);
      expect(() => encodeBytes(new Uint8Array(17))).toThrow(/16 bytes/);
    });
  });

  describe('decodeBytes', () => {
    it('round-trips zero bytes', () => {
      expect(decodeBytes(encodeBytes(KNOWN_ZERO))).toEqual(KNOWN_ZERO);
    });

    it('round-trips 0xff bytes', () => {
      expect(decodeBytes(encodeBytes(KNOWN_FF))).toEqual(KNOWN_FF);
    });

    it('round-trips a pseudo-random UUIDv7-shaped payload', () => {
      // 01977c4a-0066-7777-aaaa-bbbbbbbbbbbb hex bytes.
      const uuidHex = '01977c4a00667777aaaabbbbbbbbbbbb';
      const bytes = new Uint8Array(uuidHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)));
      const encoded = encodeBytes(bytes);
      expect(encoded).toHaveLength(26);
      expect(decodeBytes(encoded)).toEqual(bytes);
    });

    it('accepts uppercase Crockford input', () => {
      const encoded = encodeBytes(KNOWN_FF);
      const upperOnly = encoded.toUpperCase();
      expect(decodeBytes(upperOnly)).toEqual(KNOWN_FF);
    });

    it('accepts the I/L → 1, O → 0 disambiguation mappings', () => {
      // Produce a canonical lowercase encoded string, then deliberately
      // substitute disambiguation aliases for digits 0 and 1.
      const encoded = encodeBytes(KNOWN_ZERO); // all zeros → "0000…"
      // Replace some zeros with O / o and decode — should still round-trip.
      const massaged = `O${encoded.slice(1, 13)}o${encoded.slice(14)}`;
      expect(decodeBytes(massaged)).toEqual(KNOWN_ZERO);

      // Substitute the digit '1' with I / l / L on an encoding that has 1s.
      // Construct bytes that encode to a string containing '1': 1-bit set.
      const bitOneBytes = new Uint8Array(16);
      bitOneBytes[0] = 0b00001000; // top symbol becomes '1' (binary 00001).
      const e2 = encodeBytes(bitOneBytes);
      expect(e2.startsWith('1')).toBe(true);
      const decoded = decodeBytes(`I${e2.slice(1)}`);
      expect(decoded[0]).toBe(0b00001000);
    });

    it('rejects U as an invalid character', () => {
      // u is reserved; should fail.
      const encoded = encodeBytes(KNOWN_ZERO);
      const bad = `u${encoded.slice(1)}`;
      expect(() => decodeBytes(bad)).toThrow(/invalid character/);
    });

    it('rejects wrong-length inputs', () => {
      expect(() => decodeBytes('0'.repeat(25))).toThrow(/26-char input/);
      expect(() => decodeBytes('0'.repeat(27))).toThrow(/26-char input/);
      expect(() => decodeBytes('')).toThrow(/26-char input/);
    });

    it('rejects clearly non-base32 characters', () => {
      const encoded = encodeBytes(KNOWN_ZERO);
      const bad = `!${encoded.slice(1)}`;
      expect(() => decodeBytes(bad)).toThrow(/invalid character/);
    });

    it('rejects payloads whose pad bits are non-zero', () => {
      // The last symbol of a valid encoding has its bottom 2 bits = 0. Forge
      // an encoding by setting bottom bits non-zero — should reject.
      const encoded = encodeBytes(KNOWN_ZERO);
      // last symbol '0' (index 0) — replace with 'z' (index 31) which has bits 11111
      const tampered = `${encoded.slice(0, 25)}z`;
      expect(() => decodeBytes(tampered)).toThrow(/non-zero pad bits/);
    });
  });
});
