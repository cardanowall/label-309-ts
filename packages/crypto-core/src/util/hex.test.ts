import { describe, expect, it } from 'vitest';

import { hexToBytes } from './hex';

describe('hexToBytes', () => {
  it('decodes an empty string to a zero-length Uint8Array', () => {
    const out = hexToBytes('');
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(0);
  });

  it('decodes a 2-char hex pair to a single byte', () => {
    expect(Array.from(hexToBytes('00'))).toEqual([0x00]);
    expect(Array.from(hexToBytes('ff'))).toEqual([0xff]);
    expect(Array.from(hexToBytes('7f'))).toEqual([0x7f]);
  });

  it('decodes a 64-char (32-byte) all-zero hex to 32 zero bytes', () => {
    const out = hexToBytes('00'.repeat(32));
    expect(out.length).toBe(32);
    expect(out.every((b) => b === 0)).toBe(true);
  });

  it('decodes a 64-char (32-byte) all-ff hex to 32 0xff bytes', () => {
    const out = hexToBytes('ff'.repeat(32));
    expect(out.length).toBe(32);
    expect(out.every((b) => b === 0xff)).toBe(true);
  });

  it('decodes deadbeef × 8 (canonical 32-byte vector)', () => {
    const out = hexToBytes('deadbeef'.repeat(8));
    expect(out.length).toBe(32);
    for (let i = 0; i < 8; i++) {
      expect(out[i * 4 + 0]).toBe(0xde);
      expect(out[i * 4 + 1]).toBe(0xad);
      expect(out[i * 4 + 2]).toBe(0xbe);
      expect(out[i * 4 + 3]).toBe(0xef);
    }
  });

  it('returns a fresh Uint8Array on each call (reference identity)', () => {
    const a = hexToBytes('a1b2c3d4');
    const b = hexToBytes('a1b2c3d4');
    expect(a).not.toBe(b);
  });

  it('throws on odd-length input', () => {
    expect(() => hexToBytes('a')).toThrowError(/not even/);
    expect(() => hexToBytes('abc')).toThrowError(/not even/);
  });

  it('throws on uppercase hex (caller must lowercase first)', () => {
    expect(() => hexToBytes('AB')).toThrowError(/non-hex character/);
  });

  it('throws on a non-hex character', () => {
    expect(() => hexToBytes('zz')).toThrowError(/non-hex character/);
    expect(() => hexToBytes('a1g0')).toThrowError(/non-hex character/);
  });
});
