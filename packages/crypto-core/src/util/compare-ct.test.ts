import { describe, expect, it } from 'vitest';

import { compareCt } from './compare-ct';

describe('compareCt — constant-time byte-array equality', () => {
  it('returns true for equal-content equal-length arrays', () => {
    expect(compareCt(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('returns false for unequal-content equal-length arrays', () => {
    expect(compareCt(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it('returns false for length-mismatched arrays (short-circuits before timingSafeEqual)', () => {
    expect(compareCt(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
    expect(compareCt(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });

  it('returns true for two empty arrays', () => {
    expect(compareCt(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it('returns true for two identical 32-byte arrays', () => {
    const a = new Uint8Array(32).fill(0xab);
    const b = new Uint8Array(32).fill(0xab);
    expect(compareCt(a, b)).toBe(true);
  });

  it('returns false for two 32-byte arrays differing by one byte', () => {
    const a = new Uint8Array(32).fill(0xab);
    const b = new Uint8Array(32).fill(0xab);
    b[15] = 0xac;
    expect(compareCt(a, b)).toBe(false);
  });
});
