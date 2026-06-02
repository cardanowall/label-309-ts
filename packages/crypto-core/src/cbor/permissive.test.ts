import { describe, expect, it } from 'vitest';
import { encode } from 'cbor2';

import { decodeCanonicalCbor, encodeCanonicalCbor } from './canonical';
import { decodeCbor } from './permissive';

describe('decodeCbor (permissive)', () => {
  it('decodes a Cardano-tx-shaped 4-element array', () => {
    const txValue = [
      new Map([['placeholder', 'body']]),
      new Map([['placeholder', 'witness_set']]),
      true,
      null,
    ];
    const bytes = encode(txValue);
    const decoded = decodeCbor(bytes);
    expect(Array.isArray(decoded)).toBe(true);
    expect((decoded as unknown[]).length).toBe(4);
  });

  it('decodes the same byte string as decodeCanonicalCbor (deep equal)', () => {
    const value = { t: 'poe', v: 1 };
    const bytes = encodeCanonicalCbor(value);
    const permissive = decodeCbor(bytes);
    const canonical = decodeCanonicalCbor(bytes);
    expect(permissive).toEqual(canonical);
  });

  it('throws on truly malformed bytes', () => {
    const garbage = new Uint8Array([0xff, 0xff, 0xff]);
    expect(() => decodeCbor(garbage)).toThrow();
  });
});
