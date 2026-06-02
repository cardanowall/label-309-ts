import { describe, expect, it } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '../cbor/canonical';

import { parseCoseKeyEd25519 } from './cose-key';

function buildKey(entries: Array<[number, unknown]>): Uint8Array {
  return encodeCanonicalCbor(new Map(entries) as unknown as CanonicalCborValue);
}

const PUB = new Uint8Array(32).fill(0xab);

describe('parseCoseKeyEd25519', () => {
  it('canonical CIP-30 OKP/Ed25519 COSE_Key returns the 32-byte x', () => {
    const blob = buildKey([
      [1, 1], // kty: OKP
      [3, -8], // alg: EdDSA
      [-1, 6], // crv: Ed25519
      [-2, PUB], // x
    ]);
    const out = parseCoseKeyEd25519(blob);
    expect(out).toEqual(PUB);
  });

  it('alg is OPTIONAL — accepted when omitted', () => {
    const blob = buildKey([
      [1, 1],
      [-1, 6],
      [-2, PUB],
    ]);
    const out = parseCoseKeyEd25519(blob);
    expect(out).toEqual(PUB);
  });

  it('rejects wrong kty (EC2 instead of OKP)', () => {
    const blob = buildKey([
      [1, 2], // kty: EC2 — not OKP
      [3, -8],
      [-1, 6],
      [-2, PUB],
    ]);
    expect(parseCoseKeyEd25519(blob)).toBeNull();
  });

  it('rejects wrong crv (X25519 = 4 instead of Ed25519 = 6)', () => {
    const blob = buildKey([
      [1, 1],
      [3, -8],
      [-1, 4],
      [-2, PUB],
    ]);
    expect(parseCoseKeyEd25519(blob)).toBeNull();
  });

  it('rejects wrong alg when present (-7 ES256 instead of -8 EdDSA)', () => {
    const blob = buildKey([
      [1, 1],
      [3, -7],
      [-1, 6],
      [-2, PUB],
    ]);
    expect(parseCoseKeyEd25519(blob)).toBeNull();
  });

  it('rejects missing x', () => {
    const blob = buildKey([
      [1, 1],
      [3, -8],
      [-1, 6],
    ]);
    expect(parseCoseKeyEd25519(blob)).toBeNull();
  });

  it('rejects wrong x length (31 bytes)', () => {
    const blob = buildKey([
      [1, 1],
      [3, -8],
      [-1, 6],
      [-2, new Uint8Array(31).fill(0xab)],
    ]);
    expect(parseCoseKeyEd25519(blob)).toBeNull();
  });

  it('rejects garbage CBOR', () => {
    expect(parseCoseKeyEd25519(new Uint8Array([0xff, 0xff, 0xff]))).toBeNull();
  });

  it('rejects non-map (e.g., array)', () => {
    const blob = encodeCanonicalCbor([1, 2, 3] as unknown as CanonicalCborValue);
    expect(parseCoseKeyEd25519(blob)).toBeNull();
  });
});
