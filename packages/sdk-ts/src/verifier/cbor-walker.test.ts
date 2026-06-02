// Regression — Cardano caps every metadata bstr/tstr at 64 bytes, so any
// CIP-309 record larger than 64 bytes is emitted as a `bytes-chunk-array`
// at the label-309 value position. The verifier's
// `sliceLabel309Value` MUST reassemble the chunks before handing the bytes
// to `validatePoeRecord`; without that the canonical-CBOR decoder sees a
// CBOR array of byte strings instead of the inner record map and reports
// `SCHEMA_TYPE_MISMATCH` / `MALFORMED_CBOR`, surfacing as a `failed`
// verdict on the public viewer.

import { describe, expect, it } from 'vitest';

import { sliceLabel309Value } from './cbor-walker';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Minimal Conway-era tx CBOR shell with one metadata map entry at label 309.
// The tx body / witness_set / is_valid are stubs (CBOR null / 0xf6 / true)
// so the walker reaches auxiliary_data without choking. Auxiliary data is
// tag-259 wrapped post-Alonzo: 0xd9 0x0103 = tag(259).
function buildTxWithLabel309(label309ValueHex: string): Uint8Array {
  // tx = [body, witness_set, is_valid, auxiliary_data]
  // body, witness_set: stub bare empty maps (0xa0).
  // is_valid: true (0xf5).
  // auxiliary_data: tag(259) over a map {0 → {309 → <value>}}.
  // Top-level tx array: 0x84 (array of 4).
  // tag 259 wrapping: 0xd9 0x01 0x03 followed by the wrapped map.
  // Outer aux map { 0 (uint) → metadata map }: 0xa1 0x00 <metadata-map>.
  // Metadata map { 309 (uint16) → value }: 0xa1 0x19 0x01 0x35 <value>.
  const txPrefix = '84a0a0f5d90103a100a1190135';
  return hexToBytes(txPrefix + label309ValueHex);
}

describe('sliceLabel309Value — chunked metadata reassembly', () => {
  it('concatenates a bytes-chunk-array back into the canonical CBOR record body', () => {
    // The "canonical record body" is just a small CBOR map {1 → 1} — `a10101`
    // — split across two chunks of 1 + 2 bytes. Real records are larger but
    // the reassembly contract is the same.
    // Chunk array: 0x82 = array(2); each entry is a bstr: 0x41 0xa1, then 0x42 0x01 0x01.
    const tx = buildTxWithLabel309('82' + '41a1' + '42' + '0101');
    const out = sliceLabel309Value(tx);
    expect(out).not.toBeNull();
    // Reassembled value should be `a10101` (3 bytes), a CBOR map { 1: 1 }.
    expect(Array.from(out!)).toEqual([0xa1, 0x01, 0x01]);
  });

  it('strips the bstr head when label-309 value is a single byte string', () => {
    // Single chunk: 0x43 = bstr(3), then `a10101`.
    const tx = buildTxWithLabel309('43a10101');
    const out = sliceLabel309Value(tx);
    expect(out).not.toBeNull();
    expect(Array.from(out!)).toEqual([0xa1, 0x01, 0x01]);
  });

  it('passes through a bare CBOR map value (small-fixture shape)', () => {
    // Direct map: 0xa1 = map(1), 0x01 = uint(1), 0x01 = uint(1).
    const tx = buildTxWithLabel309('a10101');
    const out = sliceLabel309Value(tx);
    expect(out).not.toBeNull();
    expect(Array.from(out!)).toEqual([0xa1, 0x01, 0x01]);
  });

  it('rejects an array whose elements are not byte strings', () => {
    // Array with a uint element instead of bstr: 0x81 0x01.
    const tx = buildTxWithLabel309('8101');
    expect(() => sliceLabel309Value(tx)).toThrow(/MALFORMED_CBOR/);
  });
});
