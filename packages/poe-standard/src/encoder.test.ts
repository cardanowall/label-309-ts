// Encoder behaviour — canonical CBOR output is deterministic, optionals
// absent from the record are absent from the wire, the signing body removes
// exactly `sigs`, and `validatePoeRecord(encodePoeRecord(R))` round-trips.

import { decodeCanonicalCbor } from '@cardanowall/crypto-core/cbor';
import { describe, expect, it } from 'vitest';

import { encodePoeRecord, encodeRecordBodyForSigning } from './encoder';
import type { PoeRecord } from './schema';
import { validatePoeRecord } from './validator';

function bytes(len: number, fill = 0xab): Uint8Array<ArrayBuffer> {
  return new Uint8Array(len).fill(fill);
}

function bytesToHex(value: Uint8Array): string {
  let out = '';
  for (const b of value) out += b.toString(16).padStart(2, '0');
  return out;
}

const minimalRecord = (): PoeRecord => ({
  v: 1,
  items: [{ hashes: { 'sha2-256': bytes(32) } }],
});

describe('encodePoeRecord', () => {
  it('round-trips through the validator and preserves the decoded shape', () => {
    const encoded = encodePoeRecord(minimalRecord());
    const result = validatePoeRecord(encoded);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(Object.keys(result.record)).toEqual(['v', 'items']);
    expect(result.record.items?.[0]?.hashes['sha2-256']).toEqual(bytes(32));
  });

  it('is deterministic: two structurally equal records encode byte-identically', () => {
    // Insertion order differs; canonical map-key sorting must erase it.
    const a: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': bytes(32), 'blake2b-256': bytes(32, 0x22) } }],
    };
    const b: PoeRecord = {
      items: [{ hashes: { 'blake2b-256': bytes(32, 0x22), 'sha2-256': bytes(32) } }],
      v: 1,
    } as PoeRecord;
    expect(bytesToHex(encodePoeRecord(a))).toBe(bytesToHex(encodePoeRecord(b)));
  });

  it('omits optionals that are absent OR explicitly undefined (no CBOR undefined leaks)', () => {
    const explicit: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': bytes(32) }, uris: undefined, enc: undefined }],
      merkle: undefined,
      supersedes: undefined,
      sigs: undefined,
      crit: undefined,
    };
    expect(bytesToHex(encodePoeRecord(explicit))).toBe(
      bytesToHex(encodePoeRecord(minimalRecord())),
    );
    // The bytes decode under the canonical profile (which rejects the CBOR
    // `undefined` simple value outright).
    expect(() => decodeCanonicalCbor(encodePoeRecord(explicit))).not.toThrow();
  });

  it('encodes the de-chunked wire shapes: single-bstr kem_ct and plain tstr uris', () => {
    const record: PoeRecord = {
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': bytes(32) },
          uris: ['ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
          enc: {
            scheme: 1,
            aead: 'chacha20-poly1305-stream64k',
            kem: 'mlkem768x25519',
            nonce: bytes(24),
            slots: [{ kem_ct: bytes(1120), wrap: bytes(48) }],
            slots_mac: bytes(32),
          },
        },
      ],
    };
    const decoded = decodeCanonicalCbor(encodePoeRecord(record)) as {
      items: Array<{
        uris: unknown[];
        enc: { slots: Array<{ kem_ct: unknown; wrap: unknown }> };
      }>;
    };
    expect(typeof decoded.items[0]!.uris[0]).toBe('string');
    const slot = decoded.items[0]!.enc.slots[0]!;
    expect(slot.kem_ct).toBeInstanceOf(Uint8Array);
    expect((slot.kem_ct as Uint8Array).length).toBe(1120);
    expect((slot.wrap as Uint8Array).length).toBe(48);
    expect(validatePoeRecord(encodePoeRecord(record)).valid).toBe(true);
  });

  it('preserves extension keys, including nested map values', () => {
    const record: PoeRecord = {
      ...minimalRecord(),
      'x-note': 'kept',
      'x-meta': { a: 1, bb: 2 },
    } as PoeRecord;
    const decoded = decodeCanonicalCbor(encodePoeRecord(record)) as Record<string, unknown>;
    expect(decoded['x-note']).toBe('kept');
    expect(decoded['x-meta']).toEqual({ a: 1, bb: 2 });
  });
});

describe('encodeRecordBodyForSigning', () => {
  it('removes exactly `sigs` and nothing else', () => {
    const record: PoeRecord = {
      ...minimalRecord(),
      sigs: [{ cose_sign1: bytes(90, 0x01) }],
      'x-note': 'signed-too',
    } as PoeRecord;
    const body = decodeCanonicalCbor(encodeRecordBodyForSigning(record)) as Record<string, unknown>;
    expect('sigs' in body).toBe(false);
    expect(body['x-note']).toBe('signed-too');
    expect(body['v']).toBe(1);
  });

  it('equals the full encoding for a record with no sigs', () => {
    const record = minimalRecord();
    expect(bytesToHex(encodeRecordBodyForSigning(record))).toBe(
      bytesToHex(encodePoeRecord(record)),
    );
  });
});
