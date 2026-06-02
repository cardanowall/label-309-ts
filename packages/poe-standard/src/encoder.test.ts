// Encoder round-trip tests — canonical CBOR output is deterministic, the
// decoded value preserves every field the validator expects to see, and
// `validate(encode(R)).record` round-trips back to `R`.

import { decodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { compareCt } from '@cardanowall/crypto-core/util';
import { describe, expect, it } from 'vitest';

import { encodePoeRecord, encodeRecordBodyForSigning } from './encoder';
import { PoeRecordSchema, type PoeRecord } from './schema';
import { validatePoeRecord } from './validator';

function hash32(byte = 0xab): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

const minimalRecord = (): PoeRecord => ({
  v: 1,
  items: [{ hashes: { 'sha2-256': hash32() } }],
});

describe('encodePoeRecord — basic behaviour', () => {
  it('returns canonical CBOR bytes that decode back to the same record shape', () => {
    const record = minimalRecord();
    const encoded = encodePoeRecord(record);
    expect(encoded).toBeInstanceOf(Uint8Array);
    const decoded = decodeCanonicalCbor(encoded);
    const asMap =
      decoded instanceof Map
        ? decoded
        : new Map(Object.entries(decoded as Record<string, unknown>));
    expect(asMap.get('v')).toBe(1);
    expect(Array.isArray(asMap.get('items'))).toBe(true);
  });

  it('is deterministic: encoding the same record twice yields byte-identical output', () => {
    const a = encodePoeRecord(minimalRecord());
    const b = encodePoeRecord(minimalRecord());
    expect(compareCt(a, b)).toBe(true);
  });

  it('sorts top-level map keys canonically regardless of input order', () => {
    const reversed: unknown = {
      sigs: [{ cose_sign1: [new Uint8Array(64)] }],
      items: [{ hashes: { 'sha2-256': hash32() } }],
      v: 1,
    };
    const canonical: unknown = {
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      sigs: [{ cose_sign1: [new Uint8Array(64)] }],
    };
    const a = encodePoeRecord(PoeRecordSchema.parse(reversed));
    const b = encodePoeRecord(PoeRecordSchema.parse(canonical));
    expect(compareCt(a, b)).toBe(true);
  });

  it('emits supersedes as a bare 32-byte bstr', () => {
    const tx = new Uint8Array(32).fill(0x42);
    const record: PoeRecord = { ...minimalRecord(), supersedes: tx };
    const encoded = encodePoeRecord(record);
    const decoded = decodeCanonicalCbor(encoded);
    const map =
      decoded instanceof Map
        ? decoded
        : new Map(Object.entries(decoded as Record<string, unknown>));
    const sup = map.get('supersedes') as Uint8Array;
    expect(sup).toBeInstanceOf(Uint8Array);
    expect(sup.length).toBe(32);
    expect(compareCt(sup, tx)).toBe(true);
  });

  it('emits hashes as a text-keyed CBOR map (not an array)', () => {
    const record: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32(0x11), 'blake2b-256': hash32(0x22) } }],
    };
    const encoded = encodePoeRecord(record);
    const decoded = decodeCanonicalCbor(encoded);
    const map =
      decoded instanceof Map
        ? decoded
        : new Map(Object.entries(decoded as Record<string, unknown>));
    const items = map.get('items') as Array<Record<string, unknown> | Map<unknown, unknown>>;
    const item0 = items[0]!;
    const hashes =
      item0 instanceof Map ? item0.get('hashes') : (item0 as Record<string, unknown>)['hashes'];
    // cbor2 surfaces a text-keyed map as a plain object. Either way, the
    // shape MUST NOT be an array.
    expect(Array.isArray(hashes)).toBe(false);
  });

  it('emits a closed sigs[i] map with the canonical cose_key-before-cose_sign1 key order', () => {
    const record: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      sigs: [
        {
          cose_sign1: [new Uint8Array(60)],
          cose_key: [new Uint8Array(50)],
        },
      ],
    };
    const encoded = encodePoeRecord(record);
    const decoded = decodeCanonicalCbor(encoded);
    const map =
      decoded instanceof Map
        ? decoded
        : new Map(Object.entries(decoded as Record<string, unknown>));
    const sigs = map.get('sigs') as Array<Record<string, unknown> | Map<unknown, unknown>>;
    const sig0 = sigs[0]!;
    const keys =
      sig0 instanceof Map ? Array.from(sig0.keys()) : Object.keys(sig0 as Record<string, unknown>);
    // Canonical CBOR text-key sort places `cose_key` (length-8 → header 0x68)
    // before `cose_sign1` (length-10 → header 0x6a).
    expect(keys[0]).toBe('cose_key');
    expect(keys[1]).toBe('cose_sign1');
  });
});

describe('encodePoeRecord — round-trip with validator', () => {
  it.each<[string, () => PoeRecord]>([
    ['minimal items', () => minimalRecord()],
    [
      'merkle-only',
      () => ({
        v: 1,
        merkle: [{ alg: 'rfc9162-sha256', root: hash32(), leaf_count: 4 }],
      }),
    ],
    [
      'items + supersedes',
      () => ({
        v: 1,
        items: [{ hashes: { 'sha2-256': hash32() } }],
        supersedes: new Uint8Array(32).fill(0x33),
      }),
    ],
    [
      'sealed slots envelope',
      () => ({
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': hash32(), 'blake2b-256': hash32(0x22) },
            enc: {
              scheme: 1,
              aead: 'xchacha20-poly1305',
              kem: 'x25519',
              nonce: new Uint8Array(24),
              slots: [{ epk: new Uint8Array(32).fill(0x05), wrap: new Uint8Array(48).fill(0x06) }],
              slots_mac: new Uint8Array(32).fill(0x07),
            },
          },
        ],
      }),
    ],
    [
      'passphrase envelope',
      () => ({
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': hash32() },
            enc: {
              scheme: 1,
              aead: 'xchacha20-poly1305',
              nonce: new Uint8Array(24),
              passphrase: {
                alg: 'argon2id',
                salt: new Uint8Array(16),
                params: { m: 65536, t: 3, p: 1 },
              },
            },
          },
        ],
      }),
    ],
  ])('validator(encoder(%s)).ok === true', (_, build) => {
    const record = build();
    const bytes = encodePoeRecord(record);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(true);
  });

  it('round-tripped record bytes are byte-identical to a re-encode of the parsed record', () => {
    const record = minimalRecord();
    const bytes = encodePoeRecord(record);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const reencoded = encodePoeRecord(result.record);
    expect(reencoded).toEqual(bytes);
  });
});

describe('encodeRecordBodyForSigning', () => {
  it('strips the sigs field before encoding', () => {
    const sigBytes = new Uint8Array(64).fill(0x99);
    const withSigs: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      sigs: [{ cose_sign1: [sigBytes] }],
    };
    const bodyBytes = encodeRecordBodyForSigning(withSigs);

    const withoutSigs: PoeRecord = {
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
    };
    const expected = encodePoeRecord(withoutSigs);

    expect(bodyBytes).toEqual(expected);
  });

  it('preserves every other field (items, merkle, supersedes, crit, extension keys)', () => {
    const recordBody = {
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      merkle: [{ alg: 'rfc9162-sha256', root: hash32(0x77), leaf_count: 8 }],
      supersedes: new Uint8Array(32).fill(0x11),
    } as const satisfies CanonicalCborValue;
    const full: PoeRecord = {
      ...(recordBody as unknown as PoeRecord),
      sigs: [{ cose_sign1: [new Uint8Array(64)] }],
    };
    const bodyBytes = encodeRecordBodyForSigning(full);
    const directBody = encodePoeRecord(recordBody as unknown as PoeRecord);
    expect(bodyBytes).toEqual(directBody);
  });
});
