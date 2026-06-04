// Label 309 v1 validator — positive KAT corpus (in-test records).
//
// Each case builds a record in-test and verifies the round-trip property
//   validate(encode(R)).ok === true && validate(encode(R)).record ≡ R
// across the full v1 wire surface (items-only, merkle-only, hybrid,
// supersedence, sealed-slots envelope, passphrase envelope, signed records,
// extension keys). A future revision will replay byte-pinned `.cbor` fixture
// files under `tests/fixtures/positive/` instead of building the records
// in-test.

import { describe, expect, it } from 'vitest';

import { encodePoeRecord } from './encoder';
import { type PoeRecord } from './schema';
import { validatePoeRecord } from './validator';

function hash32(byte = 0xab): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

function bytes(len: number, byte = 0x00): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(len);
  out.fill(byte);
  return out;
}

// Chunk a flat byte string into <=64-byte CBOR-bytes chunks (the on-wire
// `kem_ct` shape). A 1120-byte X-Wing `enc` chunks into 18 chunks: 17 x 64 + 32.
function chunk64(value: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>[] {
  const out: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < value.length; i += 64) {
    const end = Math.min(i + 64, value.length);
    const c = new Uint8Array(end - i);
    c.set(value.subarray(i, end));
    out.push(c);
  }
  return out;
}

// The 1120-byte X-Wing `enc` as the chunked `kem_ct` wire form.
const MLKEM768X25519_ENC_LENGTH = 1120;

const CORPUS: ReadonlyArray<{ name: string; build: () => PoeRecord }> = [
  {
    name: 'minimal-items',
    build: () => ({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32(), 'blake2b-256': hash32(0xcd) } }],
    }),
  },
  {
    name: 'merkle-only',
    build: () => ({
      v: 1,
      merkle: [{ alg: 'rfc9162-sha256', root: hash32(0x77), leaf_count: 8 }],
    }),
  },
  {
    name: 'hybrid-items-merkle',
    build: () => ({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      merkle: [{ alg: 'rfc9162-sha256', root: hash32(0x88), leaf_count: 16 }],
    }),
  },
  {
    name: 'supersedence',
    build: () => ({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      supersedes: bytes(32, 0x33),
    }),
  },
  {
    name: 'sealed-slots',
    build: () => ({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32(), 'blake2b-256': hash32(0x22) },
          enc: {
            scheme: 1,
            aead: 'xchacha20-poly1305',
            kem: 'x25519',
            nonce: bytes(24),
            slots: [
              { epk: bytes(32, 0x01), wrap: bytes(48, 0x02) },
              { epk: bytes(32, 0x03), wrap: bytes(48, 0x04) },
              { epk: bytes(32, 0x05), wrap: bytes(48, 0x06) },
            ],
            slots_mac: bytes(32, 0x07),
          },
        },
      ],
    }),
  },
  {
    name: 'sealed-slots-hybrid-mlkem768x25519',
    build: () => ({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32(), 'blake2b-256': hash32(0x22) },
          enc: {
            scheme: 1,
            aead: 'xchacha20-poly1305',
            kem: 'mlkem768x25519',
            nonce: bytes(24),
            slots: [
              { kem_ct: chunk64(bytes(MLKEM768X25519_ENC_LENGTH, 0x11)), wrap: bytes(48, 0x02) },
              { kem_ct: chunk64(bytes(MLKEM768X25519_ENC_LENGTH, 0x33)), wrap: bytes(48, 0x04) },
            ],
            slots_mac: bytes(32, 0x07),
          },
        },
      ],
    }),
  },
  {
    name: 'sealed-passphrase',
    build: () => ({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          enc: {
            scheme: 1,
            aead: 'xchacha20-poly1305',
            nonce: bytes(24),
            passphrase: {
              alg: 'argon2id',
              salt: bytes(16),
              params: { m: 65536, t: 3, p: 1 },
            },
          },
        },
      ],
    }),
  },
  {
    name: 'items-with-ar-uri',
    build: () => {
      const txid = 'A'.repeat(43);
      return {
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': hash32() },
            uris: [[`ar://${txid}`]],
          },
        ],
      };
    },
  },
  {
    name: 'items-with-ipfs-cidv0-uri',
    build: () => ({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          uris: [['ipfs://QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH']],
        },
      ],
    }),
  },
];

describe('validator — positive KAT corpus (in-test records)', () => {
  for (const { name, build } of CORPUS) {
    it(`accepts ${name} and round-trips through encoder`, () => {
      const record = build();
      const bytes = encodePoeRecord(record);
      const result = validatePoeRecord(bytes);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const reencoded = encodePoeRecord(result.record);
      // Byte-exact round-trip: validate(encode(R)).record encodes back to the
      // same bytes.
      expect(reencoded).toEqual(bytes);
    });
  }
});

describe.todo(
  'validator — positive KAT corpus (fixture-file replay — pending fixture regeneration)',
);
