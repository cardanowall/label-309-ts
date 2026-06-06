// Label 309 v1 validator — negative KAT corpus (one in-test record per
// structural code the validator emits).
//
// Each case constructs a minimal CBOR / record payload in-test and asserts
// the exact code emitted. A future revision will replay byte-pinned `.cbor`
// fixture files under `tests/fixtures/negative/` instead of building the
// payloads in-test.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { describe, expect, it } from 'vitest';

import { encodePoeRecord } from './encoder';
import { STRUCTURAL_ERROR_CODES, type StructuralErrorCode } from './error-codes';
import { validatePoeRecord } from './validator';

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hash32(byte = 0xab): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

function buildCoseSign1(
  alg: number,
  options: { kid?: Uint8Array; payload?: Uint8Array | null } = {},
): Uint8Array<ArrayBuffer> {
  const protectedMap = new Map<number, unknown>([[1, alg]]);
  if (options.kid !== undefined) protectedMap.set(4, options.kid);
  const protectedBytes = encodeCanonicalCbor(protectedMap as unknown as CanonicalCborValue);
  const unprotected = new Map<number, unknown>();
  const signature = new Uint8Array(64).fill(0x99);
  const encoded = encodeCanonicalCbor([
    protectedBytes,
    unprotected as unknown as CanonicalCborValue,
    options.payload ?? null,
    signature,
  ] as readonly CanonicalCborValue[]);
  // `encodeCanonicalCbor` returns `Uint8Array` (wide / unspecified generic);
  // copy to a fresh ArrayBuffer-backed view so callers expecting the narrow
  // `Uint8Array<ArrayBuffer>` (the Zod-inferred type) type-check cleanly.
  const out = new Uint8Array(encoded.length);
  out.set(encoded);
  return out;
}

// Use a fresh ArrayBuffer per chunk so the result is `Uint8Array<ArrayBuffer>`
// (the narrow generic the Zod schema's `z.instanceof(Uint8Array)` infers);
// `.subarray()` would yield `Uint8Array<ArrayBufferLike>` and break the
// downstream `PoeRecord` literal type check.
function chunked(bytes: Uint8Array): Uint8Array<ArrayBuffer>[] {
  if (bytes.length === 0) return [new Uint8Array(0)];
  const out: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < bytes.length; i += 64) {
    const end = Math.min(i + 64, bytes.length);
    const chunk = new Uint8Array(end - i);
    chunk.set(bytes.subarray(i, end));
    out.push(chunk);
  }
  return out;
}

interface NegativeCase {
  readonly name: StructuralErrorCode;
  readonly bytes: () => Uint8Array;
}

const validItem = (): CanonicalCborValue =>
  ({ hashes: { 'sha2-256': hash32() } }) as CanonicalCborValue;

const sealedBase = (): Record<string, unknown> => ({
  scheme: 1,
  aead: 'xchacha20-poly1305',
  kem: 'x25519',
  nonce: new Uint8Array(24),
  slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
  slots_mac: new Uint8Array(32),
});

// 1120-byte X-Wing `enc`, chunked into the on-wire `kem_ct` shape
// (18 chunks: 17 x 64 + 1 x 32).
const MLKEM768X25519_ENC_LENGTH = 1120;
function chunk64(value: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < value.length; i += 64) {
    const end = Math.min(i + 64, value.length);
    const c = new Uint8Array(end - i);
    c.set(value.subarray(i, end));
    out.push(c);
  }
  return out;
}

// A well-formed hybrid sealed envelope (kem='mlkem768x25519'); callers mutate
// individual slots to exercise the cross-KEM shape negatives.
const sealedHybridBase = (): Record<string, unknown> => ({
  scheme: 1,
  aead: 'xchacha20-poly1305',
  kem: 'mlkem768x25519',
  nonce: new Uint8Array(24),
  slots: [{ kem_ct: chunk64(new Uint8Array(MLKEM768X25519_ENC_LENGTH)), wrap: new Uint8Array(48) }],
  slots_mac: new Uint8Array(32),
});

function recordWithEnc(enc: Record<string, unknown>): Uint8Array {
  return encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': hash32() },
        enc: enc as CanonicalCborValue,
      },
    ],
  } as CanonicalCborValue);
}

const CASES: ReadonlyArray<NegativeCase> = [
  // CBOR decode
  {
    name: 'MALFORMED_CBOR',
    bytes: () => hexToBytes('ffffffff'),
  },
  // Shape
  {
    name: 'SCHEMA_TYPE_MISMATCH',
    bytes: () =>
      encodeCanonicalCbor({ v: 1, items: 'not-an-array' } as unknown as CanonicalCborValue),
  },
  {
    name: 'SCHEMA_MISSING_REQUIRED',
    bytes: () => encodeCanonicalCbor({} as CanonicalCborValue),
  },
  {
    name: 'SCHEMA_UNKNOWN_FIELD',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [validItem()],
        supersedess: new Uint8Array(32),
      } as CanonicalCborValue),
  },
  {
    name: 'SCHEMA_INVALID_LITERAL',
    bytes: () => encodeCanonicalCbor({ v: 2, items: [validItem()] } as CanonicalCborValue),
  },
  {
    name: 'SCHEMA_EMPTY_RECORD',
    bytes: () => encodeCanonicalCbor({ v: 1, items: [], merkle: [] } as CanonicalCborValue),
  },
  // Hashes
  {
    name: 'HASH_DIGEST_LENGTH_MISMATCH',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [{ hashes: { 'sha2-256': new Uint8Array(31) } }],
      } as CanonicalCborValue),
  },
  {
    name: 'UNSUPPORTED_HASH_ALG',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [{ hashes: { md5: new Uint8Array(16) } }],
      } as CanonicalCborValue),
  },
  // Merkle
  {
    name: 'UNSUPPORTED_MERKLE_COMMIT_ALG',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        merkle: [{ alg: 'custom-merkle', root: hash32(), leaf_count: 4 }],
      } as CanonicalCborValue),
  },
  // URIs
  {
    name: 'INVALID_URI',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': hash32() },
            uris: [['https://example.org/x']],
          },
        ],
      } as CanonicalCborValue),
  },
  // Encryption envelope
  {
    name: 'UNAUTHENTICATED_CIPHER_FORBIDDEN',
    // Realistic OpenSSL/JCA spelling, not the contrived `aes-cbc` substring.
    bytes: () => recordWithEnc({ ...sealedBase(), aead: 'aes-256-cbc' }),
  },
  {
    name: 'UNSUPPORTED_AEAD_ALG',
    bytes: () => recordWithEnc({ ...sealedBase(), aead: 'twofish-gcm' }),
  },
  {
    name: 'NONCE_LENGTH_MISMATCH',
    bytes: () => recordWithEnc({ ...sealedBase(), nonce: new Uint8Array(12) }),
  },
  {
    name: 'UNSUPPORTED_ENVELOPE_SCHEME',
    bytes: () => recordWithEnc({ ...sealedBase(), scheme: 2 }),
  },
  {
    name: 'ENC_SLOTS_EMPTY',
    bytes: () => recordWithEnc({ ...sealedBase(), slots: [] }),
  },
  {
    name: 'ENC_SLOT_INVALID_SHAPE',
    bytes: () =>
      recordWithEnc({
        ...sealedBase(),
        slots: [{ epk: new Uint8Array(32) }],
      }),
  },
  {
    name: 'UNSUPPORTED_KEM_ALG',
    bytes: () => recordWithEnc({ ...sealedBase(), kem: 'x448' }),
  },
  {
    name: 'ENC_KEM_REQUIRED',
    bytes: () => {
      const enc = sealedBase();
      delete enc['kem'];
      return recordWithEnc(enc);
    },
  },
  {
    name: 'KEM_EPK_LENGTH_MISMATCH',
    bytes: () =>
      recordWithEnc({
        ...sealedBase(),
        slots: [{ epk: new Uint8Array(31), wrap: new Uint8Array(48) }],
      }),
  },
  {
    name: 'KEM_CT_LENGTH_MISMATCH',
    // A hybrid slot whose kem_ct reassembles to 1119 bytes (one byte short of
    // the 1120-byte X-Wing enc).
    bytes: () =>
      recordWithEnc({
        ...sealedHybridBase(),
        slots: [
          {
            kem_ct: chunk64(new Uint8Array(MLKEM768X25519_ENC_LENGTH - 1)),
            wrap: new Uint8Array(48),
          },
        ],
      }),
  },
  {
    name: 'WRAP_LENGTH_MISMATCH',
    bytes: () =>
      recordWithEnc({
        ...sealedBase(),
        slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(40) }],
      }),
  },
  {
    name: 'ENC_SLOTS_MAC_INVALID_LENGTH',
    bytes: () => recordWithEnc({ ...sealedBase(), slots_mac: new Uint8Array(31) }),
  },
  {
    name: 'ENC_SLOTS_MAC_REQUIRED',
    bytes: () => {
      const enc = sealedBase();
      delete enc['slots_mac'];
      return recordWithEnc(enc);
    },
  },
  {
    name: 'ENC_SLOTS_REQUIRED',
    bytes: () => {
      const enc = sealedBase();
      delete enc['slots'];
      delete enc['kem'];
      return recordWithEnc(enc);
    },
  },
  {
    name: 'ENC_EXCLUSIVITY_VIOLATION',
    bytes: () =>
      recordWithEnc({
        ...sealedBase(),
        passphrase: {
          alg: 'argon2id',
          salt: new Uint8Array(16),
          params: { m: 65536, t: 3, p: 1 },
        },
      }),
  },
  {
    name: 'ENC_NO_KEY_PATH',
    bytes: () =>
      recordWithEnc({
        scheme: 1,
        aead: 'xchacha20-poly1305',
        nonce: new Uint8Array(24),
      }),
  },
  {
    name: 'ENC_REQUIRES_CONTENT_HASH',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [
          {
            hashes: {},
            enc: sealedBase() as CanonicalCborValue,
          },
        ],
      } as CanonicalCborValue),
  },
  {
    name: 'ENC_PASSPHRASE_ALG_UNSUPPORTED',
    bytes: () =>
      recordWithEnc({
        scheme: 1,
        aead: 'xchacha20-poly1305',
        nonce: new Uint8Array(24),
        passphrase: {
          alg: 'pbkdf2-sha-256',
          salt: new Uint8Array(16),
          params: { i: 600000 },
        },
      }),
  },
  {
    name: 'ENC_PASSPHRASE_SALT_TOO_SHORT',
    bytes: () =>
      recordWithEnc({
        scheme: 1,
        aead: 'xchacha20-poly1305',
        nonce: new Uint8Array(24),
        passphrase: {
          alg: 'argon2id',
          salt: new Uint8Array(15),
          params: { m: 65536, t: 3, p: 1 },
        },
      }),
  },
  {
    name: 'ENC_PASSPHRASE_SALT_TOO_LONG',
    bytes: () =>
      recordWithEnc({
        scheme: 1,
        aead: 'xchacha20-poly1305',
        nonce: new Uint8Array(24),
        passphrase: {
          alg: 'argon2id',
          salt: new Uint8Array(65),
          params: { m: 65536, t: 3, p: 1 },
        },
      }),
  },
  {
    name: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
    bytes: () =>
      recordWithEnc({
        scheme: 1,
        aead: 'xchacha20-poly1305',
        nonce: new Uint8Array(24),
        passphrase: {
          alg: 'argon2id',
          salt: new Uint8Array(16),
          params: { m: 1024, t: 3, p: 1 },
        },
      }),
  },
  // Signatures
  {
    name: 'MALFORMED_SIG_COSE_SIGN1',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [validItem()],
        sigs: [{ cose_sign1: [new Uint8Array([0xff, 0xff, 0xff])] }],
      } as CanonicalCborValue),
  },
  // `SIGNATURE_UNSUPPORTED` is info-severity; in the negative-corpus sense the
  // record still passes structural validation, so we exercise it in
  // `validator.test.ts` instead.
  {
    name: 'SIG_ENTRY_INVALID_SHAPE',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [validItem()],
        sigs: [
          {
            cose_sign1: [new Uint8Array(64)],
            extra_field: new Uint8Array(8),
          },
        ],
      } as CanonicalCborValue),
  },
  {
    name: 'SIG_ENTRY_KID_COSE_KEY_CONFLICT',
    bytes: () => {
      const cose = buildCoseSign1(-8, { kid: hash32(0x42) });
      const coseKey = encodeCanonicalCbor(
        new Map<number, unknown>([
          [1, 1],
          [-1, 6],
          [-2, hash32(0x55)],
        ]) as unknown as CanonicalCborValue,
      );
      return encodePoeRecord({
        v: 1,
        items: [{ hashes: { 'sha2-256': hash32() } }],
        sigs: [
          {
            cose_sign1: chunked(cose),
            cose_key: chunked(coseKey),
          },
        ],
      });
    },
  },
  {
    name: 'SIG_PRIVATE_KEY_LEAKED',
    bytes: () => {
      const cose = buildCoseSign1(-8);
      const coseKey = encodeCanonicalCbor(
        new Map<number, unknown>([
          [1, 1],
          [-1, 6],
          [-2, hash32(0x55)],
          [-4, hash32(0xaa)], // private d
        ]) as unknown as CanonicalCborValue,
      );
      return encodePoeRecord({
        v: 1,
        items: [{ hashes: { 'sha2-256': hash32() } }],
        sigs: [
          {
            cose_sign1: chunked(cose),
            cose_key: chunked(coseKey),
          },
        ],
      });
    },
  },
  // Chunking
  {
    name: 'CHUNK_TOO_LARGE',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [validItem()],
        sigs: [{ cose_sign1: [new Uint8Array(65)] }],
      } as CanonicalCborValue),
  },
  // Supersedence
  {
    name: 'SUPERSEDES_TX_INVALID_LENGTH',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [validItem()],
        supersedes: new Uint8Array(31),
      } as CanonicalCborValue),
  },
  // Crit
  {
    name: 'CRIT_SHAPE_INVALID',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [validItem()],
        crit: ['v'], // base key in crit[]
      } as CanonicalCborValue),
  },
  {
    name: 'EXTENSION_UNSUPPORTED_CRITICAL',
    bytes: () =>
      encodeCanonicalCbor({
        v: 1,
        items: [validItem()],
        'x-foo': 'bar',
        crit: ['x-foo'],
      } as CanonicalCborValue),
  },
];

const KNOWN_CODES: ReadonlySet<string> = new Set(STRUCTURAL_ERROR_CODES);

describe('validator — negative KAT corpus (in-test records, one per structural code)', () => {
  for (const { name, bytes } of CASES) {
    it(`emits ${name}`, () => {
      const result = validatePoeRecord(bytes());
      expect(result.ok).toBe(false);
      if (result.ok) return;
      const emittedCodes = new Set(result.issues.map((i) => i.code));
      expect(emittedCodes.has(name)).toBe(true);
      // Every emitted code MUST be a STRUCTURAL_ERROR_CODES member.
      for (const code of emittedCodes) {
        expect(KNOWN_CODES.has(code)).toBe(true);
      }
    });
  }
});

// Hybrid (mlkem768x25519) KEM-aware slot-shape negatives. These pin the
// cross-KEM-contamination gate that the permissive (`.strict()`-free) schema
// can no longer catch: the validator's KEM-driven domain pass must reject a
// slot that mixes the two KEMs' ciphertext fields, and must length-check the
// reassembled kem_ct. Each asserts the SOLE emitted error code so a future
// regression that silently downgrades the code (or drops the check) fails.
describe('validator — hybrid mlkem768x25519 slot-shape negatives', () => {
  function expectSoleCode(rec: Uint8Array, code: StructuralErrorCode): void {
    const result = validatePoeRecord(rec);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const codes = result.issues.map((i) => i.code);
    expect(codes).toContain(code);
    // No other error code should fire for these single-defect records.
    expect(new Set(codes)).toEqual(new Set([code]));
  }

  it('hybrid slot carrying a stray epk -> ENC_SLOT_INVALID_SHAPE', () => {
    expectSoleCode(
      recordWithEnc({
        ...sealedHybridBase(),
        slots: [
          {
            kem_ct: chunk64(new Uint8Array(MLKEM768X25519_ENC_LENGTH)),
            epk: new Uint8Array(32), // forbidden on the hybrid path
            wrap: new Uint8Array(48),
          },
        ],
      }),
      'ENC_SLOT_INVALID_SHAPE',
    );
  });

  it('classical x25519 slot carrying a stray kem_ct -> ENC_SLOT_INVALID_SHAPE', () => {
    expectSoleCode(
      recordWithEnc({
        ...sealedBase(),
        slots: [
          {
            epk: new Uint8Array(32),
            kem_ct: chunk64(new Uint8Array(MLKEM768X25519_ENC_LENGTH)), // forbidden on x25519
            wrap: new Uint8Array(48),
          },
        ],
      }),
      'ENC_SLOT_INVALID_SHAPE',
    );
  });

  it('hybrid slot whose kem_ct reassembles to != 1120 -> KEM_CT_LENGTH_MISMATCH', () => {
    expectSoleCode(
      recordWithEnc({
        ...sealedHybridBase(),
        slots: [
          {
            // 1184 bytes (one extra 64-byte chunk) — reassembles to != 1120.
            kem_ct: chunk64(new Uint8Array(MLKEM768X25519_ENC_LENGTH + 64)),
            wrap: new Uint8Array(48),
          },
        ],
      }),
      'KEM_CT_LENGTH_MISMATCH',
    );
  });
});

// Resource bounds — the slot-count cap and the decoded-envelope byte backstop.
// These are not in the frozen shared corpus because their inputs are large
// (over-bound slot arrays built programmatically); the corpus carries only the
// cheap duplicate cases. Constants mirror the sealed-PoE unwrap layer
// (MAX_SLOTS = 1024, decoded-envelope bound 65536 bytes).
describe('validator — enc resource bounds (slot-count cap + decoded-envelope size)', () => {
  const MAX_SLOTS = 1024;
  const MAX_DECODED_ENVELOPE_BYTES = 65536;
  const NONCE_LENGTH = 24;
  const SLOTS_MAC_LENGTH = 32;

  function distinctEpkSlots(n: number): Array<{ epk: Uint8Array; wrap: Uint8Array }> {
    const slots: Array<{ epk: Uint8Array; wrap: Uint8Array }> = [];
    for (let i = 0; i < n; i++) {
      const epk = new Uint8Array(32);
      // 32-byte big-endian counter keeps every epk distinct, so the slot-count
      // cap — not the duplicate check — is what trips.
      epk[31] = i & 0xff;
      epk[30] = (i >> 8) & 0xff;
      slots.push({ epk, wrap: new Uint8Array(48) });
    }
    return slots;
  }

  function codesOf(rec: Uint8Array): Set<string> {
    const result = validatePoeRecord(rec);
    if (result.ok) return new Set();
    return new Set(result.issues.map((i) => i.code));
  }

  it('MAX_SLOTS + 1 slots -> sole code ENC_SLOTS_TOO_MANY', () => {
    // MAX_SLOTS + 1 trips the slot-count cap, which short-circuits the byte
    // backstop, so ENC_SLOTS_TOO_MANY is the sole emitted code even though the
    // x25519 array would also exceed the byte bound at that count.
    const rec = recordWithEnc({ ...sealedBase(), slots: distinctEpkSlots(MAX_SLOTS + 1) });
    expect(codesOf(rec)).toEqual(new Set(['ENC_SLOTS_TOO_MANY']));
  });

  it('x25519 array at the byte backstop validates; one slot over -> ENC_ENVELOPE_TOO_LARGE', () => {
    // x25519 per-slot bytes = 32 + 48 = 80. The byte backstop is the tighter
    // guard at this width (it trips below MAX_SLOTS), so the largest accepted
    // count is the floor below the bound; one more trips ENC_ENVELOPE_TOO_LARGE.
    const perSlot = 32 + 48;
    const justUnder = Math.floor(
      (MAX_DECODED_ENVELOPE_BYTES - NONCE_LENGTH - SLOTS_MAC_LENGTH) / perSlot,
    );
    expect(justUnder).toBeLessThan(MAX_SLOTS);
    const ok = recordWithEnc({ ...sealedBase(), slots: distinctEpkSlots(justUnder) });
    expect(validatePoeRecord(ok).ok).toBe(true);
    const over = recordWithEnc({ ...sealedBase(), slots: distinctEpkSlots(justUnder + 1) });
    expect(codesOf(over)).toEqual(new Set(['ENC_ENVELOPE_TOO_LARGE']));
  });

  it('decoded envelope above the byte backstop -> ENC_ENVELOPE_TOO_LARGE (hybrid, below MAX_SLOTS)', () => {
    // Hybrid per-slot bytes = 1120 + 48 = 1168. The smallest slot count whose
    // decoded envelope exceeds the bound is below MAX_SLOTS, so the byte
    // backstop (not the slot cap) is the active guard.
    const perSlot = MLKEM768X25519_ENC_LENGTH + 48;
    const over =
      Math.floor((MAX_DECODED_ENVELOPE_BYTES - NONCE_LENGTH - SLOTS_MAC_LENGTH) / perSlot) + 1;
    expect(over).toBeLessThanOrEqual(MAX_SLOTS);
    const slots = Array.from({ length: over }, (_, i) => {
      // Distinct kem_ct per slot so the duplicate check does not fire instead.
      const body = new Uint8Array(MLKEM768X25519_ENC_LENGTH);
      body[0] = i & 0xff;
      body[1] = (i >> 8) & 0xff;
      return { kem_ct: chunk64(body), wrap: new Uint8Array(48) };
    });
    const rec = recordWithEnc({ ...sealedHybridBase(), slots });
    expect(codesOf(rec)).toEqual(new Set(['ENC_ENVELOPE_TOO_LARGE']));
  });

  it('decoded envelope exactly at the byte backstop validates (hybrid just-below)', () => {
    const perSlot = MLKEM768X25519_ENC_LENGTH + 48;
    const justUnder = Math.floor(
      (MAX_DECODED_ENVELOPE_BYTES - NONCE_LENGTH - SLOTS_MAC_LENGTH) / perSlot,
    );
    const slots = Array.from({ length: justUnder }, (_, i) => {
      const body = new Uint8Array(MLKEM768X25519_ENC_LENGTH);
      body[0] = i & 0xff;
      body[1] = (i >> 8) & 0xff;
      return { kem_ct: chunk64(body), wrap: new Uint8Array(48) };
    });
    const rec = recordWithEnc({ ...sealedHybridBase(), slots });
    const result = validatePoeRecord(rec);
    expect(result.ok).toBe(true);
  });
});

// Shared cross-SDK negative KAT corpus. Each vector pins the EXACT set of
// structural codes `validatePoeRecord` emits for a byte-frozen CBOR record, so
// the TS / Python / Rust validators stay code-for-code identical. An empty
// `expected_error_codes` array means the record is VALID.
interface ValidatorNegativeVector {
  readonly name: string;
  readonly cbor_hex: string;
  readonly expected_error_codes: ReadonlyArray<string>;
}
interface ValidatorNegativeCorpus {
  readonly version: number;
  readonly primitive: string;
  readonly vectors: ReadonlyArray<ValidatorNegativeVector>;
}

const sharedFixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../crypto-core/tests/fixtures',
);

const validatorNegativeCorpus = JSON.parse(
  fs.readFileSync(path.join(sharedFixturesDir, 'poe-record/validator-negative.json'), 'utf8'),
) as ValidatorNegativeCorpus;

describe('validator — shared cross-SDK negative KAT corpus (fixture-file replay)', () => {
  for (const vector of validatorNegativeCorpus.vectors) {
    it(`${vector.name} → ${vector.expected_error_codes.join('+') || '(valid)'}`, () => {
      const result = validatePoeRecord(hexToBytes(vector.cbor_hex));
      const expected = new Set(vector.expected_error_codes);
      if (expected.size === 0) {
        expect(result.ok).toBe(true);
        return;
      }
      expect(result.ok).toBe(false);
      if (result.ok) return;
      const emitted = new Set(result.issues.map((i) => i.code));
      expect(emitted).toEqual(expected);
    });
  }
});

describe.todo('validator — negative KAT corpus (additional fixture files)');
