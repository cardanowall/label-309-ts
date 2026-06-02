// CIP-309 v1 validator unit tests — domain-pass coverage.
//
// Each test constructs a CBOR record in-test (no fixture-file dependency),
// runs `validatePoeRecord`, and asserts the exact structural code emitted.
// Round-trip tests live in `encoder.test.ts`; broader KAT coverage in
// `validator.positive.kat.test.ts` / `validator.negative.kat.test.ts`.

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { describe, expect, expectTypeOf, it } from 'vitest';

import { encodePoeRecord } from './encoder';
import { type PoeRecord } from './schema';
import { validatePoeRecord, type ValidateResult, type ValidationIssue } from './validator';

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

// Copy `bytes.subarray(...)` into a fresh `Uint8Array<ArrayBuffer>` — the
// narrow generic is what `z.instanceof(Uint8Array)` infers, and `subarray`
// would emit the wider `Uint8Array<ArrayBufferLike>` that TS6 rejects.
function copyBytes(bytes: Uint8Array, start = 0, end = bytes.length): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(end - start);
  out.set(bytes.subarray(start, end));
  return out;
}

function emittedCodes(result: ValidateResult): string[] {
  if (result.ok) {
    return [
      ...(result.warnings ?? []).map((i) => i.code),
      ...(result.info ?? []).map((i) => i.code),
    ];
  }
  return result.issues.map((i) => i.code);
}

function buildCoseSign1(
  alg: number,
  options: { kid?: Uint8Array; payload?: Uint8Array | null } = {},
): Uint8Array {
  const protectedMap = new Map<number, unknown>([[1, alg]]);
  if (options.kid !== undefined) protectedMap.set(4, options.kid);
  const protectedBytes =
    protectedMap.size === 0
      ? new Uint8Array(0)
      : encodeCanonicalCbor(protectedMap as unknown as CanonicalCborValue);
  const unprotected = new Map<number, unknown>();
  const signature = new Uint8Array(64).fill(0x99);
  return encodeCanonicalCbor([
    protectedBytes,
    unprotected as unknown as CanonicalCborValue,
    options.payload ?? null,
    signature,
  ] as readonly CanonicalCborValue[]);
}

// =============================================================================
// Step 2 — CBOR decode error mapping
// =============================================================================

describe('validatePoeRecord — CBOR decode', () => {
  it('maps duplicate-key bytes to MALFORMED_CBOR', () => {
    // {"a": 1, "a": 2} — duplicate map keys are a canonical-decode failure;
    // the taxonomy folds them into MALFORMED_CBOR (no separate code).
    const bytes = hexToBytes('a261610161610' + '2');
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
    expect(result.issues[0]!.path).toEqual([]);
  });

  it('maps non-canonical (unsorted, distinct) map keys to MALFORMED_CBOR', () => {
    // {"b": 1, "a": 2} — distinct keys, but "b" precedes "a" so the map is not
    // in canonical bytewise order. cbor2 reports this with the same "out of
    // order key" message as a true duplicate; both MUST surface as
    // MALFORMED_CBOR (not a duplicate-specific code).
    const bytes = hexToBytes('a2616201616102');
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
    expect(result.issues[0]!.path).toEqual([]);
  });

  it('maps malformed bytes to MALFORMED_CBOR', () => {
    const result = validatePoeRecord(hexToBytes('ffffffff'));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
  });

  it('maps empty input to MALFORMED_CBOR', () => {
    const result = validatePoeRecord(new Uint8Array(0));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
  });

  it('maps indefinite-length CBOR to MALFORMED_CBOR', () => {
    const result = validatePoeRecord(hexToBytes('5fff'));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
  });
});

// =============================================================================
// Step 4a — content-commitment rule (`SCHEMA_EMPTY_RECORD`)
// =============================================================================

describe('validatePoeRecord — content-commitment rule', () => {
  it('rejects an items+merkle-both-absent record with SCHEMA_EMPTY_RECORD', () => {
    const bytes = encodeCanonicalCbor({ v: 1 } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SCHEMA_EMPTY_RECORD');
  });

  it('rejects an items=[]/merkle=[] both-empty record with SCHEMA_EMPTY_RECORD', () => {
    const bytes = encodeCanonicalCbor({ v: 1, items: [], merkle: [] } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SCHEMA_EMPTY_RECORD');
  });

  it('accepts a merkle-only record (no items[])', () => {
    const record: PoeRecord = {
      v: 1,
      merkle: [{ alg: 'rfc9162-sha256', root: hash32(), leaf_count: 4 }],
    };
    const result = validatePoeRecord(encodePoeRecord(record));
    expect(result.ok).toBe(true);
  });
});

// =============================================================================
// Step 3 — schema mapping
// =============================================================================

describe('validatePoeRecord — schema mapping', () => {
  it('maps missing `v` → SCHEMA_MISSING_REQUIRED', () => {
    const bytes = encodeCanonicalCbor({
      items: [{ hashes: { 'sha2-256': hash32() } }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SCHEMA_MISSING_REQUIRED');
  });

  it('maps `v: 2` → SCHEMA_INVALID_LITERAL', () => {
    const bytes = encodeCanonicalCbor({
      v: 2,
      items: [{ hashes: { 'sha2-256': hash32() } }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SCHEMA_INVALID_LITERAL');
  });

  it('maps unknown non-extension top-level key (typo) → SCHEMA_UNKNOWN_FIELD', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      supersedess: new Uint8Array(32),
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SCHEMA_UNKNOWN_FIELD');
  });

  it('accepts extension keys (`x-*`, `seal-*`) without rejection', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      'x-vendor-flag': 'experiment',
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(true);
  });
});

// =============================================================================
// Step 4b — hash-map registry / digest length
// =============================================================================

describe('validatePoeRecord — hash-map domain checks', () => {
  it('rejects an unknown hash alg with UNSUPPORTED_HASH_ALG', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [{ hashes: { md5: new Uint8Array(16) } }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('UNSUPPORTED_HASH_ALG');
  });

  it('rejects a 31-byte sha2-256 digest with HASH_DIGEST_LENGTH_MISMATCH', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [{ hashes: { 'sha2-256': new Uint8Array(31) } }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('HASH_DIGEST_LENGTH_MISMATCH');
  });

  it('accepts a single-hash record (CIP-309 v1 — no SINGLE_HASH warning)', () => {
    const bytes = encodePoeRecord({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
    });
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // v1 emits no SINGLE_HASH warning for a single-hash record.
    expect(result.warnings ?? []).toHaveLength(0);
  });
});

// =============================================================================
// Step 4c — URI chunking + per-scheme shape
// =============================================================================

describe('validatePoeRecord — URI checks', () => {
  it('rejects an URI with a fragment identifier with INVALID_URI', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          uris: [['https://example.org/x#section']],
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('INVALID_URI');
  });

  it('rejects an URI with an out-of-set scheme with INVALID_URI', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          uris: [['https://example.org/x']],
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('INVALID_URI');
  });

  it('accepts a well-formed ar:// URI', () => {
    const txid = 'A'.repeat(43);
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          uris: [[`ar://${txid}`]],
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(true);
  });

  it('rejects an ar:// URI with wrong-length txid', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          uris: [['ar://shorttxid']],
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('INVALID_URI');
  });

  it('accepts a well-formed CIDv0 ipfs:// URI', () => {
    // CIDv0 sample: sha2-256(empty) base58 = QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH
    const cid0 = 'QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH';
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          uris: [[`ipfs://${cid0}`]],
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(true);
  });

  it('rejects an ipfs:// URI with a base64 (m-prefix) multibase', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': hash32() },
          uris: [['ipfs://mAYIKsomethingbase64']],
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('INVALID_URI');
  });
});

// =============================================================================
// Step 4d — encryption envelope
// =============================================================================

describe('validatePoeRecord — encryption envelope', () => {
  const sealedBase = {
    scheme: 1,
    aead: 'xchacha20-poly1305',
    kem: 'x25519',
    nonce: new Uint8Array(24),
    slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
    slots_mac: new Uint8Array(32),
  };

  const wrap = (enc: Record<string, unknown>): CanonicalCborValue =>
    ({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() }, enc: enc as CanonicalCborValue }],
    }) as CanonicalCborValue;

  it('accepts a minimal slots envelope', () => {
    const result = validatePoeRecord(encodeCanonicalCbor(wrap({ ...sealedBase })));
    expect(result.ok).toBe(true);
  });

  // A slot that is "not a 2-key map {epk, wrap}" MUST classify as
  // ENC_SLOT_INVALID_SHAPE — including the extra-key, wrong-whole-type, and
  // scalar cases that previously fell through to SCHEMA_UNKNOWN_FIELD /
  // SCHEMA_TYPE_MISMATCH.
  it('emits ENC_SLOT_INVALID_SHAPE for a slot carrying an extra key', () => {
    const enc = {
      ...sealedBase,
      slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48), foo: 1 }],
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc as Record<string, unknown>)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const codes = emittedCodes(result);
    expect(codes).toContain('ENC_SLOT_INVALID_SHAPE');
    expect(codes).not.toContain('SCHEMA_UNKNOWN_FIELD');
  });

  it('emits ENC_SLOT_INVALID_SHAPE for an array where a slot map is expected', () => {
    const enc = { ...sealedBase, slots: [[1, 2]] };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc as Record<string, unknown>)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const codes = emittedCodes(result);
    expect(codes).toContain('ENC_SLOT_INVALID_SHAPE');
    expect(codes).not.toContain('SCHEMA_TYPE_MISMATCH');
  });

  it('emits ENC_SLOT_INVALID_SHAPE for a scalar where a slot map is expected', () => {
    const enc = { ...sealedBase, slots: [5] };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc as Record<string, unknown>)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const codes = emittedCodes(result);
    expect(codes).toContain('ENC_SLOT_INVALID_SHAPE');
    expect(codes).not.toContain('SCHEMA_TYPE_MISMATCH');
  });

  it('emits ENC_REQUIRES_CONTENT_HASH when hashes is empty', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [{ hashes: {}, enc: { ...sealedBase } as CanonicalCborValue }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_REQUIRES_CONTENT_HASH');
  });

  // Realistic OpenSSL/JCA cipher spellings — `aes-256-cbc` etc. do NOT contain
  // the literal substring `aes-cbc`, so the prior `/aes-cbc/i` test gave false
  // confidence. The whole unauthenticated-cipher family MUST classify as
  // UNAUTHENTICATED_CIPHER_FORBIDDEN, never the generic UNSUPPORTED_AEAD_ALG.
  it.each([
    'aes-256-cbc',
    'aes-128-cbc',
    'AES-256-CBC',
    'aes-256-ctr',
    'aes-128-ecb',
    'rc4',
    'des-ede3-cbc',
  ])('emits UNAUTHENTICATED_CIPHER_FORBIDDEN for unauthenticated cipher %s', (aead) => {
    const result = validatePoeRecord(encodeCanonicalCbor(wrap({ ...sealedBase, aead })));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const codes = emittedCodes(result);
    expect(codes).toContain('UNAUTHENTICATED_CIPHER_FORBIDDEN');
    expect(codes).not.toContain('UNSUPPORTED_AEAD_ALG');
  });

  it('emits UNSUPPORTED_AEAD_ALG for an unknown but not-unauthenticated aead', () => {
    const result = validatePoeRecord(
      encodeCanonicalCbor(wrap({ ...sealedBase, aead: 'twofish-gcm' })),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const codes = emittedCodes(result);
    expect(codes).toContain('UNSUPPORTED_AEAD_ALG');
    expect(codes).not.toContain('UNAUTHENTICATED_CIPHER_FORBIDDEN');
  });

  // Authenticated AEADs MUST NOT be caught by the unauthenticated-cipher
  // family. `aes-256-gcm` is not in the v1 registry → UNSUPPORTED_AEAD_ALG;
  // `chacha20-poly1305` likewise; neither is UNAUTHENTICATED_CIPHER_FORBIDDEN.
  it.each(['aes-256-gcm', 'chacha20-poly1305'])(
    'does not flag authenticated AEAD %s as an unauthenticated cipher',
    (aead) => {
      const result = validatePoeRecord(encodeCanonicalCbor(wrap({ ...sealedBase, aead })));
      expect(result.ok).toBe(false);
      if (result.ok) return;
      const codes = emittedCodes(result);
      expect(codes).not.toContain('UNAUTHENTICATED_CIPHER_FORBIDDEN');
      expect(codes).toContain('UNSUPPORTED_AEAD_ALG');
    },
  );

  it('accepts the registered xchacha20-poly1305 AEAD (not flagged)', () => {
    const result = validatePoeRecord(
      encodeCanonicalCbor(wrap({ ...sealedBase, aead: 'xchacha20-poly1305' })),
    );
    expect(result.ok).toBe(true);
  });

  it('emits NONCE_LENGTH_MISMATCH when nonce length != 24 for xchacha', () => {
    const result = validatePoeRecord(
      encodeCanonicalCbor(wrap({ ...sealedBase, nonce: new Uint8Array(12) })),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('NONCE_LENGTH_MISMATCH');
  });

  it('emits UNSUPPORTED_ENVELOPE_SCHEME when scheme != 1', () => {
    const result = validatePoeRecord(encodeCanonicalCbor(wrap({ ...sealedBase, scheme: 2 })));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('UNSUPPORTED_ENVELOPE_SCHEME');
  });

  it('emits ENC_SLOTS_EMPTY when slots is []', () => {
    const result = validatePoeRecord(encodeCanonicalCbor(wrap({ ...sealedBase, slots: [] })));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_SLOTS_EMPTY');
  });

  it('emits UNSUPPORTED_KEM_ALG when kem is unknown', () => {
    const result = validatePoeRecord(encodeCanonicalCbor(wrap({ ...sealedBase, kem: 'x448' })));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('UNSUPPORTED_KEM_ALG');
  });

  it('emits ENC_KEM_REQUIRED when slots is present but kem is absent', () => {
    const enc: Record<string, unknown> = { ...sealedBase };
    delete enc['kem'];
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_KEM_REQUIRED');
  });

  it('emits KEM_EPK_LENGTH_MISMATCH when slot.epk length != 32', () => {
    const enc = {
      ...sealedBase,
      slots: [{ epk: new Uint8Array(31), wrap: new Uint8Array(48) }],
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('KEM_EPK_LENGTH_MISMATCH');
  });

  it('emits WRAP_LENGTH_MISMATCH when slot.wrap length != 48', () => {
    const enc = {
      ...sealedBase,
      slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(40) }],
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('WRAP_LENGTH_MISMATCH');
  });

  it('emits ENC_SLOTS_MAC_INVALID_LENGTH for a 31-byte slots_mac', () => {
    const enc = { ...sealedBase, slots_mac: new Uint8Array(31) };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_SLOTS_MAC_INVALID_LENGTH');
  });

  it('emits ENC_SLOTS_MAC_REQUIRED when slots is present but slots_mac is absent', () => {
    const enc: Record<string, unknown> = { ...sealedBase };
    delete enc['slots_mac'];
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_SLOTS_MAC_REQUIRED');
  });

  it('emits ENC_SLOTS_REQUIRED when slots_mac is present but slots is absent', () => {
    const enc: Record<string, unknown> = { ...sealedBase };
    delete enc['slots'];
    delete enc['kem'];
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_SLOTS_REQUIRED');
  });

  it('emits ENC_EXCLUSIVITY_VIOLATION when slots AND passphrase both present', () => {
    const enc = {
      ...sealedBase,
      passphrase: {
        alg: 'argon2id',
        salt: new Uint8Array(16),
        params: { m: 65536, t: 3, p: 1 },
      },
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_EXCLUSIVITY_VIOLATION');
  });

  it('emits ENC_NO_KEY_PATH when neither slots nor passphrase present', () => {
    const enc = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: new Uint8Array(24),
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_NO_KEY_PATH');
  });

  it('emits ENC_PASSPHRASE_ALG_UNSUPPORTED for unknown passphrase alg', () => {
    const enc = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: new Uint8Array(24),
      passphrase: {
        alg: 'pbkdf2-sha-256',
        salt: new Uint8Array(16),
        params: { i: 600000 },
      },
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_PASSPHRASE_ALG_UNSUPPORTED');
  });

  it('emits ENC_PASSPHRASE_SALT_TOO_SHORT for salt < 16 bytes', () => {
    const enc = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: new Uint8Array(24),
      passphrase: {
        alg: 'argon2id',
        salt: new Uint8Array(15),
        params: { m: 65536, t: 3, p: 1 },
      },
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_PASSPHRASE_SALT_TOO_SHORT');
  });

  it('emits ENC_PASSPHRASE_SALT_TOO_LONG for salt > 64 bytes', () => {
    const enc = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: new Uint8Array(24),
      passphrase: {
        alg: 'argon2id',
        salt: new Uint8Array(65),
        params: { m: 65536, t: 3, p: 1 },
      },
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_PASSPHRASE_SALT_TOO_LONG');
  });

  it('emits ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW for m < 65536', () => {
    const enc = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: new Uint8Array(24),
      passphrase: {
        alg: 'argon2id',
        salt: new Uint8Array(16),
        params: { m: 1024, t: 3, p: 1 },
      },
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW');
  });

  it('emits SCHEMA_UNKNOWN_FIELD for extra argon2id params keys', () => {
    const enc = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: new Uint8Array(24),
      passphrase: {
        alg: 'argon2id',
        salt: new Uint8Array(16),
        params: { m: 65536, t: 3, p: 1, hash_len: 32 },
      },
    };
    const result = validatePoeRecord(encodeCanonicalCbor(wrap(enc)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SCHEMA_UNKNOWN_FIELD');
  });
});

// =============================================================================
// Step 4i — merkle commitments
// =============================================================================

describe('validatePoeRecord — merkle commitments', () => {
  it('accepts a valid rfc9162-sha256 commit', () => {
    const result = validatePoeRecord(
      encodePoeRecord({
        v: 1,
        merkle: [{ alg: 'rfc9162-sha256', root: hash32(), leaf_count: 4 }],
      }),
    );
    expect(result.ok).toBe(true);
  });

  it('emits UNSUPPORTED_MERKLE_COMMIT_ALG for an unknown alg', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      merkle: [{ alg: 'custom-merkle', root: hash32(), leaf_count: 4 }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('UNSUPPORTED_MERKLE_COMMIT_ALG');
  });

  it('emits HASH_DIGEST_LENGTH_MISMATCH for a 31-byte root', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      merkle: [{ alg: 'rfc9162-sha256', root: new Uint8Array(31), leaf_count: 4 }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('HASH_DIGEST_LENGTH_MISMATCH');
  });
});

// =============================================================================
// Step 4f/4g — sigs entries
// =============================================================================

describe('validatePoeRecord — sigs entries', () => {
  const minimalItems = [{ hashes: { 'sha2-256': hash32() } }];

  it('accepts a path-1 sig entry (cose_sign1 only, alg=-8, detached payload)', () => {
    const cose = buildCoseSign1(-8);
    const result = validatePoeRecord(
      encodePoeRecord({
        v: 1,
        items: minimalItems,
        sigs: [{ cose_sign1: Array.from(chunked(cose)) }],
      }),
    );
    expect(result.ok).toBe(true);
  });

  it('emits SIGNATURE_UNSUPPORTED (info) for alg=-7 (ES256, reserved)', () => {
    const cose = buildCoseSign1(-7);
    const result = validatePoeRecord(
      encodePoeRecord({
        v: 1,
        items: minimalItems,
        sigs: [{ cose_sign1: Array.from(chunked(cose)) }],
      }),
    );
    // The unsupported sig is info-severity and does NOT fail the record —
    // the public hash-only PoE remains valid.
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const codes = emittedCodes(result);
    expect(codes).toContain('SIGNATURE_UNSUPPORTED');
  });

  it('emits MALFORMED_SIG_COSE_SIGN1 for attached payload (zero-length bstr)', () => {
    const cose = buildCoseSign1(-8, { payload: new Uint8Array(0) });
    const result = validatePoeRecord(
      encodePoeRecord({
        v: 1,
        items: minimalItems,
        sigs: [{ cose_sign1: Array.from(chunked(cose)) }],
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('MALFORMED_SIG_COSE_SIGN1');
  });

  it('emits MALFORMED_SIG_COSE_SIGN1 for garbage cose_sign1 chunks', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      sigs: [{ cose_sign1: [new Uint8Array([0xff, 0xff, 0xff])] }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('MALFORMED_SIG_COSE_SIGN1');
  });

  it('emits SIG_ENTRY_KID_COSE_KEY_CONFLICT when both 32-byte kid AND cose_key present', () => {
    const cose = buildCoseSign1(-8, { kid: hash32(0x42) });
    const coseKey = encodeCanonicalCbor(
      new Map<number, unknown>([
        [1, 1], // kty: OKP
        [-1, 6], // crv: Ed25519
        [-2, hash32(0x55)], // x: pubkey
      ]) as unknown as CanonicalCborValue,
    );
    const bytes = encodePoeRecord({
      v: 1,
      items: minimalItems,
      sigs: [
        {
          cose_sign1: Array.from(chunked(cose)),
          cose_key: Array.from(chunked(coseKey)),
        },
      ],
    });
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SIG_ENTRY_KID_COSE_KEY_CONFLICT');
  });

  it('emits SIG_PRIVATE_KEY_LEAKED when cose_key carries COSE_Key label -4 (private d scalar)', () => {
    const cose = buildCoseSign1(-8);
    const coseKey = encodeCanonicalCbor(
      new Map<number, unknown>([
        [1, 1], // kty: OKP
        [-1, 6], // crv: Ed25519
        [-2, hash32(0x55)], // x: pubkey
        [-4, hash32(0xaa)], // d: PRIVATE SCALAR — must be rejected
      ]) as unknown as CanonicalCborValue,
    );
    const bytes = encodePoeRecord({
      v: 1,
      items: minimalItems,
      sigs: [
        {
          cose_sign1: Array.from(chunked(cose)),
          cose_key: Array.from(chunked(coseKey)),
        },
      ],
    });
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SIG_PRIVATE_KEY_LEAKED');
  });

  it('emits SIG_ENTRY_INVALID_SHAPE when sigs[i] carries an extra field', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      sigs: [
        {
          cose_sign1: [new Uint8Array(64)],
          extra_field: new Uint8Array(8),
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SIG_ENTRY_INVALID_SHAPE');
  });

  it('emits SIG_ENTRY_INVALID_SHAPE when sigs[i] is missing cose_sign1', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      sigs: [{ cose_key: [new Uint8Array(50)] }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SIG_ENTRY_INVALID_SHAPE');
  });

  // Multi-cosigner: the validator must catch the bad entry at
  // ANY index in sigs[], not just sigs[0]. These tests pin the per-index
  // iteration discipline. They are constructed inline (rather than loaded from
  // JSON fixtures) to match every other validator test in this file.
  it('emits SIG_PRIVATE_KEY_LEAKED when the bad entry sits at sigs[2] (multi-cosigner)', () => {
    const goodCose1 = buildCoseSign1(-8, { kid: hash32(0x11) });
    const goodCose2 = buildCoseSign1(-8, { kid: hash32(0x22) });
    const badCose = buildCoseSign1(-8);
    const poisonedCoseKey = encodeCanonicalCbor(
      new Map<number, unknown>([
        [1, 1], // kty: OKP
        [-1, 6], // crv: Ed25519
        [-2, hash32(0x55)], // x: pubkey
        [-4, hash32(0xaa)], // d: PRIVATE SCALAR — must be rejected
      ]) as unknown as CanonicalCborValue,
    );
    const bytes = encodePoeRecord({
      v: 1,
      items: minimalItems,
      sigs: [
        { cose_sign1: Array.from(chunked(goodCose1)) },
        { cose_sign1: Array.from(chunked(goodCose2)) },
        {
          cose_sign1: Array.from(chunked(badCose)),
          cose_key: Array.from(chunked(poisonedCoseKey)),
        },
      ],
    });
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SIG_PRIVATE_KEY_LEAKED');
  });

  it('emits SIG_ENTRY_KID_COSE_KEY_CONFLICT when the bad entry sits at sigs[1] (multi-cosigner)', () => {
    const goodCose = buildCoseSign1(-8, { kid: hash32(0x11) });
    const badCose = buildCoseSign1(-8, { kid: hash32(0x42) });
    const coseKey = encodeCanonicalCbor(
      new Map<number, unknown>([
        [1, 1],
        [-1, 6],
        [-2, hash32(0x55)],
      ]) as unknown as CanonicalCborValue,
    );
    const bytes = encodePoeRecord({
      v: 1,
      items: minimalItems,
      sigs: [
        { cose_sign1: Array.from(chunked(goodCose)) },
        {
          cose_sign1: Array.from(chunked(badCose)),
          cose_key: Array.from(chunked(coseKey)),
        },
      ],
    });
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SIG_ENTRY_KID_COSE_KEY_CONFLICT');
  });

  it('emits SIG_ENTRY_INVALID_SHAPE when the bad entry sits at sigs[1] (multi-cosigner, extra field)', () => {
    const goodCose = buildCoseSign1(-8, { kid: hash32(0x11) });
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      sigs: [
        { cose_sign1: Array.from(chunked(goodCose)) },
        {
          cose_sign1: [new Uint8Array(64)],
          extra_field: new Uint8Array(8),
        },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SIG_ENTRY_INVALID_SHAPE');
  });

  it('emits MALFORMED_SIG_COSE_SIGN1 when the bad entry sits at sigs[2] (multi-cosigner)', () => {
    const goodCose1 = buildCoseSign1(-8, { kid: hash32(0x11) });
    const goodCose2 = buildCoseSign1(-8, { kid: hash32(0x22) });
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      sigs: [
        { cose_sign1: Array.from(chunked(goodCose1)) },
        { cose_sign1: Array.from(chunked(goodCose2)) },
        { cose_sign1: [new Uint8Array([0xff, 0xff, 0xff])] },
      ],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('MALFORMED_SIG_COSE_SIGN1');
  });
});

// =============================================================================
// Step 4j — crit[] shape rules
// =============================================================================

describe('validatePoeRecord — crit[] shape rules', () => {
  const minimalItems = [{ hashes: { 'sha2-256': hash32() } }];

  it('emits CRIT_SHAPE_INVALID when crit names a base key (`v`)', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      crit: ['v'],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('CRIT_SHAPE_INVALID');
  });

  it('emits CRIT_SHAPE_INVALID when crit names a non-extension-key', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      crit: ['UPPERCASE-FOO'],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('CRIT_SHAPE_INVALID');
  });

  it('emits CRIT_SHAPE_INVALID for a dangling reference (extension key absent from record)', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      crit: ['x-missing'],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('CRIT_SHAPE_INVALID');
  });

  it('emits CRIT_SHAPE_INVALID for duplicate entries', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      'x-foo': 'bar',
      crit: ['x-foo', 'x-foo'],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('CRIT_SHAPE_INVALID');
  });

  it('emits EXTENSION_UNSUPPORTED_CRITICAL when crit names a well-formed extension this validator does not implement', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: minimalItems,
      'x-foo': 'bar',
      crit: ['x-foo'],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('EXTENSION_UNSUPPORTED_CRITICAL');
  });
});

// =============================================================================
// Step 4h — supersedes
// =============================================================================

describe('validatePoeRecord — supersedes', () => {
  it('accepts a 32-byte supersedes bstr', () => {
    const bytes = encodePoeRecord({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      supersedes: new Uint8Array(32).fill(0x42),
    });
    expect(validatePoeRecord(bytes).ok).toBe(true);
  });

  it('emits SUPERSEDES_TX_INVALID_LENGTH for a 31-byte supersedes', () => {
    const bytes = encodeCanonicalCbor({
      v: 1,
      items: [{ hashes: { 'sha2-256': hash32() } }],
      supersedes: new Uint8Array(31),
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(emittedCodes(result)).toContain('SUPERSEDES_TX_INVALID_LENGTH');
  });
});

// =============================================================================
// Issue sorting + result shape narrowing
// =============================================================================

describe('validatePoeRecord — result shape', () => {
  it('sorts errors deterministically by path', () => {
    const bytes = encodeCanonicalCbor({
      v: 99,
      items: [{ hashes: { 'sha2-256': hash32() } }, { hashes: { 'sha2-256': new Uint8Array(31) } }],
    } as CanonicalCborValue);
    const result = validatePoeRecord(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const paths = result.issues.map((e) => e.path.join('.'));
    const sorted = [...paths].sort((a, b) => a.localeCompare(b));
    expect(paths).toEqual(sorted);
  });

  it('narrows to record + optional warnings/info on ok === true (compile-time)', () => {
    const fake = {} as ValidateResult;
    if (fake.ok === true) {
      expectTypeOf(fake.record).toEqualTypeOf<PoeRecord>();
      expectTypeOf(fake.warnings).toEqualTypeOf<ReadonlyArray<ValidationIssue> | undefined>();
      expectTypeOf(fake.info).toEqualTypeOf<ReadonlyArray<ValidationIssue> | undefined>();
    }
  });

  it('narrows to issues on ok === false (compile-time)', () => {
    const fake = {} as ValidateResult;
    if (fake.ok === false) {
      // @ts-expect-error record is not accessible on the false branch
      void fake.record;
      expectTypeOf(fake.issues).toEqualTypeOf<ReadonlyArray<ValidationIssue>>();
    }
  });
});

// =============================================================================
// Test helpers
// =============================================================================

function chunked(bytes: Uint8Array): Uint8Array<ArrayBuffer>[] {
  if (bytes.length === 0) return [new Uint8Array(0)];
  const out: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < bytes.length; i += 64) {
    out.push(copyBytes(bytes, i, Math.min(i + 64, bytes.length)));
  }
  return out;
}
