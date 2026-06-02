// Zod-schema unit tests for the CIP-309 v1 wire shape.
//
// Cross-field semantics and registry-membership checks live in
// `validator.test.ts`; this file pins ONLY the schema-layer behaviour
// (shape gates, length refinements, closed-map invariants, literal
// rejection of `v != 1`).

import { describe, expect, it } from 'vitest';

import {
  ChunkedBytesArraySchema,
  EncryptionEnvelopeSchema,
  HashDigestSchema,
  ItemEntrySchema,
  MerkleCommitSchema,
  PassphraseBlockSchema,
  PoeRecordSchema,
  SigEntrySchema,
  SlotSchema,
  SupersedesSchema,
  UriChunkArraySchema,
  type PoeRecord,
} from './schema';

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const sha2 = hexToBytes('acbd2db1c365826ec79328a30c46418396121ca457bcb28f6f4275ebff7635e8');
const blake2b = hexToBytes('4933a770ca4423edb274f3d660c2c8ae88e55331bb7eaf622c7a78d52128bae8');

const minimalItem = (): unknown => ({
  hashes: { 'sha2-256': sha2 },
});

describe('PoeRecordSchema — positive parses', () => {
  it('parses a minimal items-only record', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [{ hashes: { 'sha2-256': sha2, 'blake2b-256': blake2b } }],
    });
    expect(result.success).toBe(true);
  });

  it('parses a merkle-only record (no items[])', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      merkle: [{ alg: 'rfc9162-sha256', root: sha2, leaf_count: 4 }],
    });
    expect(result.success).toBe(true);
  });

  it('parses a hybrid items+merkle record', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [minimalItem()],
      merkle: [{ alg: 'rfc9162-sha256', root: sha2, leaf_count: 4 }],
    });
    expect(result.success).toBe(true);
  });

  it('parses supersedes as a bare 32-byte bstr', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [minimalItem()],
      supersedes: new Uint8Array(32),
    });
    expect(result.success).toBe(true);
  });

  it('parses a record with a sealed-PoE envelope (slots path)', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': sha2 },
          enc: {
            scheme: 1,
            aead: 'xchacha20-poly1305',
            kem: 'x25519',
            nonce: new Uint8Array(24),
            slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
            slots_mac: new Uint8Array(32),
          },
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('parses a record with a passphrase envelope (argon2id)', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [
        {
          hashes: { 'sha2-256': sha2 },
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
    });
    expect(result.success).toBe(true);
  });

  it('parses a record with record-level sigs (path 1, cose_sign1 only)', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [minimalItem()],
      sigs: [{ cose_sign1: [new Uint8Array(64), new Uint8Array(20)] }],
    });
    expect(result.success).toBe(true);
  });

  it('parses a record with record-level sigs (path 2, cose_sign1 + cose_key)', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [minimalItem()],
      sigs: [
        {
          cose_sign1: [new Uint8Array(64)],
          cose_key: [new Uint8Array(50)],
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('parses extension keys (vendor `x-foo`, companion `seal-foo`)', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [minimalItem()],
      'x-vendor-flag': 'experiment',
      'seal-something': new Uint8Array(8),
    });
    expect(result.success).toBe(true);
  });
});

describe('PoeRecordSchema — negative parses', () => {
  it('rejects v: 2 (literal mismatch — validator maps to SCHEMA_INVALID_LITERAL)', () => {
    const result = PoeRecordSchema.safeParse({ v: 2, items: [minimalItem()] });
    expect(result.success).toBe(false);
    if (!result.success) {
      // Zod 4's `z.literal(1)` raises `invalid_value`; the validator's mapper
      // lifts that to `SCHEMA_INVALID_LITERAL`. The raw schema doesn't attach
      // a `params.code` here — the mapping happens in `validator.ts`.
      expect(result.error.issues[0]!.code).toBe('invalid_value');
      expect(result.error.issues[0]!.path).toEqual(['v']);
    }
  });

  it('rejects v: 1.5 (non-integer)', () => {
    const result = PoeRecordSchema.safeParse({ v: 1.5, items: [minimalItem()] });
    expect(result.success).toBe(false);
  });

  it('rejects missing v', () => {
    const result = PoeRecordSchema.safeParse({ items: [minimalItem()] });
    expect(result.success).toBe(false);
  });

  it('accepts the empty items array at the schema layer (validator emits SCHEMA_EMPTY_RECORD)', () => {
    const result = PoeRecordSchema.safeParse({ v: 1, items: [] });
    expect(result.success).toBe(true);
  });

  it('rejects unknown top-level base-name typos like Sigs/supersedess via loose object (accepted by schema, validator emits SCHEMA_UNKNOWN_FIELD)', () => {
    const result = PoeRecordSchema.safeParse({
      v: 1,
      items: [minimalItem()],
      supersedess: new Uint8Array(32),
    });
    // looseObject admits the field; validator emits SCHEMA_UNKNOWN_FIELD.
    expect(result.success).toBe(true);
  });
});

describe('HashDigestSchema', () => {
  it('accepts a 32-byte digest', () => {
    expect(HashDigestSchema.safeParse(sha2).success).toBe(true);
  });

  it('accepts any byte length at the schema layer (length check lives in the validator domain pass)', () => {
    expect(HashDigestSchema.safeParse(new Uint8Array(31)).success).toBe(true);
    expect(HashDigestSchema.safeParse(new Uint8Array(64)).success).toBe(true);
  });

  it('rejects a non-Uint8Array value', () => {
    expect(HashDigestSchema.safeParse('hex-string').success).toBe(false);
  });
});

describe('SupersedesSchema', () => {
  it('accepts a 32-byte bstr', () => {
    expect(SupersedesSchema.safeParse(new Uint8Array(32)).success).toBe(true);
  });

  it('rejects a 31-byte bstr with SUPERSEDES_TX_INVALID_LENGTH params code', () => {
    const result = SupersedesSchema.safeParse(new Uint8Array(31));
    expect(result.success).toBe(false);
    if (!result.success) {
      const params = (result.error.issues[0] as unknown as { params?: { code?: string } }).params;
      expect(params?.code).toBe('SUPERSEDES_TX_INVALID_LENGTH');
    }
  });

  it('rejects a map (legacy {tx, reason} shape)', () => {
    const result = SupersedesSchema.safeParse({ tx: new Uint8Array(32), reason: 'x' });
    expect(result.success).toBe(false);
  });
});

describe('ChunkedBytesArraySchema / UriChunkArraySchema', () => {
  it('rejects an empty chunk (length 0) with CHUNK_TOO_LARGE', () => {
    const result = ChunkedBytesArraySchema.safeParse([new Uint8Array(0)]);
    expect(result.success).toBe(false);
    if (!result.success) {
      const params = (result.error.issues[0] as unknown as { params?: { code?: string } }).params;
      expect(params?.code).toBe('CHUNK_TOO_LARGE');
    }
  });

  it('rejects a 65-byte chunk', () => {
    const result = ChunkedBytesArraySchema.safeParse([new Uint8Array(65)]);
    expect(result.success).toBe(false);
  });

  it('accepts a 64-byte chunk', () => {
    expect(ChunkedBytesArraySchema.safeParse([new Uint8Array(64)]).success).toBe(true);
  });

  it('rejects an empty chunk array', () => {
    expect(ChunkedBytesArraySchema.safeParse([]).success).toBe(false);
  });

  it('UriChunkArraySchema measures bytes not chars (rejects > 64 UTF-8 bytes)', () => {
    // 22 emoji × 4 bytes each = 88 bytes > 64.
    const chunk = '😀'.repeat(22);
    const result = UriChunkArraySchema.safeParse([chunk]);
    expect(result.success).toBe(false);
  });
});

describe('SlotSchema', () => {
  // The schema is intentionally PERMISSIVE: it admits both the classical
  // ({epk, wrap}) and hybrid ({kem_ct, wrap}) slot shapes structurally. The
  // KEM-driven length + cross-KEM-contamination gate lives in the validator's
  // domain pass (see validator KAT for KEM_EPK_LENGTH_MISMATCH /
  // KEM_CT_LENGTH_MISMATCH / WRAP_LENGTH_MISMATCH / ENC_SLOT_INVALID_SHAPE),
  // because the required shape depends on the envelope-level `kem` a slot
  // cannot see in isolation.
  it('accepts a classical slot {epk, wrap}', () => {
    expect(
      SlotSchema.safeParse({ epk: new Uint8Array(32), wrap: new Uint8Array(48) }).success,
    ).toBe(true);
  });

  it('accepts a hybrid slot {kem_ct: chunk-array, wrap}', () => {
    expect(
      SlotSchema.safeParse({
        kem_ct: [new Uint8Array(64), new Uint8Array(32)],
        wrap: new Uint8Array(48),
      }).success,
    ).toBe(true);
  });

  it('does NOT enforce field lengths at the schema layer (moved to validator)', () => {
    // A 31-byte epk and a 47-byte wrap both parse — the schema no longer
    // carries the length refinements; the validator emits the typed codes.
    expect(
      SlotSchema.safeParse({ epk: new Uint8Array(31), wrap: new Uint8Array(47) }).success,
    ).toBe(true);
  });

  it('rejects a kem_ct chunk outside [1, 64] bytes with CHUNK_TOO_LARGE', () => {
    const result = SlotSchema.safeParse({
      kem_ct: [new Uint8Array(65)],
      wrap: new Uint8Array(48),
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const codes = result.error.issues.map(
        (i) => (i as unknown as { params?: { code?: string } }).params?.code,
      );
      expect(codes).toContain('CHUNK_TOO_LARGE');
    }
  });
});

describe('PassphraseBlockSchema', () => {
  it('accepts a valid argon2id block', () => {
    expect(
      PassphraseBlockSchema.safeParse({
        alg: 'argon2id',
        salt: new Uint8Array(16),
        params: { m: 65536, t: 3, p: 1 },
      }).success,
    ).toBe(true);
  });

  it('rejects salt length < 16 with ENC_PASSPHRASE_SALT_TOO_SHORT', () => {
    const result = PassphraseBlockSchema.safeParse({
      alg: 'argon2id',
      salt: new Uint8Array(15),
      params: { m: 65536, t: 3, p: 1 },
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const codes = result.error.issues.map(
        (i) => (i as unknown as { params?: { code?: string } }).params?.code,
      );
      expect(codes).toContain('ENC_PASSPHRASE_SALT_TOO_SHORT');
    }
  });

  it('rejects salt length > 64 with ENC_PASSPHRASE_SALT_TOO_LONG', () => {
    const result = PassphraseBlockSchema.safeParse({
      alg: 'argon2id',
      salt: new Uint8Array(65),
      params: { m: 65536, t: 3, p: 1 },
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const codes = result.error.issues.map(
        (i) => (i as unknown as { params?: { code?: string } }).params?.code,
      );
      expect(codes).toContain('ENC_PASSPHRASE_SALT_TOO_LONG');
    }
  });
});

describe('EncryptionEnvelopeSchema', () => {
  it('accepts a minimal slots envelope', () => {
    expect(
      EncryptionEnvelopeSchema.safeParse({
        scheme: 1,
        aead: 'xchacha20-poly1305',
        kem: 'x25519',
        nonce: new Uint8Array(24),
        slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
        slots_mac: new Uint8Array(32),
      }).success,
    ).toBe(true);
  });

  it('rejects unknown envelope fields (.strict)', () => {
    expect(
      EncryptionEnvelopeSchema.safeParse({
        scheme: 1,
        aead: 'xchacha20-poly1305',
        nonce: new Uint8Array(24),
        slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
        slots_mac: new Uint8Array(32),
        future_field: 'x',
      }).success,
    ).toBe(false);
  });

  it('rejects wrong-length slots_mac', () => {
    const result = EncryptionEnvelopeSchema.safeParse({
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: new Uint8Array(24),
      slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
      slots_mac: new Uint8Array(31),
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const params = (result.error.issues[0] as unknown as { params?: { code?: string } }).params;
      expect(params?.code).toBe('ENC_SLOTS_MAC_INVALID_LENGTH');
    }
  });
});

describe('MerkleCommitSchema', () => {
  it('accepts a minimal merkle commit', () => {
    expect(
      MerkleCommitSchema.safeParse({
        alg: 'rfc9162-sha256',
        root: sha2,
        leaf_count: 4,
      }).success,
    ).toBe(true);
  });

  it('rejects leaf_count < 1', () => {
    expect(
      MerkleCommitSchema.safeParse({
        alg: 'rfc9162-sha256',
        root: sha2,
        leaf_count: 0,
      }).success,
    ).toBe(false);
  });

  it('rejects unknown fields (.strict)', () => {
    expect(
      MerkleCommitSchema.safeParse({
        alg: 'rfc9162-sha256',
        root: sha2,
        leaf_count: 4,
        future_field: 'x',
      }).success,
    ).toBe(false);
  });

  it('accepts any root length at the schema layer (length check lives in the validator domain pass)', () => {
    expect(
      MerkleCommitSchema.safeParse({
        alg: 'rfc9162-sha256',
        root: new Uint8Array(31),
        leaf_count: 4,
      }).success,
    ).toBe(true);
  });
});

describe('SigEntrySchema', () => {
  it('accepts {cose_sign1} (path 1)', () => {
    expect(SigEntrySchema.safeParse({ cose_sign1: [new Uint8Array(64)] }).success).toBe(true);
  });

  it('accepts {cose_sign1, cose_key} (path 2)', () => {
    expect(
      SigEntrySchema.safeParse({
        cose_sign1: [new Uint8Array(64)],
        cose_key: [new Uint8Array(50)],
      }).success,
    ).toBe(true);
  });

  it('rejects missing cose_sign1', () => {
    expect(SigEntrySchema.safeParse({ cose_key: [new Uint8Array(50)] }).success).toBe(false);
  });

  it('rejects extra keys (.strict)', () => {
    expect(
      SigEntrySchema.safeParse({
        cose_sign1: [new Uint8Array(64)],
        sig: [new Uint8Array(64)],
      }).success,
    ).toBe(false);
  });
});

describe('ItemEntrySchema', () => {
  it('accepts a minimal item', () => {
    expect(ItemEntrySchema.safeParse({ hashes: { 'sha2-256': sha2 } }).success).toBe(true);
  });

  it('rejects extra keys', () => {
    expect(
      ItemEntrySchema.safeParse({ hashes: { 'sha2-256': sha2 }, sig: [new Uint8Array(64)] })
        .success,
    ).toBe(false);
  });
});

describe('PoeRecord type inference (compile-time)', () => {
  it('inferred PoeRecord narrows v to 1', () => {
    const record: PoeRecord = { v: 1, items: [{ hashes: { 'sha2-256': sha2 } }] };
    const v: 1 = record.v;
    expect(v).toBe(1);
  });
});
