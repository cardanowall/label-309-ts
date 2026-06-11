// Zod-schema unit tests for the Label 309 v1 wire shape.
//
// Cross-field semantics, registry membership, and code attribution live in
// the validator tests; this file pins ONLY the schema-layer behaviour —
// closed-map invariants, the de-chunked single-value field shapes, length
// refinements, the `v == 1` literal, and the extension-key namespace
// predicate.

import { describe, expect, it } from 'vitest';

import {
  EncOpaqueSchema,
  EncScheme1Schema,
  isExtensionKey,
  ItemEntrySchema,
  MerkleCommitSchema,
  PassphraseBlockSchema,
  PoeRecordSchema,
  SigEntrySchema,
  SlotSchema,
  SupersedesSchema,
  TOP_LEVEL_BASE_KEYS,
} from './schema';

function bytes(len: number, fill = 0x11): Uint8Array {
  return new Uint8Array(len).fill(fill);
}

describe('PoeRecordSchema (top level)', () => {
  it('parses a minimal hash-only record and preserves extension keys', () => {
    const parsed = PoeRecordSchema.safeParse({
      v: 1,
      items: [{ hashes: { 'sha2-256': bytes(32) } }],
      'x-note': 'kept',
    });
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data['x-note']).toBe('kept');
  });

  it('rejects v != 1 and a missing v', () => {
    expect(PoeRecordSchema.safeParse({ v: 2 }).success).toBe(false);
    expect(PoeRecordSchema.safeParse({}).success).toBe(false);
  });

  it('the base-key set is exactly the six v1 top-level keys', () => {
    expect([...TOP_LEVEL_BASE_KEYS].sort()).toEqual([
      'crit',
      'items',
      'merkle',
      'sigs',
      'supersedes',
      'v',
    ]);
  });
});

describe('ItemEntrySchema', () => {
  it('is a closed map: a stray key fails the parse', () => {
    const ok = ItemEntrySchema.safeParse({ hashes: { 'sha2-256': bytes(32) } });
    expect(ok.success).toBe(true);
    const stray = ItemEntrySchema.safeParse({ hashes: { 'sha2-256': bytes(32) }, extra: 1 });
    expect(stray.success).toBe(false);
  });

  it('each URI is a single text string (no per-field chunk wrapper)', () => {
    const ok = ItemEntrySchema.safeParse({
      hashes: { 'sha2-256': bytes(32) },
      uris: ['ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
    });
    expect(ok.success).toBe(true);
    const chunked = ItemEntrySchema.safeParse({
      hashes: { 'sha2-256': bytes(32) },
      uris: [['ar://aaa', 'split']],
    });
    expect(chunked.success).toBe(false);
  });
});

describe('MerkleCommitSchema', () => {
  it('parses {alg, root, leaf_count, ?uris} and admits bigint leaf_count', () => {
    expect(
      MerkleCommitSchema.safeParse({ alg: 'rfc9162-sha256', root: bytes(32), leaf_count: 8 })
        .success,
    ).toBe(true);
    expect(
      MerkleCommitSchema.safeParse({
        alg: 'rfc9162-sha256',
        root: bytes(32),
        leaf_count: 2n ** 53n + 1n,
      }).success,
    ).toBe(true);
  });

  it('is a closed map and requires every field', () => {
    expect(
      MerkleCommitSchema.safeParse({
        alg: 'rfc9162-sha256',
        root: bytes(32),
        leaf_count: 1,
        extra: true,
      }).success,
    ).toBe(false);
    expect(MerkleCommitSchema.safeParse({ alg: 'rfc9162-sha256', root: bytes(32) }).success).toBe(
      false,
    );
  });
});

describe('encryption envelope schemas', () => {
  const slotsEnvelope = {
    scheme: 1,
    aead: 'chacha20-poly1305-stream64k',
    kem: 'x25519',
    nonce: bytes(24),
    slots: [{ epk: bytes(32), wrap: bytes(48) }],
    slots_mac: bytes(32),
  };

  it('EncScheme1Schema parses the slots path and the passphrase path', () => {
    expect(EncScheme1Schema.safeParse(slotsEnvelope).success).toBe(true);
    expect(
      EncScheme1Schema.safeParse({
        scheme: 1,
        aead: 'chacha20-poly1305-stream64k',
        nonce: bytes(24),
        passphrase: { alg: 'argon2id', salt: bytes(16), params: { m: 65536, t: 3, p: 4 } },
      }).success,
    ).toBe(true);
  });

  it('EncScheme1Schema is closed: a stray envelope key fails', () => {
    expect(EncScheme1Schema.safeParse({ ...slotsEnvelope, extra: 1 }).success).toBe(false);
  });

  it('slots_mac carries a 32-byte refinement', () => {
    expect(EncScheme1Schema.safeParse({ ...slotsEnvelope, slots_mac: bytes(31) }).success).toBe(
      false,
    );
  });

  it('SlotSchema is permissive (the KEM-driven gate closes it in the validator)', () => {
    expect(SlotSchema.safeParse({ epk: bytes(32), wrap: bytes(48) }).success).toBe(true);
    expect(SlotSchema.safeParse({ kem_ct: bytes(1120), wrap: bytes(48) }).success).toBe(true);
    expect(SlotSchema.safeParse({}).success).toBe(true);
  });

  it('kem_ct is a SINGLE byte string, not a chunk array', () => {
    expect(SlotSchema.safeParse({ kem_ct: [bytes(64), bytes(64)], wrap: bytes(48) }).success).toBe(
      false,
    );
  });

  it('EncOpaqueSchema requires only a uint scheme and admits anything else text-keyed', () => {
    expect(EncOpaqueSchema.safeParse({ scheme: 7, anything: 'goes', k: bytes(4) }).success).toBe(
      true,
    );
    expect(EncOpaqueSchema.safeParse({ scheme: 2n ** 60n }).success).toBe(true);
    expect(EncOpaqueSchema.safeParse({ anything: 'goes' }).success).toBe(false);
  });
});

describe('PassphraseBlockSchema', () => {
  it('enforces the 16..64-byte salt bounds via dedicated refinement codes', () => {
    const block = (saltLen: number) => ({
      alg: 'argon2id',
      salt: bytes(saltLen),
      params: { m: 65536, t: 3, p: 4 },
    });
    expect(PassphraseBlockSchema.safeParse(block(16)).success).toBe(true);
    expect(PassphraseBlockSchema.safeParse(block(64)).success).toBe(true);

    const short = PassphraseBlockSchema.safeParse(block(15));
    expect(short.success).toBe(false);
    if (!short.success) {
      const params = short.error.issues[0] as unknown as { params?: { code?: string } };
      expect(params.params?.code).toBe('ENC_PASSPHRASE_SALT_TOO_SHORT');
    }

    const long = PassphraseBlockSchema.safeParse(block(65));
    expect(long.success).toBe(false);
    if (!long.success) {
      const params = long.error.issues[0] as unknown as { params?: { code?: string } };
      expect(params.params?.code).toBe('ENC_PASSPHRASE_SALT_TOO_LONG');
    }
  });

  it('is a closed map at the block level', () => {
    expect(
      PassphraseBlockSchema.safeParse({
        alg: 'argon2id',
        salt: bytes(16),
        params: { m: 65536, t: 3, p: 4 },
        mac: bytes(32),
      }).success,
    ).toBe(false);
  });
});

describe('SigEntrySchema', () => {
  it('cose_sign1 / cose_key are single byte strings in a closed map', () => {
    expect(SigEntrySchema.safeParse({ cose_sign1: bytes(80) }).success).toBe(true);
    expect(SigEntrySchema.safeParse({ cose_sign1: bytes(80), cose_key: bytes(40) }).success).toBe(
      true,
    );
    expect(SigEntrySchema.safeParse({ cose_sign1: [bytes(64), bytes(16)] }).success).toBe(false);
    expect(SigEntrySchema.safeParse({ cose_sign1: bytes(80), extra: 1 }).success).toBe(false);
    expect(SigEntrySchema.safeParse({}).success).toBe(false);
  });
});

describe('SupersedesSchema', () => {
  it('requires exactly 32 bytes with the dedicated refinement code', () => {
    expect(SupersedesSchema.safeParse(bytes(32)).success).toBe(true);
    const bad = SupersedesSchema.safeParse(bytes(31));
    expect(bad.success).toBe(false);
    if (!bad.success) {
      const params = bad.error.issues[0] as unknown as { params?: { code?: string } };
      expect(params.params?.code).toBe('SUPERSEDES_TX_INVALID_LENGTH');
    }
  });
});

describe('isExtensionKey', () => {
  it('accepts the vendor and companion namespaces', () => {
    expect(isExtensionKey('x-note')).toBe(true);
    expect(isExtensionKey('x-a')).toBe(true);
    expect(isExtensionKey('myext-field')).toBe(true);
  });

  it('rejects base-key look-alikes and non-namespaced keys', () => {
    expect(isExtensionKey('supersedess')).toBe(false);
    expect(isExtensionKey('Sigs')).toBe(false);
    expect(isExtensionKey('x-')).toBe(false);
    expect(isExtensionKey('X-note')).toBe(false);
    expect(isExtensionKey('-leading')).toBe(false);
  });

  it('rejects control characters anywhere in the key, including a trailing newline', () => {
    expect(isExtensionKey('x-note\n')).toBe(false);
    expect(isExtensionKey('x-note\n\n')).toBe(false);
    expect(isExtensionKey('x-a\nb')).toBe(false);
    expect(isExtensionKey('x-a\u0000b')).toBe(false);
    expect(isExtensionKey('x-a\u009fb')).toBe(false);
  });

  it('admits non-control characters in the suffix (only control characters are excluded)', () => {
    expect(isExtensionKey('x-a b')).toBe(true);
    expect(isExtensionKey('x-a.b')).toBe(true);
  });
});
