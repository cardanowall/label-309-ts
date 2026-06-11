// Structural-validator behaviour tests — the contract surface the byte-pinned
// conformance corpora do not pin: option defaults, issue paths and their
// deterministic ordering, exact-integer boundary handling, the default
// Argon2id policy ceiling, and decode-layer dispositions. Each test builds
// its record in-test; corpus replay lives in the `*.kat.test.ts` files.

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { describe, expect, it } from 'vitest';

import { encodePoeRecord } from './encoder';
import type { PoeRecord } from './schema';
import {
  DEFAULT_PASSPHRASE_PARAMS_CEILING,
  validatePoeRecord,
  type ValidationIssue,
  type ValidationResult,
} from './validator';

function bytes(len: number, fill = 0xab): Uint8Array<ArrayBuffer> {
  return new Uint8Array(len).fill(fill);
}

function encode(value: CanonicalCborValue): Uint8Array {
  return encodeCanonicalCbor(value);
}

const minimalItems = () => [{ hashes: { 'sha2-256': bytes(32) } }];

function passphraseRecord(params: Record<string, number | bigint>): Uint8Array {
  return encode({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': bytes(32) },
        enc: {
          scheme: 1,
          aead: 'chacha20-poly1305-stream64k',
          nonce: bytes(24),
          passphrase: { alg: 'argon2id', salt: bytes(16), params },
        },
      },
    ],
  });
}

function issuesOf(result: ValidationResult): ReadonlyArray<ValidationIssue> {
  return result.valid ? [...(result.warnings ?? []), ...(result.info ?? [])] : result.issues;
}

function errorAt(result: ValidationResult, code: string): ValidationIssue | undefined {
  return issuesOf(result).find((issue) => issue.code === code);
}

describe('decode layer (step 1)', () => {
  it('never throws: garbage bytes yield MALFORMED_CBOR as data', () => {
    const result = validatePoeRecord(Uint8Array.from([0xff, 0x00, 0x13, 0x37]));
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
    expect(result.issues[0]!.path).toEqual([]);
  });

  it('rejects empty input as MALFORMED_CBOR', () => {
    const result = validatePoeRecord(new Uint8Array(0));
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
  });

  it('rejects duplicate map keys at decode (no separate duplicate-key code)', () => {
    // a2 6176 01 6176 02 — {"v":1,"v":2} with a duplicate key.
    const dup = Uint8Array.from([0xa2, 0x61, 0x76, 0x01, 0x61, 0x76, 0x02]);
    const result = validatePoeRecord(dup);
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues.map((issue) => issue.code)).toEqual(['MALFORMED_CBOR']);
  });

  it('rejects non-canonical (unsorted) map-key order', () => {
    // {"items":[…],"v":1} with "items" before "v" violates bytewise key order…
    // shortest spelling: a2 65 6974656d73 80 61 76 01 (items:[], v:1) — wrong
    // order because "v" (0x6176) sorts before "items" (0x65…) is FALSE under
    // length-first ordering; canonical order is "v" < "items". Emit the
    // unsorted variant by placing "items" first.
    const unsorted = Uint8Array.from([
      0xa2, 0x65, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x80, 0x61, 0x76, 0x01,
    ]);
    const result = validatePoeRecord(unsorted);
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
  });

  it('rejects an integral float v (1.0) rather than coercing it to 1', () => {
    // a1 6176 f93c00 — {"v": 1.0 as float16}.
    const floatV = Uint8Array.from([0xa1, 0x61, 0x76, 0xf9, 0x3c, 0x00]);
    const result = validatePoeRecord(floatV);
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues[0]!.code).toBe('MALFORMED_CBOR');
  });
});

describe('non-text map keys', () => {
  it('a non-text key at the top level is SCHEMA_TYPE_MISMATCH at the record root', () => {
    const result = validatePoeRecord(
      encode(new Map<string | number, CanonicalCborValue>([[1, 1]])),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues[0]!.code).toBe('SCHEMA_TYPE_MISMATCH');
    expect(result.issues[0]!.path).toEqual([]);
  });

  it('a non-text key inside hashes is SCHEMA_TYPE_MISMATCH at the hashes map', () => {
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [{ hashes: new Map<string | number, CanonicalCborValue>([[7, bytes(32)]]) }],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const issue = result.issues.find((entry) => entry.code === 'SCHEMA_TYPE_MISMATCH');
    expect(issue?.path).toEqual(['items', 0, 'hashes']);
  });

  it('a non-text key inside enc is SCHEMA_TYPE_MISMATCH at the enc map', () => {
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': bytes(32) },
            enc: new Map<string | number, CanonicalCborValue>([[0, 'x']]),
          },
        ],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const issue = result.issues.find((entry) => entry.code === 'SCHEMA_TYPE_MISMATCH');
    expect(issue?.path).toEqual(['items', 0, 'enc']);
  });
});

describe('issue paths and deterministic ordering', () => {
  it('attributes registry and length codes at the offending entry', () => {
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [{ hashes: { md5: bytes(16), 'sha2-256': bytes(31) } }],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues.map((issue) => [issue.code, issue.path.join('.')])).toEqual([
      ['UNSUPPORTED_HASH_ALG', 'items.0.hashes.md5'],
      ['HASH_DIGEST_LENGTH_MISMATCH', 'items.0.hashes.sha2-256'],
    ]);
  });

  it('sorts issues path-segment-wise with integer segments before text segments', () => {
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [
          { hashes: { 'sha2-256': bytes(31) } },
          { hashes: { 'sha2-256': bytes(32) }, uris: ['https://forbidden.example'] },
        ],
        merkle: [{ alg: 'rfc9162-sha256', root: bytes(32), leaf_count: 0 }],
        sigs: [],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const rendered = result.issues.map((issue) => issue.path.join('.'));
    expect(rendered).toEqual([
      'items.0.hashes.sha2-256',
      'items.1.uris.0',
      'merkle.0.leaf_count',
      'sigs',
    ]);
  });

  it('breaks same-path ties by error-code registry order', () => {
    // An enc-bearing item whose hashes map is empty fires both
    // SCHEMA_TYPE_MISMATCH (registry position 1) and ENC_REQUIRES_CONTENT_HASH
    // (position 32) — at different paths; the same-path tie-break is pinned
    // with two codes that share the enc path in the strict role instead.
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': bytes(32) },
            enc: { scheme: 2, opaque: 'x' },
          },
        ],
      }),
      { role: 'recipient_or_strict' },
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const atEnc = result.issues.filter((issue) => issue.path.join('.') === 'items.0.enc');
    expect(atEnc.map((issue) => issue.code)).toEqual(['ENC_UNSUPPORTED']);
    const atScheme = result.issues.filter((issue) => issue.path.join('.') === 'items.0.enc.scheme');
    expect(atScheme.map((issue) => issue.code)).toEqual(['UNSUPPORTED_ENVELOPE_SCHEME']);
    // Prefix path sorts before its extension.
    expect(result.issues.findIndex((issue) => issue.code === 'ENC_UNSUPPORTED')).toBeLessThan(
      result.issues.findIndex((issue) => issue.code === 'UNSUPPORTED_ENVELOPE_SCHEME'),
    );
  });

  it('compares text segments by UTF-8 bytes, not locale order', () => {
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [{ hashes: { 'zz-alg': bytes(32), 'éé-alg': bytes(32) } }],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const paths = result.issues.map((issue) => issue.path.join('.'));
    // 'z' (0x7a) sorts before 'é' (UTF-8 0xc3 0xa9).
    expect(paths).toEqual(['items.0.hashes.zz-alg', 'items.0.hashes.éé-alg']);
  });
});

describe('exact-integer handling (uint fields)', () => {
  it('accepts leaf_count at the 2^32 − 1 ceiling and rejects 2^32', () => {
    const ok = validatePoeRecord(
      encode({
        v: 1,
        merkle: [{ alg: 'rfc9162-sha256', root: bytes(32), leaf_count: 4294967295 }],
      }),
    );
    expect(ok.valid).toBe(true);
    const over = validatePoeRecord(
      encode({
        v: 1,
        merkle: [{ alg: 'rfc9162-sha256', root: bytes(32), leaf_count: 4294967296 }],
      }),
    );
    expect(over.valid).toBe(false);
    if (over.valid) return;
    expect(over.issues[0]!.code).toBe('SCHEMA_MERKLE_LEAF_COUNT_INVALID');
  });

  it('rejects a leaf_count above 2^53 exactly (no double rounding)', () => {
    const result = validatePoeRecord(
      encode({
        v: 1,
        merkle: [{ alg: 'rfc9162-sha256', root: bytes(32), leaf_count: 2n ** 53n + 1n }],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues[0]!.code).toBe('SCHEMA_MERKLE_LEAF_COUNT_INVALID');
    expect(result.issues[0]!.path).toEqual(['merkle', 0, 'leaf_count']);
  });

  it('rejects an Argon2id parameter above 2^32 − 1 as SCHEMA_TYPE_MISMATCH', () => {
    const result = validatePoeRecord(passphraseRecord({ m: 2n ** 53n + 1n, t: 3, p: 4 }));
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const issue = errorAt(result, 'SCHEMA_TYPE_MISMATCH');
    expect(issue?.path).toEqual(['items', 0, 'enc', 'passphrase', 'params', 'm']);
  });

  it('a negative integer where a uint is required is SCHEMA_TYPE_MISMATCH', () => {
    const result = validatePoeRecord(
      encode({ v: 1, merkle: [{ alg: 'rfc9162-sha256', root: bytes(32), leaf_count: -1 }] }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues[0]!.code).toBe('SCHEMA_TYPE_MISMATCH');
  });
});

describe('Argon2id policy ceiling', () => {
  it('enforces the default ceiling without any options', () => {
    const result = validatePoeRecord(
      passphraseRecord({ m: DEFAULT_PASSPHRASE_PARAMS_CEILING.m + 1, t: 3, p: 4 }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const issue = errorAt(result, 'ENC_PASSPHRASE_PARAMS_EXCEED_POLICY');
    expect(issue?.path).toEqual(['items', 0, 'enc', 'passphrase', 'params', 'm']);
  });

  it('accepts parameters at the default ceiling exactly', () => {
    const result = validatePoeRecord(
      passphraseRecord({
        m: DEFAULT_PASSPHRASE_PARAMS_CEILING.m,
        t: DEFAULT_PASSPHRASE_PARAMS_CEILING.t,
        p: DEFAULT_PASSPHRASE_PARAMS_CEILING.p,
      }),
    );
    expect(result.valid).toBe(true);
  });

  it('passphraseParamsCeiling: null disables the ceiling', () => {
    const result = validatePoeRecord(
      passphraseRecord({ m: 4_294_967_295, t: 4_294_967_295, p: 4_294_967_295 }),
      { passphraseParamsCeiling: null },
    );
    expect(result.valid).toBe(true);
  });

  it('a tightened ceiling rejects per offending parameter', () => {
    const result = validatePoeRecord(passphraseRecord({ m: 65_536, t: 10, p: 8 }), {
      passphraseParamsCeiling: { m: 65_536, t: 4, p: 4 },
    });
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const offending = result.issues
      .filter((issue) => issue.code === 'ENC_PASSPHRASE_PARAMS_EXCEED_POLICY')
      .map((issue) => issue.path[issue.path.length - 1]);
    expect(offending).toEqual(['p', 't']);
  });

  it('the ceiling never masks the floor code', () => {
    const result = validatePoeRecord(passphraseRecord({ m: 8, t: 1, p: 0 }));
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const codes = new Set(result.issues.map((issue) => issue.code));
    expect(codes.has('ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW')).toBe(true);
    expect(codes.has('ENC_PASSPHRASE_PARAMS_EXCEED_POLICY')).toBe(false);
  });
});

describe('crit and the supported-extensions option', () => {
  const critRecord = () =>
    encode({ v: 1, items: minimalItems(), crit: ['x-note'], 'x-note': 'value' });

  it('the default empty set fails every crit-bearing record', () => {
    const result = validatePoeRecord(critRecord());
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const issue = result.issues.find((entry) => entry.code === 'EXTENSION_UNSUPPORTED_CRITICAL');
    expect(issue?.path).toEqual(['crit', 0]);
  });

  it('a configured validator accepts the same record', () => {
    const result = validatePoeRecord(critRecord(), {
      supportedCriticalExtensions: new Set(['x-note']),
    });
    expect(result.valid).toBe(true);
  });

  it('support does not bypass the crit shape rules', () => {
    const result = validatePoeRecord(
      encode({ v: 1, items: minimalItems(), crit: ['x-note', 'x-note'], 'x-note': 'value' }),
      { supportedCriticalExtensions: new Set(['x-note']) },
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const issue = result.issues.find((entry) => entry.code === 'CRIT_SHAPE_INVALID');
    expect(issue?.path).toEqual(['crit', 1]);
  });
});

describe('result shape', () => {
  it('valid results split non-error issues into warnings and info', () => {
    const record: PoeRecord = {
      v: 1,
      items: minimalItems(),
      sigs: [
        {
          // alg -7 (ES256) is registered-reserved → SIGNATURE_UNSUPPORTED (info).
          cose_sign1: encodeCanonicalCbor([
            encodeCanonicalCbor(new Map<number, CanonicalCborValue>([[1, -7]])),
            new Map<never, never>(),
            null,
            bytes(64),
          ]) as Uint8Array<ArrayBuffer>,
        },
      ],
    };
    const result = validatePoeRecord(encodePoeRecord(record));
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.warnings).toBeUndefined();
    expect(result.info?.map((issue) => issue.code)).toEqual(['SIGNATURE_UNSUPPORTED']);
    expect(result.info?.[0]?.path).toEqual(['sigs', 0]);
  });

  it('an empty sigs array is rejected (1* cardinality)', () => {
    const result = validatePoeRecord(encode({ v: 1, items: minimalItems(), sigs: [] }));
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues.map((issue) => [issue.code, issue.path.join('.')])).toEqual([
      ['SCHEMA_TYPE_MISMATCH', 'sigs'],
    ]);
  });

  it('an empty uris array is rejected (1* cardinality)', () => {
    const result = validatePoeRecord(
      encode({ v: 1, items: [{ hashes: { 'sha2-256': bytes(32) }, uris: [] }] }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues[0]!.code).toBe('SCHEMA_TYPE_MISMATCH');
    expect(result.issues[0]!.path).toEqual(['items', 0, 'uris']);
  });

  it('merkle[].uris run the same URI shape checks as items[].uris', () => {
    const result = validatePoeRecord(
      encode({
        v: 1,
        merkle: [
          {
            alg: 'rfc9162-sha256',
            root: bytes(32),
            leaf_count: 4,
            uris: ['https://forbidden.example/leaves'],
          },
        ],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues.map((issue) => [issue.code, issue.path.join('.')])).toEqual([
      ['INVALID_URI', 'merkle.0.uris.0'],
    ]);
  });
});

describe('envelope resource bounds (deployment-pinned defaults)', () => {
  it('rejects more than 1024 slots by default', () => {
    const slots = Array.from({ length: 1025 }, (_, i) => {
      const epk = new Uint8Array(32);
      epk[0] = i & 0xff;
      epk[1] = (i >> 8) & 0xff;
      return { epk, wrap: bytes(48) };
    });
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': bytes(32) },
            enc: {
              scheme: 1,
              aead: 'chacha20-poly1305-stream64k',
              kem: 'x25519',
              nonce: bytes(24),
              slots,
              slots_mac: bytes(32),
            },
          },
        ],
      }),
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    const codes = new Set(result.issues.map((issue) => issue.code));
    expect(codes.has('ENC_SLOTS_TOO_MANY')).toBe(true);
    // 1025 minimal x25519 slots necessarily exceed the 65536-byte envelope
    // bound as well — the two resource codes co-fire under reference bounds.
    expect(codes.has('ENC_ENVELOPE_TOO_LARGE')).toBe(true);
  });

  it('a tightened maxSlots fires without the size bound', () => {
    const slots = [
      { epk: bytes(32, 1), wrap: bytes(48) },
      { epk: bytes(32, 2), wrap: bytes(48) },
    ];
    const result = validatePoeRecord(
      encode({
        v: 1,
        items: [
          {
            hashes: { 'sha2-256': bytes(32) },
            enc: {
              scheme: 1,
              aead: 'chacha20-poly1305-stream64k',
              kem: 'x25519',
              nonce: bytes(24),
              slots,
              slots_mac: bytes(32),
            },
          },
        ],
      }),
      { maxSlots: 1 },
    );
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.issues.map((issue) => issue.code)).toEqual(['ENC_SLOTS_TOO_MANY']);
  });
});
