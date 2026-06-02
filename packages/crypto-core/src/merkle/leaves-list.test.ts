// Tests for the canonical-CBOR leaves-list codec.
// Byte-pinned against the reference 275-byte canonical-CBOR fixture; the
// codec follows the CDDL definition and bytewise leaf ordering.

import fs from 'node:fs';
import nodePath from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { merkleSha2256Root } from '../hash/merkle-sha2-256';
import { encodeCanonicalCbor } from '../cbor/canonical';

import {
  LEAVES_LIST_FORMAT_V1,
  MerkleLeavesListError,
  decodeLeavesList,
  encodeLeavesList,
} from './leaves-list';

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (bytes[i] as number).toString(16).padStart(2, '0');
  return s;
}

const enc = new TextEncoder();
const leafD = (i: number): Uint8Array => sha256(enc.encode(`merkle-leaf-${i}`));

// Pinned 275-byte canonical-CBOR leaves-list reference fixture.
const PINNED_CBOR_HEX =
  'a664726f6f74582093a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee' +
  '66666f726d6174781c63617264616e6f2d706f652d6d65726b6c652d6c65617665732d7631666c65' +
  '61766573845820b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c58' +
  '20986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56582027f4c2b715' +
  '7b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc582049707d9c71d5ebf72aaa3a' +
  'da7a34e152d41811b345366681fc09849e8c634076686c6561665f616c6768736861322d32353668' +
  '747265655f616c676e726663393136322d7368613235366a6c6561665f636f756e7404';

const PINNED_ROOT_HEX = '93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee';

describe('LEAVES_LIST_FORMAT_V1 constant', () => {
  it('exposes the wire literal', () => {
    expect(LEAVES_LIST_FORMAT_V1).toBe('cardano-poe-merkle-leaves-v1');
  });
});

describe('encodeLeavesList — byte-pin against reference fixture', () => {
  it('emits the pinned 275-byte canonical CBOR for the 4-leaf fixture', () => {
    const leaves = [leafD(0), leafD(1), leafD(2), leafD(3)];
    const root = merkleSha2256Root(leaves);
    expect(bytesToHex(root)).toBe(PINNED_ROOT_HEX);
    const bytes = encodeLeavesList({ leaves, root, leafAlg: 'sha2-256' });
    expect(bytes.length).toBe(275);
    expect(bytesToHex(bytes)).toBe(PINNED_CBOR_HEX);
  });

  it('emits canonical CBOR for a minimal (single-leaf) tree without leaf_alg', () => {
    const leaves = [leafD(0)];
    const root = merkleSha2256Root(leaves);
    const bytes = encodeLeavesList({ leaves, root });
    // Round-trips through the codec to itself.
    const decoded = decodeLeavesList(bytes);
    expect(decoded.leafAlg).toBeUndefined();
    expect(decoded.leafCount).toBe(1);
    expect(bytesToHex(decoded.root)).toBe(bytesToHex(root));
  });

  it('encode → decode round-trip preserves all fields (4-leaf with leaf_alg)', () => {
    const leaves = [leafD(0), leafD(1), leafD(2), leafD(3)];
    const root = merkleSha2256Root(leaves);
    const bytes = encodeLeavesList({ leaves, root, leafAlg: 'sha2-256' });
    const decoded = decodeLeavesList(bytes);
    expect(decoded.format).toBe(LEAVES_LIST_FORMAT_V1);
    expect(decoded.treeAlg).toBe('rfc9162-sha256');
    expect(decoded.leafCount).toBe(4);
    expect(decoded.leafAlg).toBe('sha2-256');
    expect(bytesToHex(decoded.root)).toBe(bytesToHex(root));
    expect(decoded.leaves.length).toBe(4);
    for (let i = 0; i < 4; i++) {
      expect(bytesToHex(decoded.leaves[i] as Uint8Array)).toBe(bytesToHex(leaves[i] as Uint8Array));
    }
  });

  it('encode → decode round-trip for a 16-leaf tree', () => {
    const leaves: Uint8Array[] = [];
    for (let i = 0; i < 16; i++) leaves.push(sha256(enc.encode(`wide-${i}`)));
    const root = merkleSha2256Root(leaves);
    const bytes = encodeLeavesList({ leaves, root });
    const decoded = decodeLeavesList(bytes);
    expect(decoded.leafCount).toBe(16);
    expect(bytesToHex(decoded.root)).toBe(bytesToHex(root));
  });
});

describe('encodeLeavesList — input validation', () => {
  it('rejects empty leaves array', () => {
    const root = new Uint8Array(32);
    expect(() => encodeLeavesList({ leaves: [], root })).toThrow(MerkleLeavesListError);
  });

  it('rejects non-32-byte leaf', () => {
    const leaves = [new Uint8Array(31)];
    const root = new Uint8Array(32);
    expect(() => encodeLeavesList({ leaves, root })).toThrow(/Uint8Array\(32\)/);
  });

  it('rejects non-32-byte root', () => {
    const leaves = [leafD(0)];
    expect(() => encodeLeavesList({ leaves, root: new Uint8Array(31) })).toThrow(
      /Uint8Array\(32\)/,
    );
  });

  it('rejects non-string leaf_alg', () => {
    const leaves = [leafD(0)];
    const root = merkleSha2256Root(leaves);
    expect(() =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      encodeLeavesList({ leaves, root, leafAlg: 123 as any }),
    ).toThrow(/leaf_alg/);
  });
});

describe('decodeLeavesList — byte-pin parse of reference fixture', () => {
  it('decodes the pinned 275-byte canonical CBOR', () => {
    const decoded = decodeLeavesList(hexToBytes(PINNED_CBOR_HEX));
    expect(decoded.format).toBe(LEAVES_LIST_FORMAT_V1);
    expect(decoded.treeAlg).toBe('rfc9162-sha256');
    expect(bytesToHex(decoded.root)).toBe(PINNED_ROOT_HEX);
    expect(decoded.leafCount).toBe(4);
    expect(decoded.leafAlg).toBe('sha2-256');
    expect(decoded.leaves.length).toBe(4);
    const expectedLeaves = [
      'b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c',
      '986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56',
      '27f4c2b7157b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc',
      '49707d9c71d5ebf72aaa3ada7a34e152d41811b345366681fc09849e8c634076',
    ];
    for (let i = 0; i < 4; i++) {
      expect(bytesToHex(decoded.leaves[i] as Uint8Array)).toBe(expectedLeaves[i]);
    }
  });
});

describe('decodeLeavesList — schema rejection', () => {
  function encodeMap(map: Record<string, unknown>): Uint8Array {
    return encodeCanonicalCbor(map as never);
  }

  it('rejects unknown format with SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED', () => {
    const leaves = [leafD(0)];
    const root = merkleSha2256Root(leaves);
    const bytes = encodeMap({
      format: 'cardano-poe-merkle-leaves-v0',
      tree_alg: 'rfc9162-sha256',
      root,
      leaves,
      leaf_count: 1,
    });
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED');
    }
  });

  it('rejects leaf_count mismatch with SCHEMA_MERKLE_LEAF_COUNT_MISMATCH', () => {
    const leaves = [leafD(0), leafD(1)];
    const root = merkleSha2256Root(leaves);
    const bytes = encodeMap({
      format: LEAVES_LIST_FORMAT_V1,
      tree_alg: 'rfc9162-sha256',
      root,
      leaves,
      leaf_count: 3, // mismatch — actual is 2
    });
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('SCHEMA_MERKLE_LEAF_COUNT_MISMATCH');
    }
  });

  it('rejects wrong tree_alg with SCHEMA_MERKLE_LEAVES_MALFORMED', () => {
    const leaves = [leafD(0)];
    const root = merkleSha2256Root(leaves);
    const bytes = encodeMap({
      format: LEAVES_LIST_FORMAT_V1,
      tree_alg: 'something-else',
      root,
      leaves,
      leaf_count: 1,
    });
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('SCHEMA_MERKLE_LEAVES_MALFORMED');
    }
  });

  it('rejects root that does not match recomputed Merkle root with MERKLE_ROOT_MISMATCH', () => {
    const leaves = [leafD(0), leafD(1)];
    const fakeRoot = new Uint8Array(32);
    fakeRoot.fill(0xab);
    const bytes = encodeMap({
      format: LEAVES_LIST_FORMAT_V1,
      tree_alg: 'rfc9162-sha256',
      root: fakeRoot,
      leaves,
      leaf_count: 2,
    });
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('MERKLE_ROOT_MISMATCH');
    }
  });

  it('rejects non-map top-level CBOR', () => {
    const bytes = encodeCanonicalCbor(['not-a-map']);
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('SCHEMA_MERKLE_LEAVES_MALFORMED');
    }
  });

  it('rejects empty leaves array', () => {
    const bytes = encodeMap({
      format: LEAVES_LIST_FORMAT_V1,
      tree_alg: 'rfc9162-sha256',
      root: new Uint8Array(32),
      leaves: [] as Uint8Array[],
      leaf_count: 0,
    });
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('SCHEMA_MERKLE_LEAVES_MALFORMED');
    }
  });

  it('rejects root that is not 32 bytes', () => {
    const bytes = encodeMap({
      format: LEAVES_LIST_FORMAT_V1,
      tree_alg: 'rfc9162-sha256',
      root: new Uint8Array(31),
      leaves: [leafD(0)],
      leaf_count: 1,
    });
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('SCHEMA_MERKLE_LEAVES_MALFORMED');
    }
  });

  it('rejects leaf that is not 32 bytes', () => {
    const bytes = encodeMap({
      format: LEAVES_LIST_FORMAT_V1,
      tree_alg: 'rfc9162-sha256',
      root: new Uint8Array(32),
      leaves: [new Uint8Array(31)],
      leaf_count: 1,
    });
    try {
      decodeLeavesList(bytes);
      expect.fail('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MerkleLeavesListError);
      expect((err as MerkleLeavesListError).code).toBe('SCHEMA_MERKLE_LEAVES_MALFORMED');
    }
  });
});

// Shared cross-SDK leaves-list negative KAT corpus. Each vector pins the exact
// error code `decodeLeavesList` throws for a byte-frozen CBOR document, keeping
// the TS / Python / Rust codecs code-for-code identical (notably the
// non-rfc9162 `tree_alg` reject → SCHEMA_MERKLE_LEAVES_MALFORMED).
interface LeavesListNegativeVector {
  readonly name: string;
  readonly cbor_hex: string;
  readonly expected_error_code: string;
}
interface LeavesListNegativeCorpus {
  readonly version: number;
  readonly primitive: string;
  readonly vectors: ReadonlyArray<LeavesListNegativeVector>;
}

const leavesListNegativeCorpus = JSON.parse(
  fs.readFileSync(
    nodePath.resolve(
      nodePath.dirname(fileURLToPath(import.meta.url)),
      '../../tests/fixtures/merkle/leaves-list-negative.json',
    ),
    'utf8',
  ),
) as LeavesListNegativeCorpus;

describe('decodeLeavesList — shared cross-SDK negative KAT corpus', () => {
  for (const vector of leavesListNegativeCorpus.vectors) {
    it(`${vector.name} → ${vector.expected_error_code}`, () => {
      try {
        decodeLeavesList(hexToBytes(vector.cbor_hex));
        expect.fail(`expected ${vector.expected_error_code} to be thrown`);
      } catch (err) {
        expect(err).toBeInstanceOf(MerkleLeavesListError);
        expect((err as MerkleLeavesListError).code).toBe(vector.expected_error_code);
      }
    });
  }
});
