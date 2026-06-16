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

// Shared cross-SDK positive KAT corpus. Each vector pins the canonical-CBOR
// leaves-list encoding both without and with the optional leaf_alg key, so the
// TS / Python / Rust codecs encode and decode byte-identically.
interface LeavesListKatVector {
  readonly name: string;
  readonly leaf_count: number;
  readonly root: string;
  readonly leaves: ReadonlyArray<string>;
  readonly cbor_hex_no_leaf_alg: string;
  readonly cbor_hex_with_leaf_alg: string;
  readonly leaf_alg: string;
}
interface LeavesListKatCorpus {
  readonly version: number;
  readonly primitive: string;
  readonly format: string;
  readonly vectors: ReadonlyArray<LeavesListKatVector>;
}

function loadMerkleFixture<T>(name: string): T {
  return JSON.parse(
    fs.readFileSync(
      nodePath.resolve(
        nodePath.dirname(fileURLToPath(import.meta.url)),
        `../../tests/fixtures/merkle/${name}`,
      ),
      'utf8',
    ),
  ) as T;
}

const leavesListKatCorpus = loadMerkleFixture<LeavesListKatCorpus>('leaves-list-kat.json');

describe('LEAVES_LIST_FORMAT_V1 constant', () => {
  it('exposes the wire literal', () => {
    expect(LEAVES_LIST_FORMAT_V1).toBe('cardano-poe-merkle-leaves-v1');
    expect(leavesListKatCorpus.format).toBe(LEAVES_LIST_FORMAT_V1);
  });
});

describe('encodeLeavesList / decodeLeavesList — shared cross-SDK positive KAT corpus', () => {
  for (const vector of leavesListKatCorpus.vectors) {
    const leaves = vector.leaves.map((hex) => hexToBytes(hex));

    it(`${vector.name}: recomputes the pinned root from the leaves`, () => {
      expect(leaves.length).toBe(vector.leaf_count);
      expect(bytesToHex(merkleSha2256Root(leaves))).toBe(vector.root);
    });

    it(`${vector.name}: encodes the pinned canonical CBOR (with leaf_alg)`, () => {
      const bytes = encodeLeavesList({
        leaves,
        root: hexToBytes(vector.root),
        leafAlg: vector.leaf_alg,
      });
      expect(bytesToHex(bytes)).toBe(vector.cbor_hex_with_leaf_alg);
    });

    it(`${vector.name}: encodes the pinned canonical CBOR (no leaf_alg)`, () => {
      const bytes = encodeLeavesList({ leaves, root: hexToBytes(vector.root) });
      expect(bytesToHex(bytes)).toBe(vector.cbor_hex_no_leaf_alg);
    });

    it(`${vector.name}: decodes the pinned CBOR back to the committed fields (with leaf_alg)`, () => {
      const decoded = decodeLeavesList(hexToBytes(vector.cbor_hex_with_leaf_alg));
      expect(decoded.format).toBe(LEAVES_LIST_FORMAT_V1);
      expect(decoded.treeAlg).toBe('rfc9162-sha256');
      expect(decoded.leafCount).toBe(vector.leaf_count);
      expect(decoded.leafAlg).toBe(vector.leaf_alg);
      expect(bytesToHex(decoded.root)).toBe(vector.root);
      expect(decoded.leaves.map((l) => bytesToHex(l))).toEqual([...vector.leaves]);
    });

    it(`${vector.name}: decodes the pinned CBOR back to the committed fields (no leaf_alg)`, () => {
      const decoded = decodeLeavesList(hexToBytes(vector.cbor_hex_no_leaf_alg));
      expect(decoded.leafAlg).toBeUndefined();
      expect(decoded.leafCount).toBe(vector.leaf_count);
      expect(bytesToHex(decoded.root)).toBe(vector.root);
      expect(decoded.leaves.map((l) => bytesToHex(l))).toEqual([...vector.leaves]);
    });

    it(`${vector.name}: encode(decode(cbor)) round-trips to the same bytes`, () => {
      const decoded = decodeLeavesList(hexToBytes(vector.cbor_hex_with_leaf_alg));
      expect(decoded.leafAlg).toBe(vector.leaf_alg);
      const reencoded = encodeLeavesList({
        leaves: decoded.leaves,
        root: decoded.root,
        leafAlg: vector.leaf_alg,
      });
      expect(bytesToHex(reencoded)).toBe(vector.cbor_hex_with_leaf_alg);
    });
  }
});

describe('encodeLeavesList — additional round-trip coverage', () => {
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
