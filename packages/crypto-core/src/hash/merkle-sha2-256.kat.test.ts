// KAT tests for the RFC 9162 §2.1.1 SHA-256 Merkle subsystem.
//
// Roots and inclusion proofs are driven by the shared cross-SDK conformance
// vectors under tests/fixtures/merkle/, so the TS / Python / Rust primitives
// assert against one byte-frozen source of truth:
//   - rfc9162-sha256-root-kat.json          — roots for tree sizes 1,2,3,4,5,7
//   - rfc9162-sha256-inclusion-proof-kat.json — per-leaf proofs for trees 1,4,7
// Proof coverage for the 2/3/5-leaf trees (not in the shared proof corpus) is
// asserted inline below.

import fs from 'node:fs';
import nodePath from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import {
  MERKLE_ALG_ID,
  merkleSha2256InclusionProof,
  merkleSha2256Root,
  merkleSha2256VerifyInclusion,
} from './merkle-sha2-256';

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

function leafD(i: number): Uint8Array {
  return sha256(enc.encode(`merkle-leaf-${i}`));
}

function loadFixture<T>(name: string): T {
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

interface RootKatVector {
  readonly name: string;
  readonly leaf_count: number;
  readonly leaves: ReadonlyArray<string>;
  readonly root: string;
}
interface RootKatCorpus {
  readonly version: number;
  readonly primitive: string;
  readonly alg: string;
  readonly vectors: ReadonlyArray<RootKatVector>;
}

interface InclusionKatLeaf {
  readonly index: number;
  readonly leaf: string;
  readonly proof: ReadonlyArray<string>;
}
interface InclusionKatTree {
  readonly name: string;
  readonly tree_size: number;
  readonly root: string;
  readonly leaves: ReadonlyArray<string>;
  readonly inclusions: ReadonlyArray<InclusionKatLeaf>;
}
interface InclusionKatCorpus {
  readonly version: number;
  readonly primitive: string;
  readonly alg: string;
  readonly trees: ReadonlyArray<InclusionKatTree>;
}

const rootKat = loadFixture<RootKatCorpus>('rfc9162-sha256-root-kat.json');
const inclusionKat = loadFixture<InclusionKatCorpus>('rfc9162-sha256-inclusion-proof-kat.json');

describe('algorithm identifier', () => {
  it('exports the canonical on-wire identifier', () => {
    expect(MERKLE_ALG_ID).toBe('rfc9162-sha256');
    expect(rootKat.alg).toBe(MERKLE_ALG_ID);
    expect(inclusionKat.alg).toBe(MERKLE_ALG_ID);
  });
});

describe('leaf inputs match the shared vector leaves (d_i = SHA-256("merkle-leaf-i"))', () => {
  // The largest fixture tree pins every distinct leaf digest used by the corpus.
  const widest = [...rootKat.vectors].sort((a, b) => b.leaf_count - a.leaf_count)[0]!;
  for (let i = 0; i < widest.leaves.length; i++) {
    it(`d_${i} matches the pinned leaf hex`, () => {
      expect(bytesToHex(leafD(i))).toBe(widest.leaves[i]);
    });
  }
});

describe('rfc9162-sha256 root KAT (shared corpus, tree sizes 1,2,3,4,5,7)', () => {
  for (const vector of rootKat.vectors) {
    it(`${vector.name} root matches the pinned hex`, () => {
      const leaves = vector.leaves.map((hex) => hexToBytes(hex));
      expect(leaves.length).toBe(vector.leaf_count);
      expect(bytesToHex(merkleSha2256Root(leaves))).toBe(vector.root);
    });
  }
});

describe('rfc9162-sha256 inclusion-proof KAT (shared corpus, trees 1,4,7)', () => {
  for (const tree of inclusionKat.trees) {
    describe(`${tree.name} (tree_size ${tree.tree_size})`, () => {
      const leaves = tree.leaves.map((hex) => hexToBytes(hex));
      const root = hexToBytes(tree.root);

      it('recomputes the pinned root from the leaves', () => {
        expect(bytesToHex(merkleSha2256Root(leaves))).toBe(tree.root);
      });

      for (const inc of tree.inclusions) {
        it(`inclusion proof[${inc.index}] matches the pinned siblings`, () => {
          const proof = merkleSha2256InclusionProof(leaves, inc.index);
          expect(proof.map(bytesToHex)).toEqual([...inc.proof]);
        });
        it(`verifyInclusion accepts proof[${inc.index}]`, () => {
          const proof = merkleSha2256InclusionProof(leaves, inc.index);
          expect(
            merkleSha2256VerifyInclusion(
              hexToBytes(inc.leaf),
              inc.index,
              tree.tree_size,
              proof,
              root,
            ),
          ).toBe(true);
        });
      }
    });
  }

  it('the single-leaf tree carries an empty proof', () => {
    const tree1 = inclusionKat.trees.find((t) => t.tree_size === 1)!;
    const leaves = tree1.leaves.map((hex) => hexToBytes(hex));
    expect(merkleSha2256InclusionProof(leaves, 0).length).toBe(0);
  });
});

// === 2/3/5-leaf inclusion proofs (odd-recursion edges absent from the shared
// proof corpus) — pinned inline against derived sibling node hashes. ===
describe('2-leaf tree inclusion proofs', () => {
  const leaves = [leafD(0), leafD(1)];
  const expectedProofs: Record<number, string[]> = {
    0: ['7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5'],
    1: ['b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc'],
  };

  for (let i = 0; i < 2; i++) {
    it(`inclusion proof[${i}] matches pinned siblings`, () => {
      const proof = merkleSha2256InclusionProof(leaves, i);
      expect(proof.map(bytesToHex)).toEqual(expectedProofs[i]);
    });
    it(`verifyInclusion accepts proof[${i}]`, () => {
      const proof = merkleSha2256InclusionProof(leaves, i);
      const root = merkleSha2256Root(leaves);
      expect(
        merkleSha2256VerifyInclusion(leaves[i] as Uint8Array, i, leaves.length, proof, root),
      ).toBe(true);
    });
  }
});

describe('3-leaf tree inclusion proofs (split 3 → 2+1)', () => {
  const leaves = [leafD(0), leafD(1), leafD(2)];
  const L1 = '7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5';
  const L0 = 'b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc';
  const L2 = '807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890';
  const H01 = 'f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee';
  const expectedProofs: Record<number, string[]> = {
    0: [L1, L2],
    1: [L0, L2],
    2: [H01],
  };

  for (let i = 0; i < 3; i++) {
    it(`inclusion proof[${i}] matches pinned siblings`, () => {
      const proof = merkleSha2256InclusionProof(leaves, i);
      expect(proof.map(bytesToHex)).toEqual(expectedProofs[i]);
    });
    it(`verifyInclusion accepts proof[${i}]`, () => {
      const proof = merkleSha2256InclusionProof(leaves, i);
      const root = merkleSha2256Root(leaves);
      expect(
        merkleSha2256VerifyInclusion(leaves[i] as Uint8Array, i, leaves.length, proof, root),
      ).toBe(true);
    });
  }
});

describe('5-leaf tree inclusion proofs (split 5 → 4+1)', () => {
  const leaves = [leafD(0), leafD(1), leafD(2), leafD(3), leafD(4)];
  const L0 = 'b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc';
  const L1 = '7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5';
  const L2 = '807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890';
  const L3 = '2c03e3ac9e4cf8ec8b505361e892e257ca59d91fa6a3b4741de9cd5962b62737';
  const L4 = '57fe46aac0fcd5d1392884b3523724bd145dcf9f70aa176318808ea56a9f8009';
  const H01 = 'f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee';
  const H23 = '1e4e22ce45fea38703a4c93994677fdb3b2602650c835bb7448c81a68a561363';
  const H0123 = '93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee';
  const expectedProofs: Record<number, string[]> = {
    0: [L1, H23, L4],
    1: [L0, H23, L4],
    2: [L3, H01, L4],
    3: [L2, H01, L4],
    4: [H0123],
  };

  for (let i = 0; i < 5; i++) {
    it(`inclusion proof[${i}] matches pinned siblings`, () => {
      const proof = merkleSha2256InclusionProof(leaves, i);
      expect(proof.map(bytesToHex)).toEqual(expectedProofs[i]);
    });
    it(`verifyInclusion accepts proof[${i}]`, () => {
      const proof = merkleSha2256InclusionProof(leaves, i);
      const root = merkleSha2256Root(leaves);
      expect(
        merkleSha2256VerifyInclusion(leaves[i] as Uint8Array, i, leaves.length, proof, root),
      ).toBe(true);
    });
  }
});

// === 16-leaf round-trip (power-of-2 wide tree, smoke check) ===
describe('16-leaf tree round-trip (root + per-leaf proof verify)', () => {
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < 16; i++) leaves.push(sha256(enc.encode(`wide-${i}`)));
  const root = merkleSha2256Root(leaves);

  for (let i = 0; i < 16; i++) {
    it(`verifyInclusion round-trips at index ${i}`, () => {
      const proof = merkleSha2256InclusionProof(leaves, i);
      expect(proof.length).toBe(4);
      expect(
        merkleSha2256VerifyInclusion(leaves[i] as Uint8Array, i, leaves.length, proof, root),
      ).toBe(true);
    });
  }
});

// === Input validation: root + inclusion proof ===
describe('input validation', () => {
  it('merkleSha2256Root rejects empty leaf list', () => {
    expect(() => merkleSha2256Root([])).toThrow(/empty leaf list/);
  });

  it('merkleSha2256Root rejects non-32-byte leaf', () => {
    expect(() => merkleSha2256Root([new Uint8Array(31)])).toThrow(/must be a Uint8Array\(32\)/);
    expect(() => merkleSha2256Root([new Uint8Array(33)])).toThrow(/must be a Uint8Array\(32\)/);
  });

  it('merkleSha2256Root rejects non-Uint8Array leaf', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => merkleSha2256Root(['notbytes' as any])).toThrow(/non-Uint8Array/);
  });

  it('merkleSha2256InclusionProof rejects empty leaf list', () => {
    expect(() => merkleSha2256InclusionProof([], 0)).toThrow(/empty leaf list/);
  });

  it('merkleSha2256InclusionProof rejects negative index', () => {
    expect(() => merkleSha2256InclusionProof([leafD(0)], -1)).toThrow(/out of range/);
  });

  it('merkleSha2256InclusionProof rejects index >= length', () => {
    expect(() => merkleSha2256InclusionProof([leafD(0), leafD(1)], 2)).toThrow(/out of range/);
  });

  it('merkleSha2256InclusionProof rejects non-integer index', () => {
    expect(() => merkleSha2256InclusionProof([leafD(0)], 0.5)).toThrow(/out of range/);
  });

  it('merkleSha2256InclusionProof rejects non-32-byte leaf', () => {
    expect(() => merkleSha2256InclusionProof([new Uint8Array(31)], 0)).toThrow(
      /must be a Uint8Array\(32\)/,
    );
  });
});

// === Negative verifier cases ===
describe('verifyInclusion negative cases', () => {
  const leaves = [leafD(0), leafD(1), leafD(2), leafD(3)];
  const root = merkleSha2256Root(leaves);

  it('rejects a wrong leaf', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    const wrongLeaf = sha256(enc.encode('not-in-tree'));
    expect(merkleSha2256VerifyInclusion(wrongLeaf, 1, 4, proof, root)).toBe(false);
  });

  it('rejects a tampered proof', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    const tampered = proof.map((s) => new Uint8Array(s));
    (tampered[0] as Uint8Array)[0] = ((tampered[0] as Uint8Array)[0] as number) ^ 0xff;
    expect(merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1, 4, tampered, root)).toBe(false);
  });

  it('rejects a tampered root', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    const tamperedRoot = new Uint8Array(root);
    tamperedRoot[0] = (tamperedRoot[0] as number) ^ 0xff;
    expect(merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1, 4, proof, tamperedRoot)).toBe(
      false,
    );
  });

  it('rejects when index is swapped to a different valid position', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    // proof was built for index 1; reusing it at index 2 must fail.
    expect(merkleSha2256VerifyInclusion(leaves[2] as Uint8Array, 2, 4, proof, root)).toBe(false);
  });

  it('throws RangeError when index is out of range for treeSize', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    expect(() => merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 4, 4, proof, root)).toThrow(
      RangeError,
    );
  });

  it('rejects non-32-byte leaf, root, or sibling input', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    expect(merkleSha2256VerifyInclusion(new Uint8Array(31), 1, 4, proof, root)).toBe(false);
    expect(
      merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1, 4, proof, new Uint8Array(31)),
    ).toBe(false);
    const badProof = [new Uint8Array(31), proof[1] as Uint8Array];
    expect(merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1, 4, badProof, root)).toBe(false);
  });

  it('rejects single-leaf proof that is not empty', () => {
    const leaf = leafD(0);
    const root1 = merkleSha2256Root([leaf]);
    expect(merkleSha2256VerifyInclusion(leaf, 0, 1, [new Uint8Array(32)], root1)).toBe(false);
  });

  it('rejects proof shorter than tree depth', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    expect(
      merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1, 4, [proof[0] as Uint8Array], root),
    ).toBe(false);
  });

  it('rejects proof longer than tree depth', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    const tooLong = [...proof, new Uint8Array(32)];
    expect(merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1, 4, tooLong, root)).toBe(false);
  });
});

// === Tampering parity with the reference negative checks ===
describe('CVE-2012-2459 prevention — leaf and internal-node prefixes differ', () => {
  it('1-leaf root != d_0 (leaf prefix byte 0x00 changes the digest)', () => {
    const d0 = leafD(0);
    const root1 = merkleSha2256Root([d0]);
    // The pinned single-leaf root is L0 != d_0.
    expect(bytesToHex(root1)).not.toBe(bytesToHex(d0));
  });
});

// === Tree-size / index range guard ===
// The verify fold uses 32-bit `>>> 1` arithmetic, so a tree_size at or above
// 2^32 would truncate inside the fold and could let a forged proof verify. The
// primitives reject the out-of-range domain up front (RangeError) rather than
// fold it. The on-chain commitment caps leaf_count at 2^32 - 1.
describe('tree-size / index range guard', () => {
  const MAX = 0xffffffff;
  const leaves = [leafD(0), leafD(1), leafD(2), leafD(3)];
  const root = merkleSha2256Root(leaves);

  it('throws when treeSize reaches 2^32 (the 32-bit fold boundary)', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    expect(() =>
      merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 0, MAX + 1, proof, root),
    ).toThrow(RangeError);
  });

  it('throws on a treeSize beyond the safe-integer range', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    expect(() =>
      merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 0, Number.MAX_VALUE, proof, root),
    ).toThrow(RangeError);
  });

  it('throws on a non-integer or negative treeSize / index', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    expect(() => merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1, 0, proof, root)).toThrow(
      RangeError,
    );
    expect(() => merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, -1, 4, proof, root)).toThrow(
      RangeError,
    );
    expect(() =>
      merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 1.5, 4, proof, root),
    ).toThrow(RangeError);
  });

  it('throws from the proof builder when index is out of range', () => {
    expect(() => merkleSha2256InclusionProof(leaves, 4)).toThrow(RangeError);
    expect(() => merkleSha2256InclusionProof(leaves, -1)).toThrow(RangeError);
  });
});
