// KAT tests for the RFC 9162 §2.1.1 SHA-256 Merkle subsystem.
// Vectors: the 4-leaf reference tree plus 1/2/3/5/7-leaf canonical trees,
// inlined byte-for-byte. These are not yet mirrored into a JSON fixture
// under tests/fixtures/merkle/.

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

// Inlined d_i pins for the reference trees (i = 0..6).
const PINNED_DI: Record<number, string> = {
  0: 'b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c',
  1: '986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56',
  2: '27f4c2b7157b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc',
  3: '49707d9c71d5ebf72aaa3ada7a34e152d41811b345366681fc09849e8c634076',
  4: 'e1599f1d13ee839f0fe64c2d5697b9d098ea947053f2fd8033e93b5ea1da8970',
  5: '7777a46ef6264ec24caf8239bea80bd6b3b1e38e9d3dc4f9daf6ce3722e8ba02',
  6: '741c8f1001d6e807fac74c182d15f01fba2ed98375ca7a7cdc6257fdae97b621',
};

describe('algorithm identifier', () => {
  it('exports the canonical on-wire identifier', () => {
    expect(MERKLE_ALG_ID).toBe('rfc9162-sha256');
  });
});

describe('leaf inputs match pinned d_i values', () => {
  for (let i = 0; i <= 6; i++) {
    it(`d_${i} matches pinned hex`, () => {
      expect(bytesToHex(leafD(i))).toBe(PINNED_DI[i]);
    });
  }
});

// === 1-leaf tree ===
describe('1-leaf tree', () => {
  const leaves = [leafD(0)];
  const expectedRoot = 'b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc';

  it('root matches pinned hex', () => {
    expect(bytesToHex(merkleSha2256Root(leaves))).toBe(expectedRoot);
  });

  it('inclusion proof at index 0 is empty', () => {
    const proof = merkleSha2256InclusionProof(leaves, 0);
    expect(proof.length).toBe(0);
  });

  it('verifyInclusion accepts the empty-path proof', () => {
    const proof = merkleSha2256InclusionProof(leaves, 0);
    const root = merkleSha2256Root(leaves);
    expect(merkleSha2256VerifyInclusion(leaves[0] as Uint8Array, 0, 1, proof, root)).toBe(true);
  });
});

// === 2-leaf tree ===
describe('2-leaf tree', () => {
  const leaves = [leafD(0), leafD(1)];
  const expectedRoot = 'f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee';
  const expectedProofs: Record<number, string[]> = {
    0: ['7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5'],
    1: ['b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc'],
  };

  it('root matches pinned hex', () => {
    expect(bytesToHex(merkleSha2256Root(leaves))).toBe(expectedRoot);
  });

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

// === 3-leaf tree ===
describe('3-leaf tree (split 3 → 2+1)', () => {
  const leaves = [leafD(0), leafD(1), leafD(2)];
  const expectedRoot = '2c5230105235655a072f552fddcbc78bf5a76e16476c882e8199f9fce20a8f55';
  const L1 = '7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5';
  const L0 = 'b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc';
  const L2 = '807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890';
  const H01 = 'f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee';
  const expectedProofs: Record<number, string[]> = {
    0: [L1, L2],
    1: [L0, L2],
    2: [H01],
  };

  it('root matches pinned hex', () => {
    expect(bytesToHex(merkleSha2256Root(leaves))).toBe(expectedRoot);
  });

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

// === 4-leaf tree (baseline) ===
describe('4-leaf tree (baseline, split 4 → 2+2)', () => {
  const leaves = [leafD(0), leafD(1), leafD(2), leafD(3)];
  const expectedRoot = '93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee';
  const L0 = 'b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc';
  const L1 = '7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5';
  const L2 = '807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890';
  const L3 = '2c03e3ac9e4cf8ec8b505361e892e257ca59d91fa6a3b4741de9cd5962b62737';
  const H01 = 'f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee';
  const H23 = '1e4e22ce45fea38703a4c93994677fdb3b2602650c835bb7448c81a68a561363';
  const expectedProofs: Record<number, string[]> = {
    0: [L1, H23],
    1: [L0, H23],
    2: [L3, H01],
    3: [L2, H01],
  };

  it('root matches pinned hex', () => {
    expect(bytesToHex(merkleSha2256Root(leaves))).toBe(expectedRoot);
  });

  for (let i = 0; i < 4; i++) {
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

// === 5-leaf tree (odd recursion edge) ===
describe('5-leaf tree (split 5 → 4+1)', () => {
  const leaves = [leafD(0), leafD(1), leafD(2), leafD(3), leafD(4)];
  const expectedRoot = '03928445a6003ca5f6a925cddb04a508116b06cf80037dca9e579ed41122fb9f';
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

  it('root matches pinned hex', () => {
    expect(bytesToHex(merkleSha2256Root(leaves))).toBe(expectedRoot);
  });

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

// === 7-leaf tree (two levels of odd-leaf recursion) ===
describe('7-leaf tree (split 7 → 4+3; right subtree splits 3 → 2+1)', () => {
  const leaves = [leafD(0), leafD(1), leafD(2), leafD(3), leafD(4), leafD(5), leafD(6)];
  const expectedRoot = '90306bf5dca8f89e7b253471148f3795e7a6c857f04924c8309d81375e79d987';
  const L0 = 'b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc';
  const L1 = '7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5';
  const L2 = '807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890';
  const L3 = '2c03e3ac9e4cf8ec8b505361e892e257ca59d91fa6a3b4741de9cd5962b62737';
  const L4 = '57fe46aac0fcd5d1392884b3523724bd145dcf9f70aa176318808ea56a9f8009';
  const L5 = 'f03cea80d0e99780698a755e4684555e821c2af821f97058926caf8e2d7d2969';
  const L6 = '5bd8bd33c7e3c41a98511068b7dfea418b5a6c84ff53767a1c7c0565efb651f4';
  const H01 = 'f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee';
  const H23 = '1e4e22ce45fea38703a4c93994677fdb3b2602650c835bb7448c81a68a561363';
  const H45 = '02c09225565b2fb10fd263edc6951200c743b9121192f68ba7967ffc8a6f1128';
  const H0123 = '93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee';
  const expectedProofs: Record<number, string[]> = {
    0: [L1, H23, '32f86b4111e8859b214cf501d1091023da954f169d8916dce42aa469c5795d17'],
    1: [L0, H23, '32f86b4111e8859b214cf501d1091023da954f169d8916dce42aa469c5795d17'],
    2: [L3, H01, '32f86b4111e8859b214cf501d1091023da954f169d8916dce42aa469c5795d17'],
    3: [L2, H01, '32f86b4111e8859b214cf501d1091023da954f169d8916dce42aa469c5795d17'],
    4: [L5, L6, H0123],
    5: [L4, L6, H0123],
    6: [H45, H0123],
  };

  it('root matches pinned hex', () => {
    expect(bytesToHex(merkleSha2256Root(leaves))).toBe(expectedRoot);
  });

  for (let i = 0; i < 7; i++) {
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

  it('rejects when index is out of range for treeSize', () => {
    const proof = merkleSha2256InclusionProof(leaves, 1);
    expect(merkleSha2256VerifyInclusion(leaves[1] as Uint8Array, 4, 4, proof, root)).toBe(false);
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

// === Hex fixture pin sanity — the inlined PINNED_DI ===
describe('inlined PINNED_DI sanity', () => {
  it('exposes pinned bytes for indices 0..6', () => {
    const hexes = Object.values(PINNED_DI);
    for (const h of hexes) expect(h.length).toBe(64);
    expect(hexToBytes(PINNED_DI[0] as string).length).toBe(32);
  });
});
