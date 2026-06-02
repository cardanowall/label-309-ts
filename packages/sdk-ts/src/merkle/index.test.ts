// Smoke test for the public `@cardanowall/sdk-ts/merkle` namespace.
//
// Asserts that every re-export resolves and that a tiny 4-leaf round-trip
// (root → inclusion proof → verify) succeeds. The deep KAT coverage already
// lives in @cardanowall/crypto-core — we do NOT duplicate that surface here;
// the only contract this file owns is "the SDK re-export barrel is correctly
// wired."

import { describe, expect, it } from 'vitest';

import {
  merkleSha2256Root,
  merkleSha2256InclusionProof,
  merkleSha2256VerifyInclusion,
  MERKLE_ALG_ID,
  encodeLeavesList,
  decodeLeavesList,
  LEAVES_LIST_FORMAT_V1,
  MerkleLeavesListError,
} from './index';
import { sha2256 } from '../hash/index';

function makeLeaf(seed: number): Uint8Array {
  const buf = new Uint8Array(32);
  buf[0] = seed & 0xff;
  return sha2256(buf);
}

describe('@cardanowall/sdk-ts/merkle re-export barrel', () => {
  it('exposes the RFC 9162 alg identifier and leaves-list format constant', () => {
    expect(MERKLE_ALG_ID).toBe('rfc9162-sha256');
    expect(LEAVES_LIST_FORMAT_V1).toBe('cardano-poe-merkle-leaves-v1');
  });

  it('round-trips a 4-leaf tree: root → proof → verify', () => {
    const leaves = [makeLeaf(0), makeLeaf(1), makeLeaf(2), makeLeaf(3)];
    const root = merkleSha2256Root(leaves);
    expect(root).toBeInstanceOf(Uint8Array);
    expect(root.length).toBe(32);

    for (let i = 0; i < leaves.length; i++) {
      const proof = merkleSha2256InclusionProof(leaves, i);
      // RFC 9162 audit-path length for a 4-leaf tree is log2(4) = 2.
      expect(proof.length).toBe(2);
      const ok = merkleSha2256VerifyInclusion(leaves[i]!, i, leaves.length, proof, root);
      expect(ok).toBe(true);
    }
  });

  it('encodes + decodes a leaves-list and surfaces typed errors', () => {
    const leaves = [makeLeaf(10), makeLeaf(11)];
    const root = merkleSha2256Root(leaves);
    const cbor = encodeLeavesList({ leaves, root });
    const decoded = decodeLeavesList(cbor);
    expect(decoded.format).toBe(LEAVES_LIST_FORMAT_V1);
    expect(decoded.treeAlg).toBe('rfc9162-sha256');
    expect(decoded.leafCount).toBe(2);
    expect(decoded.leaves).toHaveLength(2);

    // Negative path — valid CBOR but the top-level value is an array, not
    // the required leaves-list map. Surfaces the typed error class with the
    // SCHEMA_MERKLE_LEAVES_INVALID_SHAPE code from
    // `crypto-core/src/merkle/leaves-list.ts`.
    const wrongTopLevelCbor = new Uint8Array([0x80]); // CBOR `[]`
    expect(() => decodeLeavesList(wrongTopLevelCbor)).toThrow(MerkleLeavesListError);
  });
});
