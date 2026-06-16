// RFC 9162 §2.1.1 binary Merkle tree under SHA-256.
// This implements the algorithm tier identified on the wire as the
// `rfc9162-sha256` OPT-INFO; the record's `merkle[]` field carries the proof.
//
// Construction (RFC 9162 §2.1.1):
//   - Single leaf:   MTH({d_0})     = SHA-256(0x00 || d_0)
//   - Internal node: MTH(L)         = SHA-256(0x01 || MTH(L[0:k]) || MTH(L[k:n]))
//     where k = largest power of 2 strictly less than n.
//   - Empty trees (n == 0) are FORBIDDEN.
//   - The 0x00 leaf / 0x01 internal prefixes prevent the CVE-2012-2459
//     leaf-vs-internal collision family.

import { sha256 } from '@noble/hashes/sha2.js';

import { compareCt } from '../util/compare-ct';

export const MERKLE_ALG_ID = 'rfc9162-sha256' as const;

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
const DIGEST_LENGTH = 32;

// The verify fold tracks the leaf index and subtree size with `>>> 1` (an
// unsigned 32-bit shift). That arithmetic is only exact while both values stay
// within 32 bits, so the algorithm's safe domain is `1 <= treeSize <= 2^32 - 1`
// (and `0 <= index < treeSize`). A `treeSize` at or above 2^32 silently
// truncates inside the fold, which would let a forged proof verify against the
// wrong subtree shape. We therefore reject the whole out-of-range domain up
// front rather than fold it. The on-chain commitment caps `leaf_count` at the
// same `2^32 - 1`, so no legitimate tree is excluded.
const MAX_TREE_SIZE = 0xffffffff;

// Reject an out-of-range (index, treeSize) pair as a structural error. The
// parity twins in the Python and Rust SDKs must mirror this guard so a forged
// oversized `tree_size` is refused identically across all implementations.
function validateTreeRange(index: number, treeSize: number, fnName: string): void {
  if (!Number.isSafeInteger(treeSize) || treeSize < 1 || treeSize > MAX_TREE_SIZE) {
    throw new RangeError(`${fnName}: treeSize ${treeSize} out of range [1, ${MAX_TREE_SIZE}]`);
  }
  if (!Number.isSafeInteger(index) || index < 0 || index >= treeSize) {
    throw new RangeError(`${fnName}: index ${index} out of range [0, ${treeSize})`);
  }
}

function validateLeaves(leaves: ReadonlyArray<Uint8Array>, fnName: string): void {
  if (leaves.length === 0) {
    throw new Error(`${fnName}: empty leaf list (n == 0 is forbidden by RFC 9162 §2.1.1)`);
  }
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i];
    if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) {
      throw new Error(
        `${fnName}: leaf[${i}] must be a Uint8Array(${DIGEST_LENGTH}); got length ${
          leaf instanceof Uint8Array ? leaf.length : 'non-Uint8Array'
        }`,
      );
    }
  }
}

export function merkleSha2256Root(leaves: ReadonlyArray<Uint8Array>): Uint8Array {
  validateLeaves(leaves, 'merkleSha2256Root');
  return mthRecursive(leaves, 0, leaves.length);
}

export function merkleSha2256InclusionProof(
  leaves: ReadonlyArray<Uint8Array>,
  index: number,
): Uint8Array[] {
  validateLeaves(leaves, 'merkleSha2256InclusionProof');
  validateTreeRange(index, leaves.length, 'merkleSha2256InclusionProof');
  return auditPath(leaves, index, 0, leaves.length);
}

/**
 * Verify an inclusion proof per RFC 9162 §2.1.3.2 (iterative form).
 *
 * `proof` is ordered leaf-to-root: `proof[0]` is the sibling at the leaf
 * level, `proof[m-1]` is the top-level sibling. The fold uses the
 * `sn`/`fn` tracking from RFC 9162: `sn` is the leaf index within the
 * current subtree, `fn` is (subtree_size - 1). At each step, `sn` odd
 * OR `sn == fn` means the current node is a right child (sibling on
 * the left); otherwise it is a left child (sibling on the right).
 * Both shift right by one each iteration. This handles non-power-of-2
 * sizes including the "promote a lone right subtree" cases.
 */
export function merkleSha2256VerifyInclusion(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  proof: ReadonlyArray<Uint8Array>,
  root: Uint8Array,
): boolean {
  // Out-of-range (index, treeSize) is a structural error, not a "does not
  // verify" verdict: the fold's 32-bit shift arithmetic is undefined outside
  // the safe domain, so we refuse it rather than return a (potentially forged)
  // boolean. Byte-shape problems below are genuine non-verification (false).
  validateTreeRange(index, treeSize, 'merkleSha2256VerifyInclusion');
  if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) return false;
  if (!(root instanceof Uint8Array) || root.length !== DIGEST_LENGTH) return false;
  for (let i = 0; i < proof.length; i++) {
    const sibling = proof[i];
    if (!(sibling instanceof Uint8Array) || sibling.length !== DIGEST_LENGTH) {
      return false;
    }
  }

  if (treeSize === 1) {
    if (proof.length !== 0 || index !== 0) return false;
    return compareCt(hashLeaf(leaf), root);
  }

  let h = hashLeaf(leaf);
  let sn = index;
  let fn = treeSize - 1;
  for (let i = 0; i < proof.length; i++) {
    if (fn === 0) return false;
    const sibling = proof[i] as Uint8Array;
    if ((sn & 1) === 1 || sn === fn) {
      h = hashNode(sibling, h);
      while ((sn & 1) === 0 && sn !== 0) {
        sn >>>= 1;
        fn >>>= 1;
      }
    } else {
      h = hashNode(h, sibling);
    }
    sn >>>= 1;
    fn >>>= 1;
  }
  if (fn !== 0) return false;
  return compareCt(h, root);
}

function largestPow2Lt(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function hashLeaf(d: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + d.length);
  buf[0] = LEAF_PREFIX;
  buf.set(d, 1);
  return sha256(buf);
}

function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = NODE_PREFIX;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

function mthRecursive(leaves: ReadonlyArray<Uint8Array>, start: number, end: number): Uint8Array {
  const n = end - start;
  if (n === 1) {
    return hashLeaf(leaves[start] as Uint8Array);
  }
  const k = largestPow2Lt(n);
  const left = mthRecursive(leaves, start, start + k);
  const right = mthRecursive(leaves, start + k, end);
  return hashNode(left, right);
}

function auditPath(
  leaves: ReadonlyArray<Uint8Array>,
  i: number,
  start: number,
  end: number,
): Uint8Array[] {
  const n = end - start;
  if (n === 1) return [];
  const k = largestPow2Lt(n);
  if (i < k) {
    const subPath = auditPath(leaves, i, start, start + k);
    subPath.push(mthRecursive(leaves, start + k, end));
    return subPath;
  }
  const subPath = auditPath(leaves, i - k, start + k, end);
  subPath.push(mthRecursive(leaves, start, start + k));
  return subPath;
}
