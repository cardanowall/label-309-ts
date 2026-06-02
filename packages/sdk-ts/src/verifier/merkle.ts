// Merkle list-commitment verification.
//
// For each `record.merkle[i]` the verifier:
//   1. Acquires the leaves-list document (caller-supplied or fetched via the
//      first ar://-or-ipfs:// URI in `merkle[i].uris[]`).
//   2. Decodes the normative CBOR leaves-list wire form via crypto-core's
//      `decodeLeavesList` (which also recomputes the canonical RFC 9162 root
//      defence-in-depth and surfaces `MERKLE_ROOT_MISMATCH` /
//      `SCHEMA_MERKLE_LEAF_COUNT_MISMATCH`).
//   3. Compares the on-record `merkle[i].root` byte-exact to the recomputed
//      root via `compareCt`.
//
// Per-attempt URI failures are warnings (`URI_FETCH_FAILED`); the per-commit
// verdict on chain-exhaustion is `MERKLE_LEAVES_UNAVAILABLE` — a warning, NOT
// escalated to `'failed'`, because the on-chain root alone is structurally
// valid.

import { merkleSha2256Root } from '@cardanowall/crypto-core/hash';
import { decodeLeavesList, MerkleLeavesListError } from '@cardanowall/crypto-core/merkle';
import { compareCt } from '@cardanowall/crypto-core/util';
import type { MerkleCommit, PoeRecord } from '@cardanowall/poe-standard';

import { fetchItemCiphertext } from './fetch';
import type { FetchOutbound, VerifyMerkleCheck, VerifyTxInput, VerifyUriCheck } from './types';

export interface VerifyMerkleArgs {
  readonly record: PoeRecord;
  readonly input: VerifyTxInput;
  readonly fetchFn: FetchOutbound;
  readonly uriChecksOut: VerifyUriCheck[];
}

export interface VerifyMerkleResult {
  readonly checks: VerifyMerkleCheck[];
}

export async function verifyMerkleCommitments(args: VerifyMerkleArgs): Promise<VerifyMerkleResult> {
  const merkleArr = (args.record.merkle ?? []) as MerkleCommit[];
  const out: VerifyMerkleCheck[] = [];
  for (let i = 0; i < merkleArr.length; i++) {
    out.push(await verifyOneCommit(i, merkleArr[i]!, args));
  }
  return { checks: out };
}

async function verifyOneCommit(
  index: number,
  commit: MerkleCommit,
  args: VerifyMerkleArgs,
): Promise<VerifyMerkleCheck> {
  // v1 registers exactly one Merkle commitment algorithm. The structural
  // validator already rejects unknown algs; this is defence-in-depth.
  if (commit.alg !== 'rfc9162-sha256') {
    return {
      merkle_index: index,
      alg: commit.alg,
      verdict: 'unsupported',
      reason: 'UNSUPPORTED_MERKLE_COMMIT_ALG',
    };
  }

  // Leaves-list acquisition: caller-supplied bytes first, then the first
  // ar://-or-ipfs:// URI in `merkle[i].uris[]`.
  let leavesBytes: Uint8Array | null = args.input.merkleLeaves?.[index] ?? null;
  if (leavesBytes === null) {
    const uris = commit.uris;
    if (uris === undefined || uris.length === 0) {
      return {
        merkle_index: index,
        alg: commit.alg,
        verdict: 'unavailable',
        reason: 'MERKLE_LEAVES_UNAVAILABLE',
      };
    }
    try {
      leavesBytes = await fetchItemCiphertext({
        uris,
        arweaveGateways: args.input.arweaveGatewayChain,
        ipfsGateways: args.input.ipfsGatewayChain,
        fetchFn: args.fetchFn,
        uriChecksOut: args.uriChecksOut,
        // Merkle commits are not item-indexed; reuse a sentinel index so
        // downstream UIs can distinguish them from item URIs.
        itemIndex: -1 - index,
      });
    } catch {
      return {
        merkle_index: index,
        alg: commit.alg,
        verdict: 'unavailable',
        reason: 'MERKLE_LEAVES_UNAVAILABLE',
      };
    }
  }

  // Decode the leaves-list document. `decodeLeavesList` enforces format,
  // tree_alg, leaf-count match, and recomputes the root for defence-in-depth;
  // any failure surfaces as a typed error code.
  try {
    const decoded = decodeLeavesList(leavesBytes);
    // Compare the on-record root to the recomputed root byte-exact.
    const recomputed = merkleSha2256Root(decoded.leaves);
    if (!compareCt(recomputed, commit.root)) {
      return {
        merkle_index: index,
        alg: commit.alg,
        verdict: 'mismatch',
        reason: 'MERKLE_ROOT_MISMATCH',
        root_recomputed: recomputed,
      };
    }
    if (decoded.leafCount !== commit.leaf_count) {
      return {
        merkle_index: index,
        alg: commit.alg,
        verdict: 'mismatch',
        reason: 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH',
      };
    }
    return {
      merkle_index: index,
      alg: commit.alg,
      verdict: 'valid',
      root_recomputed: recomputed,
    };
  } catch (e) {
    if (e instanceof MerkleLeavesListError) {
      if (e.code === 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED') {
        return {
          merkle_index: index,
          alg: commit.alg,
          verdict: 'format-unsupported',
          reason: 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED',
        };
      }
      if (e.code === 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH') {
        return {
          merkle_index: index,
          alg: commit.alg,
          verdict: 'mismatch',
          reason: 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH',
        };
      }
      if (e.code === 'MERKLE_ROOT_MISMATCH') {
        return {
          merkle_index: index,
          alg: commit.alg,
          verdict: 'mismatch',
          reason: 'MERKLE_ROOT_MISMATCH',
        };
      }
      return {
        merkle_index: index,
        alg: commit.alg,
        verdict: 'unavailable',
        reason: e.code,
      };
    }
    return {
      merkle_index: index,
      alg: commit.alg,
      verdict: 'unavailable',
      reason: e instanceof Error ? e.message : String(e),
    };
  }
}
