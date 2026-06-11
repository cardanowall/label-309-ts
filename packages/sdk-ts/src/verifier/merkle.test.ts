// Merkle list-commitment verification tests:
//   * happy path with caller-supplied (attributable) leaves
//   * the unavailable outcome when nothing can be obtained
//   * MERKLE_ROOT_MISMATCH / SCHEMA_MERKLE_LEAF_COUNT_MISMATCH /
//     SCHEMA_MERKLE_LEAVES_MALFORMED against attributable documents
//   * the offline (fetchContent:false) reading: deliberately unchecked

import { describe, expect, it } from 'vitest';

import { merkleSha2256Root, sha256 } from '@cardanowall/crypto-core/hash';
import { encodeLeavesList } from '@cardanowall/crypto-core/merkle';
import type { MerkleCommit } from '@cardanowall/poe-standard';

import type { ContentFetchContext } from './content';
import { IssueSink } from './issues';
import { checkMerkleCommit } from './merkle';
import type { FetchOutbound } from './types';

const STUB_FETCH: FetchOutbound = async () => ({
  status: 500,
  bytes: new Uint8Array(0),
  durationMs: 0,
});

function mkCtx(fetchFn: FetchOutbound = STUB_FETCH): {
  ctx: ContentFetchContext;
  issues: IssueSink;
} {
  const issues = new IssueSink();
  return {
    ctx: {
      fetchFn,
      arweaveGateways: ['https://arweave.example'],
      ipfsGateways: [],
      issues,
    },
    issues,
  };
}

function makeLeaves(n: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) out.push(sha256(new Uint8Array([i])));
  return out;
}

function commitOf(
  leaves: Uint8Array[],
  overrides: Partial<{ root: Uint8Array; leaf_count: number; uris: string[] }> = {},
): MerkleCommit {
  return {
    alg: 'rfc9162-sha256',
    root: overrides.root ?? merkleSha2256Root(leaves),
    leaf_count: overrides.leaf_count ?? leaves.length,
    ...(overrides.uris !== undefined ? { uris: overrides.uris } : {}),
  } as unknown as MerkleCommit;
}

describe('checkMerkleCommit', () => {
  it('happy path — supplied leaves-list matches the on-chain commitment', async () => {
    const leaves = makeLeaves(5);
    const blob = encodeLeavesList({ leaves, root: merkleSha2256Root(leaves) });
    const { ctx, issues } = mkCtx();
    const out = await checkMerkleCommit({
      commit: commitOf(leaves),
      commitIndex: 0,
      outOfBand: blob,
      fetchContent: true,
      ctx,
    });
    expect(out.contentCheck).toBe('checked');
    expect(out.unavailable).toBeUndefined();
    expect(issues.sorted()).toEqual([]);
  });

  it('nothing obtainable → unavailable marker (the report assembly resolves the dual severity)', async () => {
    const leaves = makeLeaves(3);
    const { ctx } = mkCtx();
    const out = await checkMerkleCommit({
      commit: commitOf(leaves),
      commitIndex: 0,
      fetchContent: true,
      ctx,
    });
    expect(out.contentCheck).toBe('not_checked');
    expect(out.unavailable).toEqual({ path: ['merkle', 0], limitExceeded: false });
  });

  it('offline (fetchContent:false) with no out-of-band document → deliberately unchecked, no marker', async () => {
    const leaves = makeLeaves(3);
    const { ctx, issues } = mkCtx();
    const out = await checkMerkleCommit({
      commit: commitOf(leaves, { uris: ['ar://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'] }),
      commitIndex: 0,
      fetchContent: false,
      ctx,
    });
    expect(out.contentCheck).toBe('not_checked');
    expect(out.unavailable).toBeUndefined();
    expect(issues.sorted()).toEqual([]);
  });

  it('attributable document whose root disagrees with the on-chain root → MERKLE_ROOT_MISMATCH', async () => {
    const committed = makeLeaves(4);
    const other = makeLeaves(4).reverse();
    const blob = encodeLeavesList({ leaves: other, root: merkleSha2256Root(other) });
    const { ctx, issues } = mkCtx();
    const out = await checkMerkleCommit({
      commit: commitOf(committed),
      commitIndex: 0,
      outOfBand: blob,
      fetchContent: true,
      ctx,
    });
    expect(out.contentCheck).toBe('mismatched');
    expect(issues.sorted().map((i) => i.code)).toEqual(['MERKLE_ROOT_MISMATCH']);
  });

  it('leaf-count disagreement against the on-chain commitment → SCHEMA_MERKLE_LEAF_COUNT_MISMATCH', async () => {
    const leaves = makeLeaves(4);
    const blob = encodeLeavesList({ leaves, root: merkleSha2256Root(leaves) });
    const { ctx, issues } = mkCtx();
    const out = await checkMerkleCommit({
      // The on-chain commitment declares a different leaf_count than the
      // (internally consistent) document carries.
      commit: commitOf(leaves, { leaf_count: 5 }),
      commitIndex: 0,
      outOfBand: blob,
      fetchContent: true,
      ctx,
    });
    expect(out.contentCheck).toBe('mismatched');
    expect(issues.sorted().map((i) => i.code)).toEqual(['SCHEMA_MERKLE_LEAF_COUNT_MISMATCH']);
  });

  it('bytes that are not the leaves-list container → SCHEMA_MERKLE_LEAVES_MALFORMED', async () => {
    const leaves = makeLeaves(2);
    const { ctx, issues } = mkCtx();
    const out = await checkMerkleCommit({
      commit: commitOf(leaves),
      commitIndex: 0,
      outOfBand: new TextEncoder().encode('not a leaves list'),
      fetchContent: true,
      ctx,
    });
    expect(out.contentCheck).toBe('mismatched');
    expect(issues.sorted().map((i) => i.code)).toEqual(['SCHEMA_MERKLE_LEAVES_MALFORMED']);
  });
});
