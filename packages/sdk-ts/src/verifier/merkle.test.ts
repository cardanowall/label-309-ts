// Merkle list-commitment verifier tests. Exercises:
//   * happy path with caller-supplied leaves (no fetch)
//   * MERKLE_LEAVES_UNAVAILABLE when no uris[] AND no input.merkleLeaves[i]
//   * MERKLE_ROOT_MISMATCH when the on-record root disagrees with recompute
//   * SCHEMA_MERKLE_LEAF_COUNT_MISMATCH when leaf_count disagrees

import { describe, expect, it } from 'vitest';

import { merkleSha2256Root, sha256 } from '@cardanowall/crypto-core/hash';
import { encodeLeavesList } from '@cardanowall/crypto-core/merkle';
import type { PoeRecord } from '@cardanowall/poe-standard';

import { verifyMerkleCommitments } from './merkle';
import type { FetchOutbound, VerifyUriCheck } from './types';

const STUB_FETCH: FetchOutbound = async () => ({
  status: 500,
  bytes: new Uint8Array(0),
  durationMs: 0,
});

function makeLeaves(n: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) out.push(sha256(new Uint8Array([i])));
  return out;
}

// `PoeRecord['merkle']` declares `root: Uint8Array<ArrayBuffer>` (Zod's
// `.instanceof(Uint8Array)` infers the strict variant) while @noble/hashes
// returns `Uint8Array<ArrayBufferLike>`. Coerce through `as unknown` rather
// than fight the inference per test fixture.
function asMerkleArray(
  commits: Array<{ alg: string; root: Uint8Array; leaf_count: number }>,
): PoeRecord['merkle'] {
  return commits as unknown as PoeRecord['merkle'];
}

function recordWith(merkle: PoeRecord['merkle']): PoeRecord {
  return {
    v: 1,
    merkle,
    items: [{ hashes: { 'sha2-256': new Uint8Array(32) } }],
  } as PoeRecord;
}

describe('verifyMerkleCommitments', () => {
  it('happy path — supplied leaves match the on-record root', async () => {
    const leaves = makeLeaves(5);
    const root = merkleSha2256Root(leaves);
    const leavesBlob = encodeLeavesList({ leaves, root });
    const record = recordWith(asMerkleArray([{ alg: 'rfc9162-sha256', root, leaf_count: 5 }]));
    const uri: VerifyUriCheck[] = [];
    const out = await verifyMerkleCommitments({
      record,
      input: { txHash: '0'.repeat(64), merkleLeaves: { 0: leavesBlob } },
      fetchFn: STUB_FETCH,
      uriChecksOut: uri,
    });
    expect(out.checks).toHaveLength(1);
    expect(out.checks[0]!.verdict).toBe('valid');
  });

  it('MERKLE_LEAVES_UNAVAILABLE when no uris and no input bytes', async () => {
    const leaves = makeLeaves(3);
    const root = merkleSha2256Root(leaves);
    const record = recordWith(asMerkleArray([{ alg: 'rfc9162-sha256', root, leaf_count: 3 }]));
    const uri: VerifyUriCheck[] = [];
    const out = await verifyMerkleCommitments({
      record,
      input: { txHash: '0'.repeat(64) },
      fetchFn: STUB_FETCH,
      uriChecksOut: uri,
    });
    expect(out.checks[0]!.verdict).toBe('unavailable');
    expect(out.checks[0]!.reason).toBe('MERKLE_LEAVES_UNAVAILABLE');
  });

  it('MERKLE_ROOT_MISMATCH when on-record root disagrees', async () => {
    const leaves = makeLeaves(4);
    const wrongRoot = new Uint8Array(32).fill(0xaa);
    const leavesBlob = encodeLeavesList({ leaves, root: merkleSha2256Root(leaves) });
    const record = recordWith(
      asMerkleArray([{ alg: 'rfc9162-sha256', root: wrongRoot, leaf_count: 4 }]),
    );
    const uri: VerifyUriCheck[] = [];
    const out = await verifyMerkleCommitments({
      record,
      input: { txHash: '0'.repeat(64), merkleLeaves: { 0: leavesBlob } },
      fetchFn: STUB_FETCH,
      uriChecksOut: uri,
    });
    expect(out.checks[0]!.verdict).toBe('mismatch');
    expect(out.checks[0]!.reason).toBe('MERKLE_ROOT_MISMATCH');
  });

  it('SCHEMA_MERKLE_LEAF_COUNT_MISMATCH when on-record count disagrees', async () => {
    const leaves = makeLeaves(7);
    const root = merkleSha2256Root(leaves);
    const leavesBlob = encodeLeavesList({ leaves, root });
    const record = recordWith(asMerkleArray([{ alg: 'rfc9162-sha256', root, leaf_count: 999 }]));
    const uri: VerifyUriCheck[] = [];
    const out = await verifyMerkleCommitments({
      record,
      input: { txHash: '0'.repeat(64), merkleLeaves: { 0: leavesBlob } },
      fetchFn: STUB_FETCH,
      uriChecksOut: uri,
    });
    expect(out.checks[0]!.verdict).toBe('mismatch');
    expect(out.checks[0]!.reason).toBe('SCHEMA_MERKLE_LEAF_COUNT_MISMATCH');
  });
});
