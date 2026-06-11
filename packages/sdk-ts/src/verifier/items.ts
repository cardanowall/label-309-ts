// Plain-item content verification (non-`enc` items).
//
// For each item that proceeds to fetch, the verifier resolves the item's URIs
// in order against the scheme-appropriate gateway chain and checks every
// digest in `item.hashes` against the fetched bytes —
// first-success-for-availability, with the integrity / attribution /
// availability split:
//
//   * bytes satisfying every committed digest        → contentCheck `checked`
//     (no binding check needed — the record's commitment is at least as
//     strong as the storage layer's);
//   * ATTRIBUTABLE bytes failing a digest            → URI_INTEGRITY_MISMATCH
//     (error, record-attributable, verdict `failed`) — one provably
//     mismatching URI condemns the record even if a sibling URI matches,
//     because the producer asserted at publication that every listed URI
//     resolves to committed bytes;
//   * UNATTRIBUTABLE bytes failing a digest          → URI_PROVIDER_INTEGRITY_MISMATCH
//     (warning, provider-attributable) and the remaining sources are tried;
//   * sources exhausted with nothing attributable    → CONTENT_UNAVAILABLE
//     (or CONTENT_FETCH_LIMIT_EXCEEDED when an attempt aborted at the fetch
//     ceiling) — network class, claim unchecked, verdict `unverifiable`.
//
// A hash-only item (no URIs) has nothing to fetch: its claim is reported
// `not_checked` with no availability issue — nothing failed, nothing was
// expected to be fetched. Sealed (`enc`-bearing) items never enter this step;
// their plaintext claim is checked by the decryption step's post-decryption
// recheck.

import { blake2b256, sha256 } from '@cardanowall/crypto-core/hash';
import { compareCt } from '@cardanowall/crypto-core/util';
import type { ItemEntry } from '@cardanowall/poe-standard';

import {
  iterateBlobSources,
  providerMismatchPath,
  type BlobIterationFlags,
  type ContentFetchContext,
} from './content';
import type { ContentCheck } from './types';

// True iff every entry of the item's `hashes` map recomputes over `bytes`.
// The structural validator guarantees registry membership of every key, so an
// unknown algorithm reaching here is a defensive no-certify, not a wire case.
export function recomputeItemHashes(
  hashes: Readonly<Record<string, Uint8Array>>,
  bytes: Uint8Array,
): boolean {
  const entries = Object.entries(hashes);
  if (entries.length === 0) return false;
  for (const [alg, digest] of entries) {
    if (alg === 'sha2-256') {
      if (!compareCt(sha256(bytes), digest)) return false;
    } else if (alg === 'blake2b-256') {
      if (!compareCt(blake2b256(bytes), digest)) return false;
    } else {
      return false;
    }
  }
  return true;
}

export async function checkItemContent(args: {
  readonly item: ItemEntry;
  readonly itemIndex: number;
  readonly fetchContent: boolean;
  readonly ctx: ContentFetchContext;
}): Promise<ContentCheck> {
  const { item, itemIndex, ctx } = args;
  if (!args.fetchContent) return 'not_checked';

  const uris = item.uris ?? [];
  if (uris.length === 0) return 'not_checked';

  const basePath = ['items', itemIndex];
  const flags: BlobIterationFlags = { limitExceeded: false };
  for await (const blob of iterateBlobSources({
    uris,
    allowFetch: true,
    basePath,
    ctx,
    flags,
  })) {
    if (recomputeItemHashes(item.hashes, blob.bytes)) {
      return 'checked';
    }
    if (blob.attributable()) {
      ctx.issues.add(
        'URI_INTEGRITY_MISMATCH',
        basePath,
        `attributable bytes fetched from "${blob.uri ?? 'out-of-band input'}" do not satisfy the item's hashes commitment`,
      );
      return 'mismatched';
    }
    ctx.issues.add(
      'URI_PROVIDER_INTEGRITY_MISMATCH',
      providerMismatchPath(basePath, blob),
      `bytes fetched from "${blob.uri ?? 'unknown source'}" do not satisfy the item's hashes commitment and could not be attributed to the URI's content address; the serving provider is indicted, not the record`,
    );
  }

  if (flags.limitExceeded) {
    ctx.issues.add(
      'CONTENT_FETCH_LIMIT_EXCEEDED',
      basePath,
      `a fetch for this item was aborted at the deployment's maxFetchBytes ceiling${ctx.maxFetchBytes !== undefined ? ` (${ctx.maxFetchBytes} bytes)` : ''}; the claim is unchecked`,
    );
  } else {
    ctx.issues.add(
      'CONTENT_UNAVAILABLE',
      basePath,
      'the URI list was exhausted with no attributable bytes satisfying the commitment; the claim is unchecked',
    );
  }
  return 'not_checked';
}
