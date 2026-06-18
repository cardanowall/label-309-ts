// Content acquisition with attribution — the shared engine behind the three
// fetching consumers (plain-item digests, Merkle leaves-lists, sealed
// ciphertext).
//
// Multiple URIs are alternative sources for the same bytes, processed
// first-success-for-availability: sources are yielded in order (caller-
// supplied out-of-band bytes first, then each URI against its scheme's
// gateway chain) and the consumer stops at the first source satisfying its
// claim. Every yielded blob knows its ATTRIBUTION — whether the bytes are
// bound to the URI's content address (or were supplied out-of-band) — which
// decides whether a mismatch condemns the record or merely indicts the
// serving provider:
//
//   * out-of-band bytes            → attributable;
//   * ipfs:// raw-codec CIDv1      → attributable iff the multihash recompute
//                                    over the fetched bytes verifies;
//   * everything else fetched      → unattributable (no binding check
//                                    implemented for ar:// L1 / ANS-104 or
//                                    DAG-form CIDs), so mismatches route
//                                    through URI_PROVIDER_INTEGRITY_MISMATCH.
//
// Per-attempt diagnostics land in the issue sink (URI_FETCH_FAILED warnings,
// URI_TARGET_FORBIDDEN refusals, SERVICE_INDEPENDENCE_VIOLATION on a denied
// host), each at the claim's `uris[j]` path; the per-claim END-state
// (CONTENT_UNAVAILABLE vs CONTENT_FETCH_LIMIT_EXCEEDED vs the claim-specific
// availability code) is the consumer's to emit, with `flags.limitExceeded`
// recording whether an attempt aborted at the `maxFetchBytes` ceiling. A
// ceiling abort ENDS the claim: every URI of a claim addresses the same
// bytes, so any other honest source would abort at the same ceiling.

import { isBodyTooLargeError, isDenyHostError } from '../fetch/fetch-outbound';
import { verifyIpfsCidBinding } from './cid';
import type { IssuePath, IssueSink } from './issues';
import type { FetchOutbound } from './types';

// Default Arweave gateway rotation. IPFS has NO baked-in default: IPFS
// gateways are not the producer's storage provider, and a silent fallback
// would couple the verifier to an off-record gateway — a deployment that
// fetches ipfs:// must configure its own chain, and one that does not is a
// deployment that declines IPFS (URI_TARGET_FORBIDDEN at fetch time).
export const ARWEAVE_GATEWAY_DEFAULTS: ReadonlyArray<string> = [
  'https://turbo-gateway.com',
  'https://arweave.net',
  'https://permagate.io',
];

const ARWEAVE_TXID_RE = /^[A-Za-z0-9_-]{43}$/;

export interface ContentFetchContext {
  readonly fetchFn: FetchOutbound;
  readonly arweaveGateways: ReadonlyArray<string>;
  readonly ipfsGateways: ReadonlyArray<string>;
  readonly maxFetchBytes?: number | undefined;
  readonly issues: IssueSink;
}

export interface AcquiredBlob {
  readonly bytes: Uint8Array;
  readonly source: 'out_of_band' | 'fetched';
  readonly uri?: string;
  // The `uris[]` index of the source URI, absent for out-of-band bytes.
  readonly uriIndex?: number;
  // Lazily computed (and memoized) content-address binding: the digest work
  // only runs when a consumer actually needs attribution, i.e. on the
  // mismatch path. Bytes that satisfy the record's own commitment never need
  // it — the record's commitment is at least as strong as the storage
  // layer's.
  readonly attributable: () => boolean;
}

export interface BlobIterationFlags {
  limitExceeded: boolean;
}

interface ParsedFetchUri {
  readonly scheme: 'ar' | 'ipfs';
  // ar: the txid. ipfs: the CID (authority).
  readonly address: string;
  // ipfs only: the '/'-prefixed path within the DAG, '' when absent.
  readonly path: string;
}

// Scheme matching is case-insensitive (the scheme alone is folded); the
// remainder of the URI is a case-sensitive content address and is used
// verbatim.
function parseFetchUri(uri: string): ParsedFetchUri | null {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(uri);
  if (m === null) return null;
  const scheme = m[1]!.toLowerCase();
  const rest = uri.slice(m[0].length);
  if (scheme === 'ar') {
    if (!ARWEAVE_TXID_RE.test(rest)) return null;
    return { scheme: 'ar', address: rest, path: '' };
  }
  if (scheme === 'ipfs') {
    const slash = rest.indexOf('/');
    if (slash === -1) return { scheme: 'ipfs', address: rest, path: '' };
    return { scheme: 'ipfs', address: rest.slice(0, slash), path: rest.slice(slash) };
  }
  return null;
}

function joinGateway(base: string, suffix: string): string {
  return base.endsWith('/') ? `${base}${suffix}` : `${base}/${suffix}`;
}

/**
 * Yield candidate blobs for one claim, in source order: caller-supplied
 * out-of-band bytes first, then (when `allowFetch`) each URI in record order
 * against its scheme's gateway chain, first 200 per URI. The consumer breaks
 * out at the first acceptable blob; exhaustion of the generator means the
 * claim is left unchecked and the consumer emits the applicable availability
 * end-state.
 */
export async function* iterateBlobSources(args: {
  readonly outOfBand?: Uint8Array | undefined;
  readonly uris: ReadonlyArray<string>;
  readonly allowFetch: boolean;
  readonly basePath: IssuePath;
  readonly ctx: ContentFetchContext;
  readonly flags: BlobIterationFlags;
}): AsyncGenerator<AcquiredBlob> {
  const { ctx } = args;
  if (args.outOfBand !== undefined) {
    const bytes = args.outOfBand;
    yield { bytes, source: 'out_of_band', attributable: () => true };
  }
  if (!args.allowFetch) return;

  for (let uriIndex = 0; uriIndex < args.uris.length; uriIndex++) {
    const uri = args.uris[uriIndex]!;
    const uriPath: IssuePath = [...args.basePath, 'uris', uriIndex];
    const parsed = parseFetchUri(uri);
    if (parsed === null) {
      // Defence-in-depth: a target outside the closed fetch set can only
      // reach here by bypassing structural validation.
      ctx.issues.add(
        'URI_TARGET_FORBIDDEN',
        uriPath,
        `refusing to fetch "${uri}": not a conformant ar:// or ipfs:// content address`,
      );
      continue;
    }

    let gateways: ReadonlyArray<string>;
    let urlFor: (gateway: string) => string;
    let purpose: 'arweave' | 'ipfs';
    if (parsed.scheme === 'ar') {
      gateways = ctx.arweaveGateways;
      urlFor = (gw) => joinGateway(gw, parsed.address);
      purpose = 'arweave';
    } else {
      gateways = ctx.ipfsGateways;
      urlFor = (gw) => joinGateway(gw, `ipfs/${parsed.address}${parsed.path}`);
      purpose = 'ipfs';
      if (gateways.length === 0) {
        // This deployment declines every IPFS fetch — a policy statement
        // about the verifier, never about the record.
        ctx.issues.add(
          'URI_TARGET_FORBIDDEN',
          uriPath,
          `refusing to fetch "${uri}": no IPFS gateway chain is configured`,
        );
        continue;
      }
    }

    for (const gateway of gateways) {
      const url = urlFor(gateway);
      let bytes: Uint8Array;
      try {
        const res = await ctx.fetchFn(url, {
          method: 'GET',
          purpose,
          ...(ctx.maxFetchBytes !== undefined ? { maxBytes: ctx.maxFetchBytes } : {}),
        });
        if (res.status !== 200) {
          ctx.issues.add(
            'URI_FETCH_FAILED',
            uriPath,
            `fetch of "${uri}" via ${gateway} returned HTTP ${res.status}`,
          );
          continue;
        }
        bytes = res.bytes;
      } catch (e) {
        if (isBodyTooLargeError(e)) {
          // Aborted at the deployment's per-URI fetch ceiling. Every URI of
          // a claim addresses the same bytes, so any other honest source
          // would abort at the same ceiling: end the claim. The consumer's
          // end-state surfaces CONTENT_FETCH_LIMIT_EXCEEDED.
          args.flags.limitExceeded = true;
          return;
        }
        if (isDenyHostError(e)) {
          // The egress hard-failed the call against the deny-host list. A
          // per-attempt error-severity issue (verdict `failed` via severity);
          // the remaining sources are still tried so the report shows every
          // violating target.
          ctx.issues.add(
            'SERVICE_INDEPENDENCE_VIOLATION',
            uriPath,
            `outbound call to ${url} targets a denyHosts entry`,
          );
          continue;
        }
        ctx.issues.add(
          'URI_FETCH_FAILED',
          uriPath,
          `fetch of "${uri}" via ${gateway} failed: ${e instanceof Error ? e.message : String(e)}`,
        );
        continue;
      }

      let binding: 'verified' | 'failed' | 'unsupported' | null = null;
      const attributable = (): boolean => {
        if (binding === null) {
          binding =
            parsed.scheme === 'ipfs'
              ? verifyIpfsCidBinding({ cid: parsed.address, path: parsed.path, bytes })
              : 'unsupported';
        }
        return binding === 'verified';
      };
      yield { bytes, source: 'fetched', uri, uriIndex, attributable };
      // The consumer pulled the next source: this blob did not settle the
      // claim (an unattributable mismatch indicts the gateway, not the
      // address), so the remaining gateways of the same URI are tried next.
    }
  }
}

/**
 * The issue path for an unattributable provider mismatch: the source URI when
 * the blob was fetched, the claim base path otherwise.
 */
export function providerMismatchPath(basePath: IssuePath, blob: AcquiredBlob): IssuePath {
  return blob.uriIndex !== undefined ? [...basePath, 'uris', blob.uriIndex] : basePath;
}
