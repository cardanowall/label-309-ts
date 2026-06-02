// Verifier-side URI fetching plus the canonical `fetchOutbound` re-exports.
// Two concerns colocated:
//
//   * `fetchItemCiphertext` — given a chunked `uris[]` from a record item or
//     merkle entry, reconstruct the URI, dispatch to the appropriate gateway
//     chain (ar:// → Arweave HTTPS rotation; ipfs:// → caller-supplied IPFS
//     rotation), and return the raw bytes. Per-attempt diagnostics surface
//     as `URI_FETCH_FAILED` warnings in the caller's sink; the chain-exhausted
//     terminal state throws `CONTENT_UNAVAILABLE` so the caller emits the
//     terminal verdict.
//
//   * Canonical re-exports of `defaultFetchOutbound`, `wrapFetchOutbound`, et
//     al. from `../fetch/fetch-outbound.js`.

import type { FetchOutbound, VerifyUriCheck } from './types';

export {
  BodyTooLargeError,
  DEFAULT_OUTBOUND_MAX_BYTES,
  defaultFetchOutbound,
  DENY_HOSTS_DEFAULT,
  DenyHostError,
  fetchOutbound,
  OutboundExhaustedError,
  UnsupportedMethodError,
  UnsupportedProtocolError,
  wrapFetchOutbound,
} from '../fetch/fetch-outbound';
export type { RetryConfig, WrapFetchOutboundConfig } from '../fetch/fetch-outbound';

// Default Arweave gateway rotation.
const ARWEAVE_DEFAULTS: ReadonlyArray<string> = [
  'https://arweave.net',
  'https://ar-io.net',
  'https://g8way.io',
];

const ARWEAVE_TXID_RE = /^[A-Za-z0-9_-]{43}$/;

export interface FetchItemCiphertextArgs {
  // Reconstructed-from-chunks URI list (each entry is itself a chunk array).
  readonly uris: ReadonlyArray<ReadonlyArray<string>>;
  readonly arweaveGateways?: ReadonlyArray<string> | undefined;
  readonly ipfsGateways?: ReadonlyArray<string> | undefined;
  readonly fetchFn: FetchOutbound;
  // Caller-supplied sink for per-attempt URI diagnostics. Each gateway failure
  // appends a `{ok: false, reason}` entry; the successful gateway appends
  // `{ok: true}`.
  readonly uriChecksOut: VerifyUriCheck[];
  // Caller path: `items[i]` → `itemIndex`; `merkle[i]` → reuse the field for
  // mapping (the report's `uriChecks[]` is item-indexed for v1).
  readonly itemIndex: number;
}

// Returns the first gateway response whose status is 200. Individual gateway
// failures are warnings; only chain-exhaustion raises the terminal
// `CONTENT_UNAVAILABLE`. The closed v1 scheme set is `{ar://, ipfs://}`; any
// other scheme has already been rejected by the structural validator as
// `INVALID_URI` and is rejected here too as defence in depth
// (`URI_TARGET_FORBIDDEN`).
export async function fetchItemCiphertext(args: FetchItemCiphertextArgs): Promise<Uint8Array> {
  const reconstructed = args.uris.map((chunks) => chunks.join(''));
  const candidate = reconstructed.find((u) => /^(ar|ipfs):\/\//.test(u));
  if (candidate === undefined) {
    // No in-set URI present — defence-in-depth rejection.
    for (const u of reconstructed) {
      args.uriChecksOut.push({
        item_index: args.itemIndex,
        uri: u,
        ok: false,
        reason: 'URI_TARGET_FORBIDDEN',
      });
    }
    throw new Error('URI_TARGET_FORBIDDEN');
  }

  if (candidate.startsWith('ar://')) {
    const txid = candidate.slice(5);
    if (!ARWEAVE_TXID_RE.test(txid)) {
      args.uriChecksOut.push({
        item_index: args.itemIndex,
        uri: candidate,
        ok: false,
        reason: 'INVALID_URI',
      });
      throw new Error('CONTENT_UNAVAILABLE');
    }
    const gateways =
      args.arweaveGateways && args.arweaveGateways.length > 0
        ? args.arweaveGateways
        : ARWEAVE_DEFAULTS;
    for (const gw of gateways) {
      try {
        const res = await args.fetchFn(`${gw}/${txid}`, { method: 'GET', purpose: 'arweave' });
        if (res.status === 200) {
          args.uriChecksOut.push({ item_index: args.itemIndex, uri: candidate, ok: true });
          return res.bytes;
        }
        args.uriChecksOut.push({
          item_index: args.itemIndex,
          uri: candidate,
          ok: false,
          reason: `URI_FETCH_FAILED:${gw}:${res.status}`,
        });
      } catch (e) {
        args.uriChecksOut.push({
          item_index: args.itemIndex,
          uri: candidate,
          ok: false,
          reason: `URI_FETCH_FAILED:${gw}:${e instanceof Error ? e.message : String(e)}`,
        });
      }
    }
    throw new Error('CONTENT_UNAVAILABLE');
  }

  // ipfs:// — caller MUST configure an IPFS gateway chain. No baked-in
  // defaults: IPFS gateways are not the producer's storage provider, and a
  // silent fallback would couple the verifier to an off-record gateway.
  const cidPart = candidate.slice('ipfs://'.length);
  const ipfsCid = cidPart.split('/')[0] ?? cidPart;
  const ipfsGateways = args.ipfsGateways;
  if (ipfsGateways === undefined || ipfsGateways.length === 0) {
    args.uriChecksOut.push({
      item_index: args.itemIndex,
      uri: candidate,
      ok: false,
      reason: 'CONTENT_UNAVAILABLE:no_ipfs_gateway',
    });
    throw new Error('CONTENT_UNAVAILABLE');
  }
  for (const gw of ipfsGateways) {
    try {
      const sep = gw.endsWith('/') ? '' : '/';
      const url = `${gw}${sep}ipfs/${ipfsCid}`;
      const res = await args.fetchFn(url, { method: 'GET', purpose: 'ipfs' });
      if (res.status === 200) {
        args.uriChecksOut.push({ item_index: args.itemIndex, uri: candidate, ok: true });
        return res.bytes;
      }
      args.uriChecksOut.push({
        item_index: args.itemIndex,
        uri: candidate,
        ok: false,
        reason: `URI_FETCH_FAILED:${gw}:${res.status}`,
      });
    } catch (e) {
      args.uriChecksOut.push({
        item_index: args.itemIndex,
        uri: candidate,
        ok: false,
        reason: `URI_FETCH_FAILED:${gw}:${e instanceof Error ? e.message : String(e)}`,
      });
    }
  }
  throw new Error('CONTENT_UNAVAILABLE');
}
