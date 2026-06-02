// `client.records.*` wraps the open-standard indexer read surface:
//
//   GET  /api/v1/records                   → records.list(input?)
//   GET  /api/v1/records/{tx_hash}         → records.get(txHash)
//   POST /api/v1/records/{tx_hash}/verify  → records.verify(txHash, input)
//
// The PoE namespace owns the mutation methods (uploads, publish,
// publishBatch + the high-level publishContent/publishSealed/publishMerkle
// helpers); reads and verifications live here under Records — same tag
// grouping the OpenAPI registry uses (`tags: ['Records']` on these
// operationIds).
//
// Auth is optional: chain data is public. When an API key is configured the
// SDK forwards it as `Authorization: Bearer …` so owner-only fields
// (currently just `account_id`) surface for the caller's own rows, and so the
// `sealed` list filter can resolve records addressed to the caller.

import { readJson, throwIfNotOk } from './http-helpers';
import type {
  FetchImpl,
  PoeVerifyInput,
  RecordResource,
  RecordsListInput,
  RecordsListResponse,
} from './types';
import type { VerifyReport } from '../verifier/types';

interface ResolvedConfig {
  readonly apiKey: string | undefined;
  readonly baseUrl: string;
  readonly fetch: FetchImpl;
}

function buildHeaders(apiKey: string | undefined): Headers {
  const headers = new Headers({
    'content-type': 'application/json',
    accept: 'application/json',
  });
  if (apiKey !== undefined) headers.set('authorization', `Bearer ${apiKey}`);
  return headers;
}

/**
 * Derive the chain tip from a record page as `max(block_height +
 * num_confirmations - 1)` over the rows that carry a block height. Returns
 * `null` for an empty page or one with no anchored rows.
 */
function deriveTipBlockHeight(records: ReadonlyArray<RecordResource>): number | null {
  let tip: number | null = null;
  for (const r of records) {
    if (r.block_height === null) continue;
    const candidate = r.block_height + r.num_confirmations - 1;
    tip = tip === null ? candidate : Math.max(tip, candidate);
  }
  return tip;
}

export class RecordsNamespace {
  private readonly config: ResolvedConfig;

  constructor(config: ResolvedConfig) {
    this.config = config;
  }

  /**
   * List records as a paginated `RecordsListResponse` whose `data[]` entries
   * are the same `RecordResource` projection `get()` returns.
   *
   * Pass `{ sealed: true }` to restrict the page to sealed records addressed
   * to the authenticated caller (the gateway resolves the recipient from the
   * bearer identity); omit it to list every record the caller may read. Page
   * with `{ cursor: previous.next_cursor }` until `has_more` is false.
   */
  async list(input?: RecordsListInput): Promise<RecordsListResponse> {
    const params = new URLSearchParams();
    if (input?.sealed === true) params.set('sealed', 'true');
    if (input?.limit !== undefined) params.set('limit', String(input.limit));
    if (input?.cursor !== undefined && input.cursor !== null) {
      params.set('cursor', input.cursor);
    }
    const query = params.toString();
    const url = `${this.config.baseUrl}/api/v1/records${query === '' ? '' : `?${query}`}`;
    const response = await this.config.fetch(url, {
      method: 'GET',
      headers: buildHeaders(this.config.apiKey),
    });
    await throwIfNotOk(response);
    const page = (await readJson(response)) as RecordsListResponse;
    // A gateway that reports `tip_block_height` populates confirmation data
    // directly; otherwise derive it from the page rows so sealed-record sync
    // has a tip to compute confirmation depth against.
    if (page.tip_block_height === undefined || page.tip_block_height === null) {
      return { ...page, tip_block_height: deriveTipBlockHeight(page.data) };
    }
    return page;
  }

  /**
   * Fetch a record by Cardano transaction hash. Returns the JSON
   * `RecordResource` projection — same shape every `records.list` page entry
   * carries inside `data[]`.
   *
   * 404 (RecordNotFoundError) on tx_hashes the indexer has not seen, OR on
   * un-anchored rows when the caller is not their owner (oracle-safe
   * indistinguishable response per the route's privacy invariant).
   */
  async get(txHash: string): Promise<RecordResource> {
    const response = await this.config.fetch(
      `${this.config.baseUrl}/api/v1/records/${encodeURIComponent(txHash)}`,
      {
        method: 'GET',
        headers: buildHeaders(this.config.apiKey),
      },
    );
    await throwIfNotOk(response);
    return (await readJson(response)) as RecordResource;
  }

  /**
   * Run the canonical CIP-309 verifier against the record at `txHash`.
   * Returns the same `VerifyReport` shape the standalone verifier emits —
   * `VerifyReport` IS the wire body of this endpoint, with no transformer in
   * between.
   *
   * Auth required (Bearer with `poe:read` scope, or NextAuth session
   * cookie). Optional `verify_uris` toggles URI hash-equivalence checks;
   * `decryption[]` drives trial-decrypt of sealed envelopes per item.
   */
  async verify(txHash: string, input?: PoeVerifyInput): Promise<VerifyReport> {
    const response = await this.config.fetch(
      `${this.config.baseUrl}/api/v1/records/${encodeURIComponent(txHash)}/verify`,
      {
        method: 'POST',
        headers: buildHeaders(this.config.apiKey),
        body: JSON.stringify(input ?? {}),
      },
    );
    await throwIfNotOk(response);
    return (await readJson(response)) as VerifyReport;
  }
}
