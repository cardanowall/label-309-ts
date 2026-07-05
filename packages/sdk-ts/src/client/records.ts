// `client.records.*` wraps the open-standard indexer read surface. The
// configured `baseUrl` carries the gateway version segment, so these methods
// append only the bare resource suffix:
//
//   GET  /records                   → records.list(input?)
//   GET  /records/count             → records.count(input)
//   GET  /records/{tx_hash}         → records.get(txHash)
//
// The PoE namespace owns the mutation methods (uploads, publish,
// publishBatch + the high-level publishContent/submitSealed/publishMerkle
// helpers); reads live here under Records — same tag grouping the OpenAPI
// registry uses (`tags: ['Records']` on these operationIds).
//
// Auth is optional: chain data is public. When an API key is configured the
// SDK forwards it as `Authorization: Bearer …` so owner-only fields
// (currently just `account_id`) surface for the caller's own rows, and so the
// `sealed` list filter can resolve records addressed to the caller.

import { readJson, throwIfNotOk } from './http-helpers';
import type {
  FetchImpl,
  RecordResource,
  RecordsCountInput,
  RecordsCountResponse,
  RecordsListInput,
  RecordsListResponse,
} from './types';

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
    const url = `${this.config.baseUrl}/records${query === '' ? '' : `?${query}`}`;
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
   * Count the records matching a filter — the counting counterpart to
   * `list()`. The paginated feed never carries a total, so a caller that needs
   * the cardinality of a filter (a profile's proof count, an explorer facet)
   * asks here.
   *
   * `signer` is REQUIRED: a count's cost is the size of the matching set, which
   * only a signer scope bounds, so a signer-less count is rejected with 422
   * (`ValidationFailedError`). The remaining filters (`scheme`, `sealed`, the
   * block/time windows) narrow the count on top of the signer scope and share
   * the exact query grammar `list()` uses. The count is over the public anchored
   * set only.
   */
  async count(input: RecordsCountInput): Promise<RecordsCountResponse> {
    const params = new URLSearchParams();
    params.set('signer', input.signer);
    if (input.scheme !== undefined) params.set('scheme', String(input.scheme));
    if (input.sealed === true) params.set('sealed', 'true');
    if (input.fromBlock !== undefined) params.set('from_block', String(input.fromBlock));
    if (input.toBlock !== undefined) params.set('to_block', String(input.toBlock));
    if (input.fromTime !== undefined) params.set('from_time', input.fromTime);
    if (input.toTime !== undefined) params.set('to_time', input.toTime);
    const url = `${this.config.baseUrl}/records/count?${params.toString()}`;
    const response = await this.config.fetch(url, {
      method: 'GET',
      headers: buildHeaders(this.config.apiKey),
    });
    await throwIfNotOk(response);
    return (await readJson(response)) as RecordsCountResponse;
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
      `${this.config.baseUrl}/records/${encodeURIComponent(txHash)}`,
      {
        method: 'GET',
        headers: buildHeaders(this.config.apiKey),
      },
    );
    await throwIfNotOk(response);
    return (await readJson(response)) as RecordResource;
  }
}
