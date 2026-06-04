// Low-level wrappers over the public mutating /api/v1/poe/* surface:
//
//   POST /api/v1/poe/quote           — lock a USD price for a publish
//   POST /api/v1/poe/uploads         — multipart binary upload to a backend
//   POST /api/v1/poe/publish         — single finalised record (JSON)
//   POST /api/v1/poe/publish-batch   — 1..50 finalised records (JSON)
//
// Plus high-level helpers that compose the above into common flows:
//
//   publishContent({content, quoteId, signer?})            — hash-only
//   publishPrehashed({hashes, quoteId, signer?})           — caller already holds digest
//   publishSealed({content, recipients, quoteId, signer?}) — encrypt + uploads + publish
//   publishMerkle({leaves, quoteId, signer?})              — uploads + publish, Merkle root

import { bytesToHex } from '../hex';
import { readJson, throwIfNotOk } from './http-helpers';
import {
  publishContent as publishContentImpl,
  publishMerkle as publishMerkleImpl,
  publishPrehashed as publishPrehashedImpl,
  publishSealed as publishSealedImpl,
  type ResolvedPublishConfig,
} from './publish';
import type {
  FetchImpl,
  PublishBatchInput,
  PublishBatchResponse,
  PublishContentInput,
  PublishInput,
  PublishMerkleInput,
  PublishMerkleResponse,
  PublishPrehashedInput,
  PublishResponse,
  PublishSealedInput,
  QuoteInput,
  QuoteResponse,
  UploadsInput,
  UploadsResponse,
} from './types';

interface ResolvedConfig {
  readonly apiKey: string | undefined;
  readonly baseUrl: string;
  readonly fetch: FetchImpl;
}

function buildJsonHeaders(args: {
  apiKey: string | undefined;
  idempotencyKey?: string | undefined;
}): Headers {
  const headers = new Headers({ 'content-type': 'application/json', accept: 'application/json' });
  if (args.apiKey !== undefined) headers.set('authorization', `Bearer ${args.apiKey}`);
  if (args.idempotencyKey !== undefined) headers.set('idempotency-key', args.idempotencyKey);
  return headers;
}

function buildMultipartHeaders(args: {
  apiKey: string | undefined;
  idempotencyKey?: string | undefined;
}): Headers {
  // Do NOT set content-type — the runtime emits the multipart boundary header
  // automatically when the body is a FormData. Forcing it here would emit a
  // boundary-less content-type that the server rejects.
  const headers = new Headers({ accept: 'application/json' });
  if (args.apiKey !== undefined) headers.set('authorization', `Bearer ${args.apiKey}`);
  if (args.idempotencyKey !== undefined) headers.set('idempotency-key', args.idempotencyKey);
  return headers;
}

function toHex(record: Uint8Array | string): string {
  return typeof record === 'string' ? record : bytesToHex(record);
}

export class PoeNamespace {
  private readonly config: ResolvedConfig;

  constructor(config: ResolvedConfig) {
    this.config = config;
  }

  /**
   * Request an opaque price lock for an upcoming /publish call. The gateway
   * prices the described publish from the supplied byte counts, records the
   * lock, and returns a sealed price token: `quote_id`, the total `amount` in
   * `currency`, and an `expires_at`. The gateway's pricing internals are
   * deliberately NOT part of the response.
   *
   * `amount` is a decimal string; promote it to `BigInt` (or a decimal type)
   * at the application boundary if you need exact arithmetic.
   *
   * Pass the returned `quote_id` to `publish()` (or one of the high-level
   * `publishContent` / `publishSealed` / `publishMerkle` helpers).
   */
  async quote(input: QuoteInput): Promise<QuoteResponse> {
    const body = {
      record_bytes: input.recordBytes,
      recipient_count: input.recipientCount,
      file_bytes_total: input.fileBytesTotal,
    };
    const response = await this.config.fetch(`${this.config.baseUrl}/api/v1/poe/quote`, {
      method: 'POST',
      headers: buildJsonHeaders({ apiKey: this.config.apiKey }),
      body: JSON.stringify(body),
    });
    await throwIfNotOk(response);
    return (await readJson(response)) as QuoteResponse;
  }

  /**
   * Upload 1..32 binary files to a storage backend. Returns one entry per file
   * — successful entries carry the `ar://` URI + content hash, failed entries
   * carry an error code / detail so the caller can retry just the failed
   * indices.
   *
   * Billing: free. The storage cost is part of the publish quote (POST
   * /api/v1/poe/quote → POST /api/v1/poe/publish) and is debited once at
   * publish time against the locked price snapshot.
   *
   * On HTTP-level failure (auth, rate limit, malformed request) this throws
   * a typed `Label309HttpError` subclass. Per-file failures inside a 200
   * response are NOT thrown by `uploads()` itself — the response body is
   * returned verbatim so the caller can decide how to react. The
   * higher-level helpers (`publishSealed`, `publishMerkle`) treat any failed
   * file as a `PartialUploadError`.
   */
  async uploads(input: UploadsInput): Promise<UploadsResponse> {
    const form = new FormData();
    form.append('target', input.target);
    for (let idx = 0; idx < input.data.length; idx++) {
      const bytes = input.data[idx]!;
      // Uint8Array is a valid Blob source in every runtime that ships
      // FormData (browser, undici, node 20+); cast through `unknown` keeps
      // strict-mode TS happy without dragging in lib.dom.iterable.d.ts here.
      form.append(
        `file_${idx}`,
        new Blob([bytes as unknown as ArrayBuffer], { type: 'application/octet-stream' }),
        `file_${idx}.bin`,
      );
    }
    const headers = buildMultipartHeaders({
      apiKey: this.config.apiKey,
      idempotencyKey: input.idempotencyKey,
    });
    const response = await this.config.fetch(`${this.config.baseUrl}/api/v1/poe/uploads`, {
      method: 'POST',
      headers,
      body: form,
    });
    await throwIfNotOk(response);
    return (await readJson(response)) as UploadsResponse;
  }

  /**
   * Submit a single finalised canonical-CBOR record to Cardano. Caller is
   * responsible for constructing the record bytes (use `publishContent` /
   * `publishSealed` / `publishMerkle` for the assisted flows) and for
   * acquiring a `quote_id` via `quote()` first.
   *
   * Returns 202 (`dedup_hit: false`) on freshly enqueued records, or 200
   * (`dedup_hit: true`) when the same record bytes were previously submitted
   * by this account. Dedup hits debit nothing.
   */
  async publish(input: PublishInput): Promise<PublishResponse> {
    const body: { record: string; quote_id: string; signatures?: ReadonlyArray<unknown> } = {
      record: toHex(input.record),
      quote_id: input.quoteId,
    };
    if (input.signatures !== undefined) body.signatures = input.signatures;
    const response = await this.config.fetch(`${this.config.baseUrl}/api/v1/poe/publish`, {
      method: 'POST',
      headers: buildJsonHeaders({
        apiKey: this.config.apiKey,
        idempotencyKey: input.idempotencyKey,
      }),
      body: JSON.stringify(body),
    });
    await throwIfNotOk(response);
    const parsed = (await readJson(response)) as Omit<PublishResponse, 'dedup_hit'>;
    return { ...parsed, dedup_hit: response.status === 200 };
  }

  /**
   * Submit 1..50 finalised records as independent Cardano transactions.
   * Each entry carries its own `quote_id` — request quotes ahead of time
   * with one `quote()` call per record. Returns 200 with `results[]` —
   * successful entries land alongside failed ones; per-record errors do NOT
   * roll back the batch.
   */
  async publishBatch(input: PublishBatchInput): Promise<PublishBatchResponse> {
    const body = {
      records: input.records.map((r) => ({
        record: toHex(r.record),
        quote_id: r.quoteId,
        ...(r.signatures !== undefined ? { signatures: r.signatures } : {}),
      })),
    };
    const response = await this.config.fetch(`${this.config.baseUrl}/api/v1/poe/publish-batch`, {
      method: 'POST',
      headers: buildJsonHeaders({
        apiKey: this.config.apiKey,
        idempotencyKey: input.idempotencyKey,
      }),
      body: JSON.stringify(body),
    });
    await throwIfNotOk(response);
    return (await readJson(response)) as PublishBatchResponse;
  }

  /**
   * High-level hash-only publish: hash the supplied content, build a
   * single-item Label 309 record, optionally sign it with the caller-supplied
   * signer, and submit. No Arweave, no storage round-trip — anchors the
   * digest only.
   */
  async publishContent(input: PublishContentInput): Promise<PublishResponse> {
    return publishContentImpl(this.config as ResolvedPublishConfig, input);
  }

  /**
   * Hash-already-computed publish: caller already holds the digest(s) — e.g.
   * the CLI `--hash <hex>` mode, an air-gapped offline hashing flow, or any
   * pipeline that proxies digests from another tool. No client-side hashing.
   */
  async publishPrehashed(input: PublishPrehashedInput): Promise<PublishResponse> {
    return publishPrehashedImpl(this.config as ResolvedPublishConfig, input);
  }

  /**
   * Sealed-PoE: encrypt the supplied content to the recipient X25519 public
   * keys (age-style sealed envelope), upload the ciphertext to Arweave via
   * /uploads, build a Label 309 record with the resulting `ar://` URI, sign
   * it (optional), and submit via /publish.
   *
   * The sender SHOULD include their own X25519 public key in `recipients`
   * to retain decrypt access — the SDK does NOT inject the sender silently.
   */
  async publishSealed(input: PublishSealedInput): Promise<PublishResponse> {
    return publishSealedImpl(this.config as ResolvedPublishConfig, input);
  }

  /**
   * Merkle batch publish: compute the RFC 9162 §2.1.1 root over N
   * caller-supplied 32-byte leaf hashes, upload the canonical leaves-list
   * CBOR to Arweave via /uploads, bind the root + leaf_count into
   * `merkle[0]` of an on-chain record, optionally sign, and submit.
   *
   * Returns the on-chain id + tx hash + root + leaf count + the canonical
   * `ar://<tx>` URI of the leaves-list. Anyone with that URI can later
   * fetch the leaves-list, recompute the root, and prove inclusion of any
   * leaf via `merkleSha2256VerifyInclusion`.
   */
  async publishMerkle(input: PublishMerkleInput): Promise<PublishMerkleResponse> {
    return publishMerkleImpl(this.config as ResolvedPublishConfig, input);
  }
}
