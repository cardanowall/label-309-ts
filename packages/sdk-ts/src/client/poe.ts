// Low-level wrappers over the public mutating `/poe/*` surface. The configured
// `baseUrl` carries the gateway version segment, so these methods append only
// the bare resource suffix:
//
//   POST /poe/quote           — lock a USD price for a publish
//   POST /poe/uploads         — multipart binary upload to a backend
//   POST /poe/publish         — single finalised record (JSON)
//   POST /poe/publish-batch   — 1..50 finalised records (JSON)
//
// Plus high-level helpers that compose the above into common flows:
//
//   publishContent({content, quoteId, signer?})            — hash-only
//   publishPrehashed({hashes, quoteId, signer?})           — caller already holds digest
//   publishSealed({content, recipients, quoteId, signer?}) — encrypt + uploads + publish
//   publishMerkle({leaves, quoteId, signer?})              — uploads + publish, Merkle root

import { bytesToHex } from '../hex';
import { readJson, throwIfNotOk } from './http-helpers';
import { PartialUploadError } from './partial-upload-error';
import { waitForPoe } from './poe-events';
import {
  publishContent as publishContentImpl,
  publishMerkle as publishMerkleImpl,
  publishPrehashed as publishPrehashedImpl,
  publishSealed as publishSealedImpl,
  type ResolvedPublishConfig,
} from './publish';
import {
  abandonUploadSession as abandonUploadSessionImpl,
  uploadResumable as uploadResumableImpl,
  type SingleShotUpload,
} from './resumable-upload';
import type {
  FetchImpl,
  PoeStatusSnapshot,
  PoeWaitOptions,
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
  UploadResumableInput,
  UploadResumableResult,
  UploadSuccessEntry,
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
    const response = await this.config.fetch(`${this.config.baseUrl}/poe/quote`, {
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
   * /poe/quote → POST /poe/publish) and is debited once at
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
    const response = await this.config.fetch(`${this.config.baseUrl}/poe/uploads`, {
      method: 'POST',
      headers,
      body: form,
    });
    await throwIfNotOk(response);
    return (await readJson(response)) as UploadsResponse;
  }

  /**
   * Upload a single file of any size, choosing the ingress path by size.
   *
   * A file at or below `threshold` (default ~48 MiB) is sent with the unchanged
   * single-shot `uploads()` multipart call. A larger file is uploaded as a
   * resumable, content-addressed session: the helper streams the whole-file
   * SHA-256 once (never buffering a multi-GB file), creates a session, PUTs each
   * chunk (several in parallel, retrying a failed chunk), then completes —
   * polling the shared attempt endpoint when completion is accepted
   * asynchronously. Both paths converge on one `ar://` URI.
   *
   * The chunk size is the server's authoritative `chunk_bytes` from the create
   * response, clamped to its `max_chunk_bytes` ceiling; the client's `chunkBytes`
   * is only a request. A create-time dedup hit returns the existing URI without
   * uploading; a `402` funding error is surfaced as a typed error.
   *
   * The `source` works in both runtimes: a `Blob`/`File` in the browser, a
   * `Uint8Array`, a filesystem path string, or a pre-adapted `ResumableSource`
   * on the server. To resume an interrupted upload, pass the prior `sessionId`;
   * the helper GETs its status and uploads only the missing chunks.
   */
  async uploadResumable(input: UploadResumableInput): Promise<UploadResumableResult> {
    return uploadResumableImpl(this.config, this.singleShotUpload, input);
  }

  /**
   * Abandon a resumable upload session (`DELETE /poe/uploads/sessions/{sid}`),
   * discarding the session and any not-yet-adopted staged bytes server-side.
   * Use it to discard an upload the user cancelled before completion. Idempotent
   * — a session that was never created, already abandoned, or expired resolves
   * successfully (the gateway's 404/410 is treated as already-gone).
   */
  async abandonUploadSession(sessionId: string, signal?: AbortSignal): Promise<void> {
    return abandonUploadSessionImpl(this.config, sessionId, signal);
  }

  /**
   * Upload exactly one blob via the single-shot multipart route and resolve its
   * `ar://` URI. Backs the small-file branch of `uploadResumable`; it shares the
   * `uploads()` wire shape but takes one blob and an optional abort signal, and
   * surfaces a per-file failure as a `PartialUploadError` (the resumable helper
   * promises a single resolved URI, unlike the raw `uploads()` passthrough).
   */
  private readonly singleShotUpload: SingleShotUpload = async ({
    target,
    bytes,
    idempotencyKey,
    signal,
  }) => {
    const form = new FormData();
    form.append('target', target);
    form.append(
      'file_0',
      new Blob([bytes as unknown as ArrayBuffer], { type: 'application/octet-stream' }),
      'file_0.bin',
    );
    const response = await this.config.fetch(`${this.config.baseUrl}/poe/uploads`, {
      method: 'POST',
      headers: buildMultipartHeaders({ apiKey: this.config.apiKey, idempotencyKey }),
      body: form,
      ...(signal ? { signal } : {}),
    });
    await throwIfNotOk(response);
    const result = (await readJson(response)) as UploadsResponse;
    const entry = result.uploads[0];
    if (entry === undefined || entry.ok === false) {
      throw new PartialUploadError(result);
    }
    const ok = entry as UploadSuccessEntry;
    return { uri: ok.uri, sha256: ok.sha256, bytes: ok.bytes };
  };

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
    const response = await this.config.fetch(`${this.config.baseUrl}/poe/publish`, {
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
    const response = await this.config.fetch(`${this.config.baseUrl}/poe/publish-batch`, {
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
   * Wait for a published record to reach a lifecycle milestone by following
   * the gateway's live status stream (`GET /poe/events/{poe_id}`,
   * Server-Sent Events). Pass the `id` a publish call returned.
   *
   * Resolves with the record's snapshot once `options.target` is reached:
   * `'submitted'` resolves as soon as the transaction is on the wire
   * (status `confirming`, or `confirmed` which implies it); `'confirmed'`
   * resolves at the confirmed status. A record that reaches the terminal
   * `failed` status rejects with `PoeFailedError` (the snapshot rides on the
   * error); an elapsed `timeoutMs` rejects with `PoeWaitTimeoutError`
   * carrying the last snapshot seen.
   *
   * The stream is followed resiliently: dropped connections reconnect with
   * backoff and resume from the last event id, so no status change is missed
   * across a reconnect. Statuses are normalized to the wire lifecycle (the
   * raw engine statuses `submitted` / `permanent_failure` surface as
   * `confirming` / `failed`).
   */
  async wait(poeId: string, options: PoeWaitOptions): Promise<PoeStatusSnapshot> {
    return waitForPoe(this.config, poeId, options);
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
