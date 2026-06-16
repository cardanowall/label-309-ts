// Wire-format fields stay snake_case so JSON round-trips without translation;
// SDK-introduced helper fields (Label309ClientConfig, etc.) use camelCase.
//
// Money on the wire: bigint USD micro-cents serialised as decimal strings
// (1 USD = 1,000,000 micros). The SDK accepts and returns strings — callers
// promote to `bigint` at the application boundary where they need arithmetic.

import type { ResumableSourceInput } from './resumable-source';

export type FetchImpl = (input: string | URL, init?: RequestInit) => Promise<Response>;

export interface Label309ClientConfig {
  /**
   * Bearer credential, forwarded verbatim as `Authorization: Bearer <apiKey>`.
   *
   * Treated as an OPAQUE token: the SDK never parses, validates, or infers
   * anything from it, since each Label 309 gateway issues keys in its own format.
   * Omit for anonymous read-only usage.
   */
  readonly apiKey?: string;
  /**
   * Base URL of the Label 309 gateway, INCLUDING the API version segment —
   * e.g. `https://gateway.example.com/api/v1` (a proxied deployment may carry a
   * path prefix, e.g. `https://host/gw/api/v1`). REQUIRED — the client is
   * gateway-agnostic and has no default deployment. The SDK appends only the
   * bare resource suffix (`/records`, `/poe/quote`, …) to this value, so the
   * version lives entirely in your configuration: a future `/api/v2` gateway is
   * reached by configuring `…/api/v2`, with no SDK change. Used VERBATIM (a
   * single trailing slash is stripped). A missing or empty value throws
   * `InvalidClientConfigError` from the constructor.
   */
  readonly baseUrl: string;
  /** Optional custom fetch (defaults to `globalThis.fetch`). */
  readonly fetch?: FetchImpl;
}

// =============================================================================
// POST /poe/uploads — multipart binary upload to a storage backend
// =============================================================================
//
// The SDK presents the wire shape directly: caller passes a `target` enum and
// a list of byte blobs; the SDK assembles the multipart form. Up to 32 files
// per call. The response carries a per-file outcome entry — successful files
// land as `{ok: true, uri, sha256, bytes}`, failed ones as `{ok: false, error}`.
//
// Partial-success returns 200 with mixed entries. The SDK surfaces this via
// `PartialUploadError` so callers can retry only the failed indices without
// re-uploading the successful ones.
//
// Billing: free. The storage cost is part of the publish quote (POST
// /poe/quote → POST /poe/publish); it is debited once at
// publish time against the locked price snapshot.

export type StorageTarget = 'arweave';

export interface UploadsInput {
  readonly target: StorageTarget;
  /** 1..32 file blobs. Position `i` lands on the response as `uploads[i]`. */
  readonly data: ReadonlyArray<Uint8Array>;
  readonly idempotencyKey?: string;
}

export interface UploadSuccessEntry {
  readonly idx: number;
  readonly ok: true;
  readonly uri: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface UploadFailureEntry {
  readonly idx: number;
  readonly ok: false;
  readonly error: { readonly code: string; readonly detail: string };
}

export type UploadEntry = UploadSuccessEntry | UploadFailureEntry;

export interface UploadsResponse {
  readonly uploads: ReadonlyArray<UploadEntry>;
}

// =============================================================================
// Resumable / chunked upload session — /poe/uploads/sessions/*
// =============================================================================
//
// A file larger than a client threshold is uploaded as a content-addressed
// session: declare the whole-file SHA-256 and total size up front, PUT each
// fixed-size chunk (out of order / in parallel is allowed), then complete. The
// gateway assembles the chunks server-side and runs the SAME storage pipeline
// the single-shot multipart upload runs, so both paths converge on one `ar://`
// URI and one charge per logical file. The single-shot `uploads()` is unchanged
// — the session flow is purely additive and chosen by `uploadResumable()` on
// file size.
//
// Chunk size is the SERVER's decision: the create response returns the
// authoritative `chunk_bytes` (the value it will accept) and a `max_chunk_bytes`
// ceiling, both of which the client honours.

/**
 * Body of `POST /poe/uploads/sessions`. `sha256` is the lowercase-hex
 * digest of the WHOLE file; `chunk_bytes` is the client's requested chunk size,
 * which the server clamps to `max_chunk_bytes` and echoes back authoritatively.
 */
export interface UploadSessionCreateRequest {
  readonly target: StorageTarget;
  readonly sha256: string;
  readonly total_bytes: number;
  readonly chunk_bytes: number;
  readonly content_type?: string;
}

/**
 * `201 Created` from session create. `chunk_bytes` is AUTHORITATIVE — the
 * client recomputes its chunk grid from this value, not from what it requested.
 */
export interface UploadSessionCreateResponse {
  readonly session_id: string;
  readonly chunk_bytes: number;
  readonly chunk_count: number;
  readonly received: ReadonlyArray<number>;
  readonly expires_at: string;
  readonly max_chunk_bytes: number;
}

/**
 * `200 OK` short-circuit returned by session create when the declared
 * `(account, backend, sha256)` already has a committed receipt: the existing
 * URI is returned and no bytes are uploaded.
 *
 * `charged_usd_micros` is a JSON number and is always `0` on this path (the
 * bytes were already stored, so nothing is charged).
 */
export interface UploadSessionDeduplicatedResponse {
  readonly deduplicated: true;
  readonly uri: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly charged_usd_micros: number;
}

/** `200 OK` from a chunk PUT — the running received-set after this chunk. */
export interface UploadSessionChunkResponse {
  readonly index: number;
  readonly received: ReadonlyArray<number>;
  readonly remaining: number;
  readonly complete: boolean;
}

export type UploadSessionState = 'open' | 'assembling' | 'completed' | 'failed' | 'expired';

/**
 * `GET /poe/uploads/sessions/{sid}` — the resume contract. A
 * reconnecting client reads `missing` and re-PUTs only those indices.
 */
export interface UploadSessionStatus {
  readonly session_id: string;
  readonly state: UploadSessionState;
  readonly sha256: string;
  readonly total_bytes: number;
  readonly chunk_bytes: number;
  readonly chunk_count: number;
  readonly received: ReadonlyArray<number>;
  readonly missing: ReadonlyArray<number>;
  readonly expires_at: string;
  readonly attempt_id: string | null;
  readonly uri: string | null;
}

/**
 * `POST /poe/uploads/sessions/{sid}/complete`. Either the terminal
 * committed/dedup outcome (`ok`), or `accepted` with an `attempt_id` to poll via
 * `GET /poe/uploads/attempts/{attempt_id}`.
 */
export interface UploadSessionCompletedResponse {
  readonly ok: true;
  readonly uri: string;
  readonly sha256: string;
  readonly bytes: number;
  /**
   * Storage USD (micro-USD) applied at completion, a JSON number: the number
   * `0` on a free-window or deduped-on-commit completion, the charge otherwise.
   */
  readonly charged_usd_micros: number;
}

export interface UploadSessionAcceptedResponse {
  readonly accepted: true;
  readonly attempt_id: string;
}

export type UploadSessionCompleteResponse =
  | UploadSessionCompletedResponse
  | UploadSessionAcceptedResponse;

/**
 * `GET /poe/uploads/attempts/{attempt_id}` — the terminal poll target
 * shared with the single-shot path.
 *
 *   - `reserved`  — still in flight; keep polling.
 *   - `committed` — terminal success; carries `uri` and `charged_usd_micros`.
 *   - `released`  — terminal failure; carries `reason`.
 *
 * `attempt_id`, `sha256`, `bytes`, and `backend` are present in every state;
 * `uri` / `charged_usd_micros` appear only on `committed`, `reason` only on
 * `released`. `bytes` and `charged_usd_micros` are JSON numbers. Modelled as a
 * discriminated union on `state` so a consumer that narrows on `state` sees
 * exactly the fields that state carries.
 */
export type UploadAttemptState = 'reserved' | 'committed' | 'released';

export type UploadAttemptReleaseReason = 'provider_rejected' | 'unrecoverable_staged_content_lost';

interface UploadAttemptCommon {
  readonly attempt_id: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly backend: string;
}

export interface UploadAttemptReserved extends UploadAttemptCommon {
  readonly state: 'reserved';
}

export interface UploadAttemptCommitted extends UploadAttemptCommon {
  readonly state: 'committed';
  readonly uri: string;
  readonly charged_usd_micros: number;
}

export interface UploadAttemptReleased extends UploadAttemptCommon {
  readonly state: 'released';
  /**
   * Why the attempt failed. The gateway emits a closed set today
   * (`provider_rejected` — retry; `unrecoverable_staged_content_lost` —
   * re-upload), but a forward-compatible consumer should treat the value as an
   * opaque string.
   */
  readonly reason: UploadAttemptReleaseReason | (string & {});
}

export type UploadAttemptStatus =
  | UploadAttemptReserved
  | UploadAttemptCommitted
  | UploadAttemptReleased;

// -----------------------------------------------------------------------------
// uploadResumable() — high-level threshold-gated single-file upload
// -----------------------------------------------------------------------------

/**
 * Per-chunk upload progress, passed to `UploadResumableInput.onProgress` after
 * each chunk is durably accepted by the gateway. `bytesSent` and `chunkIndex`
 * count only chunks uploaded in THIS invocation; on a resume that adopts already
 * stored chunks they advance from the missing set, not from zero, so a UI should
 * treat `bytesSent / totalBytes` as the fraction of the work this call performs.
 * The single-shot path reports one terminal 100% callback.
 */
export interface UploadProgress {
  /** Bytes durably accepted so far in this invocation. */
  readonly bytesSent: number;
  /** Declared total byte count of the file. */
  readonly totalBytes: number;
  /** Index of the chunk just accepted (0-based); `0` for the single-shot path. */
  readonly chunkIndex: number;
  /** Total number of chunks in the grid; `1` for the single-shot path. */
  readonly chunksTotal: number;
}

/**
 * Input to `uploadResumable()`. The `source` works in both runtimes: a
 * `Blob`/`File` in the browser, a `Uint8Array`, a filesystem path string, or a
 * pre-adapted `ResumableSource` on the server. The helper uploads at most one
 * file and returns its `ar://` URI.
 */
export interface UploadResumableInput {
  readonly target?: StorageTarget;
  /**
   * Bytes to upload: a browser `Blob`/`File` (sliced + streamed from disk), a
   * `Uint8Array`, a server filesystem path, or a `ResumableSource`.
   */
  readonly source: ResumableSourceInput;
  /**
   * Files at or below this size use the single-shot `uploads()` path unchanged;
   * larger files use the session flow. Defaults to ~48 MiB so an upload clears
   * common CDN/proxy single-request body caps below 100 MB.
   */
  readonly threshold?: number;
  /**
   * Requested chunk size for the session. The server clamps it to its
   * `max_chunk_bytes` and the helper honours the returned authoritative value.
   * Defaults to ~48 MiB.
   */
  readonly chunkBytes?: number;
  /** Number of chunk PUTs in flight at once (default 4). */
  readonly parallelism?: number;
  /** Per-chunk retry attempts on a transient PUT failure (default 4). */
  readonly maxChunkRetries?: number;
  /**
   * Stable key for `POST .../complete` replay. When omitted the helper derives
   * one deterministically from the declared digest so a re-invocation replays
   * the same terminal result rather than racing a second completion.
   */
  readonly idempotencyKey?: string;
  /** MIME type recorded for the assembled data item. */
  readonly contentType?: string;
  /**
   * Resume an interrupted upload: pass a `session_id` from a prior attempt and
   * the helper GETs its status and uploads only the missing indices.
   */
  readonly sessionId?: string;
  /** Abort signal forwarded to every underlying request. */
  readonly signal?: AbortSignal;
  /**
   * Invoked once the chunked session is created, BEFORE any chunk PUT, with the
   * server-issued `session_id`. Persist it immediately so a crash after create
   * but before this helper returns can still resume the upload with `sessionId`.
   * Not fired on the single-shot path (there is no session) or on a create-time
   * dedup hit. Errors thrown here propagate to the caller.
   */
  readonly onSessionCreated?: (sessionId: string) => void;
  /**
   * Invoked after each chunk is durably accepted (and once at 100% on the
   * single-shot path), with cumulative progress for THIS invocation. Throwing
   * from this callback aborts the upload. Progress reflects only work done in
   * this call — a resume starts its count from the missing set, not from zero.
   */
  readonly onProgress?: (progress: UploadProgress) => void;
}

/** Result of `uploadResumable()` — the committed storage location. */
export interface UploadResumableResult {
  /** Canonical `ar://<tx>` URI of the stored content. */
  readonly uri: string;
  /** Whole-file SHA-256, lowercase hex. */
  readonly sha256: string;
  /** Stored byte count. */
  readonly bytes: number;
  /** `true` when the bytes were already stored (create-time or commit-time dedup). */
  readonly deduplicated: boolean;
  /** Which ingress path carried the bytes. */
  readonly mode: 'single-shot' | 'chunked';
}

// =============================================================================
// POST /poe/quote — lock the price for an upcoming /publish call
// =============================================================================
//
// The gateway prices the described publish (from the supplied byte counts),
// records the price lock, and returns an OPAQUE quote: an id, the total
// `amount` in the gateway's `currency`, and an expiry. The quote is a sealed
// price token — the gateway's pricing internals are deliberately NOT part of
// the public response. `/publish` consumes the quote atomically by id and
// rejects expired / already-consumed quotes with `quote-expired` /
// `quote-already-consumed`.
//
// `amount` is a decimal string so callers can promote it to an exact bigint /
// decimal at the application boundary without floating-point loss.

export interface QuoteInput {
  /** Canonical-CBOR record length in bytes (header + items). */
  readonly recordBytes: number;
  /** Number of sealed-PoE recipients (each adds an envelope slot). */
  readonly recipientCount: number;
  /** Sum of all file bytes uploaded for this record (0 for hash-only). */
  readonly fileBytesTotal: number;
}

/**
 * The per-component cost split a gateway MAY attach to a quote. Each field is a
 * USD micro-cents decimal STRING (1 USD = 1,000,000 micros), parallel to
 * `QuoteResponse.usd_micros`. Present only when the gateway opts to surface its
 * breakdown; a gateway that keeps the quote fully opaque omits it.
 */
export interface QuoteBreakdown {
  /** Cardano transaction fee component, USD micro-cents (decimal string). */
  readonly network_usd_micros: string;
  /** Arweave storage component, USD micro-cents (decimal string). */
  readonly storage_usd_micros: string;
  /** Service/margin component, USD micro-cents (decimal string). */
  readonly service_usd_micros: string;
}

/**
 * The price lock returned by `POST /poe/quote`. The core token is `quote_id`
 * (pass to `/publish`) plus `amount` / `currency` / `expires_at` to surface to
 * the user.
 *
 * The remaining fields are an OPTIONAL pricing breakdown a gateway MAY attach
 * (the CardanoWall dashboard reads them); a gateway that keeps the quote fully
 * opaque omits every one and the response still parses. They are additive and
 * MUST NOT be relied on as present.
 */
export interface QuoteResponse {
  /** Opaque id of the persisted price lock; pass to /publish. */
  readonly quote_id: string;
  /** Total locked price, as a decimal string (promote to bigint/decimal as needed). */
  readonly amount: string;
  /** Currency the `amount` is denominated in (e.g. ISO 4217 `USD`). */
  readonly currency: string;
  /** ISO8601 expiry timestamp after which the gateway rejects the quote. */
  readonly expires_at: string;
  /**
   * Total price as USD micro-cents (decimal string) — the same value `amount`
   * carries when the gateway prices in USD, exposed in the canonical micro-cents
   * unit. Optional.
   */
  readonly usd_micros?: string;
  /** Optional per-component cost split (see {@link QuoteBreakdown}). */
  readonly breakdown?: QuoteBreakdown;
  /** Markup fraction the gateway applied, as a JSON number (e.g. 0.15). Optional. */
  readonly margin_pct?: number;
  /**
   * How the margin was attributed (e.g. `account-override` vs an operator
   * default). Opaque string; optional.
   */
  readonly margin_source?: string;
  /** Age of the FX snapshot used to price the quote, in seconds. Optional. */
  readonly fx_age_seconds?: number;
}

// =============================================================================
// POST /poe/publish — finalised single-record submission (JSON only)
// =============================================================================
//
// `record` carries the canonical-CBOR record bytes — either as raw `Uint8Array`
// or as a lowercase hex string. The SDK hex-encodes `Uint8Array` for the wire.
// All `ar://` URIs in the record MUST be real Arweave tx-ids — placeholders
// are rejected by the server. Storage uploads happen separately via /uploads.
//
// `quoteId` is required: pass the `quote_id` returned by /poe/quote. The
// server consumes it atomically with the poe_record insert; expired or
// already-consumed quotes raise `quote-expired` / `quote-already-consumed`.

export interface RecordSignature {
  readonly cose_sign1: string;
  readonly cose_key?: string;
}

export interface PublishInput {
  readonly record: Uint8Array | string;
  /** UUID returned by POST /poe/quote. */
  readonly quoteId: string;
  readonly signatures?: ReadonlyArray<RecordSignature>;
  readonly idempotencyKey?: string;
}

/**
 * Publish lifecycle status as carried by the publish responses and
 * `GET /poe/events/<id>`. The named members are the values the gateway emits
 * today; the `(string & {})` arm keeps the union forward-tolerant so a status a
 * newer gateway introduces still parses (and still autocompletes the known
 * members) instead of failing the type.
 */
export type PoeStatus =
  | 'submitting'
  | 'submitted'
  | 'confirming'
  | 'confirmed'
  | 'permanent_failure'
  | 'failed'
  | (string & {});
export type ConformanceProfile = 'core' | 'signed' | 'sealed' | 'recipient-sealed';

export interface PoeItemResponse {
  readonly item_idx: number;
  readonly hashes: Record<string, string>;
  readonly uris?: ReadonlyArray<string>;
  readonly enc?: Record<string, unknown>;
}

export interface PublishResponse {
  /** Wire-format prefixed id (`poe_<26-char-crockford-base32>`) of the
   *  freshly-inserted `poe_record` row. Stable across the submit→confirm
   *  lifecycle; use it to subscribe to live status frames via
   *  `GET /poe/events/<id>`. */
  readonly id: string;
  readonly tx_hash: string | null;
  readonly status: PoeStatus;
  readonly items_count: number;
  readonly signed: boolean;
  readonly sealed: boolean;
  readonly items: ReadonlyArray<PoeItemResponse>;
  readonly conformance_profile: ConformanceProfile;
  /** Account balance after the debit, USD micro-cents (decimal string). */
  readonly balance_after_usd_micros: string;
  /**
   * `true` when the server returned 200 (dedup hit on the prior submission
   * of an identical record by this account) rather than 202 (freshly
   * enqueued).
   */
  readonly dedup_hit: boolean;
}

// =============================================================================
// POST /poe/publish-batch — 1..50 finalised records as independent txs
// =============================================================================
//
// Partial-success: per-record errors land in `results[]` without rolling back
// the batch — successful records still publish. The aggregate
// `balance_after_usd_micros` reflects only the entries that actually queued.

export interface PublishBatchEntry {
  readonly record: Uint8Array | string;
  /** UUID returned by POST /poe/quote, scoped to this record. */
  readonly quoteId: string;
  readonly signatures?: ReadonlyArray<RecordSignature>;
}

export interface PublishBatchInput {
  readonly records: ReadonlyArray<PublishBatchEntry>;
  readonly idempotencyKey?: string;
}

export interface PublishBatchSuccessEntry {
  readonly record_idx: number;
  readonly id: string;
  readonly tx_hash: string | null;
  readonly status: PoeStatus;
  readonly items_count: number;
  readonly signed: boolean;
  readonly sealed: boolean;
  readonly items: ReadonlyArray<PoeItemResponse>;
  readonly conformance_profile: ConformanceProfile;
}

// A per-record failure entry inside the 200 `results[]` payload. Same
// lowercase-kebab `code` + `detail` shape as the top-level RFC 7807 envelope —
// but only the body-level fields, since the entry is already nested inside a
// 200 response (no per-row `type`/`status`/`trace_id`).
export interface PublishBatchFailureError {
  readonly code: string;
  readonly detail: string;
  readonly errors?: ReadonlyArray<{
    readonly field: string;
    readonly code: string;
    readonly detail: string;
  }>;
  readonly extensions?: Record<string, unknown>;
}

export interface PublishBatchFailureEntry {
  readonly record_idx: number;
  readonly error: PublishBatchFailureError;
}

export type PublishBatchResultEntry = PublishBatchSuccessEntry | PublishBatchFailureEntry;

export interface PublishBatchResponse {
  readonly results: ReadonlyArray<PublishBatchResultEntry>;
  /** Aggregate balance after every successful debit in the batch. */
  readonly balance_after_usd_micros: string;
}

// =============================================================================
// GET /records/{tx_hash} — single record resource (Stripe-style)
// =============================================================================
//
// `RecordResource` is also the per-row shape projected into `data[]` of
// `GET /records`. snake_case wire field names, owner-only `account_id`
// omitted for anonymous + cross-account callers.
//
// `status` carries the chain-derived lifecycle ('confirming' / 'confirmed')
// on anchored rows for all viewers; owner-only un-anchored rows surface
// 'submitting' / 'failed'. The field is `null` only as defense-in-depth for
// the impossible un-anchored-leaked-to-non-owner case.

export type RecordStatus = 'submitting' | 'confirming' | 'confirmed' | 'failed';

export type RecordScheme = 0 | 1 | 2;

export interface RecordResource {
  readonly tx_hash: string;
  readonly status: RecordStatus | null;
  readonly block_height: number | null;
  readonly block_time: string | null;
  readonly num_confirmations: number;
  readonly scheme: RecordScheme;
  readonly item_count: number;
  readonly signer_ed25519: string | null;
  readonly metadata_cbor_base64: string;
  /** Owner-only — present iff the caller authenticated as the row's owner. */
  readonly account_id?: string;
}

// =============================================================================
// GET /records — paginated record list (client.records.list)
// =============================================================================
//
// The optional `sealed` filter narrows the page to sealed records addressed to
// the authenticated caller (the gateway resolves "addressed to me" from the
// identity behind the bearer token); omitting it lists every record the caller
// may read. Each page entry is the same `RecordResource` projection
// `records.get` returns.

export interface RecordsListInput {
  /** Opaque pagination cursor — pass back the `next_cursor` from a prior page. */
  readonly cursor?: string | null;
  /** Page size (the gateway may clamp). */
  readonly limit?: number;
  /**
   * When `true`, restrict the page to sealed records addressed to the
   * authenticated caller. When omitted, list every record the caller may read.
   */
  readonly sealed?: boolean;
}

export interface RecordsListResponse {
  readonly object: 'list';
  readonly data: ReadonlyArray<RecordResource>;
  readonly has_more: boolean;
  readonly next_cursor: string | null;
  readonly url: string;
  /**
   * The chain tip block height observed when this page was served, used to
   * compute confirmation depth during a sealed-record sync.
   *
   * Optional: a gateway that reports it (JSON key `tip_block_height`) populates
   * confirmation data directly; otherwise the SDK derives it from the page rows
   * as `max(block_height + num_confirmations - 1)`, falling back to `null` for
   * an empty page or rows without a block height.
   */
  readonly tip_block_height?: number | null;
}

// =============================================================================
// GET /records/count — exact count of records matching a filter
// =============================================================================
//
// The counting counterpart to `GET /records`: the paginated feed never carries
// a total, so a caller that needs the cardinality of a filter (a profile's proof
// count, an explorer facet) asks here. It accepts the same narrowing grammar as
// `list`, but `signer` is REQUIRED — a count's cost is the size of the matching
// set, which only a signer scope bounds, so the gateway rejects a signer-less
// count with 422. The count is over the public anchored set only and carries no
// owner-only projection.

export interface RecordsCountInput {
  /**
   * 64 lowercase-hex characters (a 32-byte Ed25519 publisher key). REQUIRED:
   * the gateway 422s a count without a signer, since a signer is the only filter
   * that bounds the count's cost.
   */
  readonly signer: string;
  /** Narrow to a single record scheme: 0 (open), 1 (sealed), or 2 (passphrase). */
  readonly scheme?: RecordScheme;
  /** Narrow to sealed records (scheme != 0). */
  readonly sealed?: boolean;
  /** Inclusive lower bound on block height. */
  readonly fromBlock?: number;
  /** Inclusive upper bound on block height. */
  readonly toBlock?: number;
  /** Inclusive lower bound on block time (ISO8601). */
  readonly fromTime?: string;
  /** Inclusive upper bound on block time (ISO8601). */
  readonly toTime?: string;
}

export interface RecordsCountResponse {
  readonly object: 'count';
  /** The exact number of records matching the filter. */
  readonly count: number;
  /** The canonical resource path the count was served from. */
  readonly url: string;
}

// =============================================================================
// GET /account/balance
// =============================================================================

/**
 * The caller's current prepaid USD balance.
 *
 * `balanceUsdMicros` is the gateway's `balance_usd_micros` wire field — the
 * balance in USD micro-cents, carried as a decimal STRING (never a JS number)
 * so the bigint value survives JSON without precision loss. An account with no
 * ledger activity yet reads `"0"`.
 */
export interface AccountBalance {
  readonly balanceUsdMicros: string;
}

// =============================================================================
// High-level publish helpers (publishContent / publishSealed / publishMerkle)
// =============================================================================
//
// The low-level uploads / publish methods are honest but verbose. The helpers
// below collapse the common flows into a single call:
//
//   - publishContent({content, quoteId, signer?})              — hash-only
//   - publishSealed({content, recipients, quoteId, signer?})   — sealed envelope
//   - publishMerkle({leaves, quoteId, signer?})                — Merkle batch root
//
// Each takes a `quoteId` obtained from a prior call to POST /poe/quote.
//
// Signer architecture (see `off-host-sign.ts` privacy contract): the SDK does
// NOT carry identity keys. Callers pass a `Signer` that owns the Ed25519
// private key (in-memory, KMS, HSM, air-gapped, …). The SDK only ever touches
// the 32-byte public key and the 64-byte signature — both public data.

/**
 * Pluggable Ed25519 signer for the high-level publish helpers. The SDK does
 * NOT hold identity keys (see the privacy contract in `off-host-sign.ts`); the
 * caller owns the key material and decides how to expose signing — in-memory
 * `@noble/ed25519`,
 * AWS KMS, GCP HSM, YubiHSM, an air-gapped offline signer, or a CIP-30
 * wallet wrapper.
 *
 * `signerPubkey` MUST be the 32-byte raw Ed25519 public key.
 *
 * `sign(sigStructureBytes)` receives the canonical-CBOR
 * `[ "Signature1", protected_bytes, h'' /* empty external_aad *\/, to_sign ]`
 * bytes and MUST return a 64-byte raw Ed25519 signature (NOT a DER-encoded
 * one). This is byte-identical to the input accepted by AWS KMS `Sign` for
 * Ed25519 keys.
 */
export interface Signer {
  readonly signerPubkey: Uint8Array;
  sign(sigStructureBytes: Uint8Array): Promise<Uint8Array>;
}

export type SupportedHashAlg = 'sha2-256' | 'blake2b-256';

export interface PublishContentInput {
  /** Content bytes to anchor. Strings are UTF-8 encoded before hashing. */
  readonly content: Uint8Array | string;
  /** UUID returned by POST /poe/quote. */
  readonly quoteId: string;
  /** Hash algorithm registered in the Label 309 hash registry. */
  readonly hashAlg?: SupportedHashAlg;
  /** Optional signer — when omitted the record publishes unsigned (profile=core). */
  readonly signer?: Signer;
  readonly idempotencyKey?: string;
}

/**
 * Hash-already-computed variant. Use when the caller already holds the
 * content digest (`sha2-256` and/or `blake2b-256`) — e.g. the CLI's `--hash`
 * mode, an air-gapped offline hashing flow, or a system that proxies digests
 * from another tool. The SDK does not re-hash; it constructs a single-item
 * record with the supplied digests in `items[0].hashes` and (optionally)
 * signs.
 */
export interface PublishPrehashedInput {
  readonly hashes: Partial<Record<SupportedHashAlg, string>>;
  /** UUID returned by POST /poe/quote. */
  readonly quoteId: string;
  readonly signer?: Signer;
  readonly idempotencyKey?: string;
}

/**
 * Sealed-PoE helper input. Encrypts `content` to the supplied X25519
 * recipient public keys (age-style sealed envelope), uploads the ciphertext
 * to Arweave via /uploads, builds a Label 309 record with the resulting
 * `ar://` URI in `items[0].uris`, optionally signs it, and submits to
 * /publish.
 *
 * Each recipient public key is a 32-byte raw X25519 public key. At least
 * one recipient is required; the sender SHOULD include themselves as a
 * recipient to retain decrypt access.
 */
export interface PublishSealedInput {
  readonly content: Uint8Array | string;
  /**
   * Recipient public keys. The length each key MUST be matches the chosen
   * `kem`: 32 bytes for `x25519`, 1216 bytes for `mlkem768x25519` (X-Wing).
   */
  readonly recipients: ReadonlyArray<Uint8Array>;
  /** UUID returned by POST /poe/quote. */
  readonly quoteId: string;
  /** Hash algorithm for the plaintext-bind hash in `items[0].hashes`. */
  readonly hashAlg?: SupportedHashAlg;
  /**
   * KEM the sealed envelope is built under. Defaults to `mlkem768x25519`
   * (X-Wing hybrid, ML-KEM-768 + X25519) — the post-quantum-safe choice. Pass
   * `x25519` only for the classical, higher-capacity path. Every recipient MUST
   * be addressed under this single KEM; mixing is not permitted.
   */
  readonly kem?: 'x25519' | 'mlkem768x25519';
  readonly signer?: Signer;
  readonly idempotencyKey?: string;
}

export interface PublishMerkleInput {
  /**
   * Leaf hashes — either raw 32-byte Uint8Array digests or hex-encoded
   * strings (64 chars, case-insensitive). Tree size is `leaves.length`.
   */
  readonly leaves: ReadonlyArray<Uint8Array | string>;
  /** UUID returned by POST /poe/quote. */
  readonly quoteId: string;
  /**
   * Leaf-hash algorithm. Only `'sha2-256'` is supported in v1 because the
   * single registered tree algorithm is `rfc9162-sha256` (SHA-256 underlying).
   */
  readonly hashAlg?: 'sha2-256';
  readonly signer?: Signer;
  readonly idempotencyKey?: string;
}

export interface PublishMerkleResponse {
  readonly id: string;
  readonly tx_hash: string | null;
  readonly status: PoeStatus;
  readonly root: string;
  readonly leaf_count: number;
  readonly ar_uri: string;
  /** Account balance after the debit, USD micro-cents (decimal string). */
  readonly balance_after_usd_micros: string;
}
