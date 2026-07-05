// High-level publish helpers — collapse the quote + uploads + publish flow
// into single calls for the common shapes:
//
//   1. `publishContent({content, quoteId, signer?})` — anchor a single content
//      blob by its `sha2-256` (or `blake2b-256`) digest. No Arweave, no
//      /uploads — the record is constructed entirely client-side and posted
//      directly to /publish against a caller-supplied quote.
//
//   2. `publishPrehashed({hashes, quoteId, signer?})` — the caller already
//      holds the digest(s).
//
//   3. `publishMerkle({leaves, signer?})` — anchor an arbitrary number of leaf
//      hashes under a single RFC 9162 §2.1.1 root, with the leaves-list CBOR
//      uploaded to Arweave via /uploads. The helper quotes internally from the
//      exact-width record-size estimate, enforces the caller's price cap, and
//      refreshes the price lock when the upload outlived it.
//
// The sealed-PoE flow lives in `./sealed`: the two-phase `sealPrepare` /
// `submitSealed` pair plus the one-shot `publishSealed` wrapper.
//
// Signer architecture: the SDK does NOT hold identity keys (privacy contract
// in `off-host-sign.ts`). The helpers take an optional `Signer` that owns the
// Ed25519 private key (in-memory `@noble/ed25519`, AWS KMS, GCP HSM, …). The
// helper builds the canonical `Sig_structure`, hands the bytes to the signer,
// and never sees the private key. When `signer` is omitted the record
// publishes unsigned (conformance profile `core` for hash-only;
// `sealed` for sealed envelopes).

import {
  sha256,
  blake2b256,
  merkleSha2256Root,
  MERKLE_ALG_ID,
} from '@cardanowall/crypto-core/hash';
import { encodeLeavesList } from '@cardanowall/crypto-core/merkle';
import { encodePoeRecord, type MerkleCommit, type PoeRecord } from '@cardanowall/poe-standard';

import { estimateRecordBytes, type RecordShape } from '../estimate/index';
import { MaxUsdExceededError } from './max-usd-exceeded-error';
import { assembleCoseSign1, prepareSigStructure } from './off-host-sign';
import { PartialUploadError } from './partial-upload-error';
import { parseHttpError } from './parse-http-error';
import {
  uploadResumable,
  DEFAULT_RESUMABLE_THRESHOLD_BYTES,
  type SingleShotUpload,
} from './resumable-upload';
import type {
  FetchImpl,
  PublishContentInput,
  PublishMerkleInput,
  PublishMerkleResponse,
  PublishPrehashedInput,
  PublishResponse,
  QuoteInput,
  QuoteResponse,
  Signer,
  StorageTarget,
  SupportedHashAlg,
  UploadsResponse,
  UploadSuccessEntry,
} from './types';

const ED25519_PUBLIC_KEY_LENGTH = 32;
const ED25519_SIGNATURE_LENGTH = 64;
const LEAF_DIGEST_LENGTH = 32;
const STORAGE_TARGET_ARWEAVE = 'arweave' as const;

// An Arweave transaction id is always 43 base64url characters, so a not-yet-
// minted `ar://<tx>` URI has a fixed final width. Charging a placeholder of
// exactly that width in a pre-upload record-size estimate keeps the quoted
// `record_bytes` an upper bound of the published record.
const ARWEAVE_TX_ID_CHARS = 43;

// The prefix of the deterministic leaves-list upload idempotency key, and how
// many leading hex characters of the leaves-list digest the key carries.
const MERKLE_UPLOAD_KEY_PREFIX = 'merkle1-';
const MERKLE_UPLOAD_KEY_DIGEST_CHARS = 32;

export interface ResolvedPublishConfig {
  readonly apiKey: string | undefined;
  readonly baseUrl: string;
  readonly fetch: FetchImpl;
}

export class PublishError extends Error {
  readonly code:
    | 'INVALID_SIGNER_PUBKEY'
    | 'INVALID_SIGNER_SIGNATURE'
    | 'INVALID_LEAVES'
    | 'INVALID_DIGEST'
    | 'INVALID_RECIPIENT'
    | 'UNSUPPORTED_HASH_ALG'
    | 'INVALID_MAX_USD'
    | 'INVALID_QUOTE_AMOUNT';

  constructor(code: PublishError['code'], message: string) {
    super(message);
    this.name = 'PublishError';
    this.code = code;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** The value of one hex digit, or `undefined` for any other character. */
function hexNibble(code: number): number | undefined {
  if (code >= 48 && code <= 57) return code - 48; // 0-9
  if (code >= 97 && code <= 102) return code - 97 + 10; // a-f
  if (code >= 65 && code <= 70) return code - 65 + 10; // A-F
  return undefined;
}

/**
 * Strict hex decode: an even length and every character in `[0-9a-fA-F]`
 * (mixed case accepted), rejecting whitespace, sign characters, and any other
 * byte. This is deliberately stricter than `parseInt`, which silently tolerates
 * `"4z"`, `" 4"`, `"+5"`, or `"-1"` and would decode corrupted digest / leaf
 * bytes that then get hashed, priced, and anchored on-chain. The accept/reject
 * set matches the Rust SDK's `hex::decode`, so the same input is honoured or
 * refused identically across implementations. `code` is the `PublishError`
 * code the caller's field maps to (leaves vs digest).
 */
function hexToBytes(hex: string, code: PublishError['code']): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new PublishError(code, `hex string has odd length: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexNibble(hex.charCodeAt(i * 2));
    const lo = hexNibble(hex.charCodeAt(i * 2 + 1));
    if (hi === undefined || lo === undefined) {
      throw new PublishError(code, `invalid hex byte at offset ${i * 2}`);
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

export function toBytes(content: Uint8Array | string): Uint8Array {
  if (typeof content === 'string') return new TextEncoder().encode(content);
  return content;
}

// Allocate a fresh Uint8Array (with a concrete ArrayBuffer backing, not
// ArrayBufferLike) so the result satisfies the strict `Uint8Array<ArrayBuffer>`
// generic that Zod infers for hash-digest schemas. @noble/hashes returns the
// generic `Uint8Array<ArrayBufferLike>` shape; an explicit clone collapses it
// to the strict variant without `as` casts.
function cloneToOwnedBuffer(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(src.length));
  out.set(src);
  return out;
}

export function hashContent(bytes: Uint8Array, alg: SupportedHashAlg): Uint8Array<ArrayBuffer> {
  if (alg === 'sha2-256') return cloneToOwnedBuffer(sha256(bytes));
  if (alg === 'blake2b-256') return cloneToOwnedBuffer(blake2b256(bytes));
  throw new PublishError(
    'UNSUPPORTED_HASH_ALG',
    `hashAlg must be 'sha2-256' or 'blake2b-256', got '${alg as string}'`,
  );
}

export function assertSigner(signer: Signer): void {
  if (
    !(signer.signerPubkey instanceof Uint8Array) ||
    signer.signerPubkey.length !== ED25519_PUBLIC_KEY_LENGTH
  ) {
    throw new PublishError(
      'INVALID_SIGNER_PUBKEY',
      `signer.signerPubkey must be a Uint8Array(${ED25519_PUBLIC_KEY_LENGTH})`,
    );
  }
  if (typeof signer.sign !== 'function') {
    throw new PublishError('INVALID_SIGNER_PUBKEY', 'signer.sign must be a function');
  }
}

function buildJsonHeaders(apiKey: string | undefined, idempotencyKey?: string): Headers {
  const headers = new Headers({ 'content-type': 'application/json', accept: 'application/json' });
  if (apiKey !== undefined) headers.set('authorization', `Bearer ${apiKey}`);
  if (idempotencyKey !== undefined) headers.set('idempotency-key', idempotencyKey);
  return headers;
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseRetryAfter(header: string | null): number | undefined {
  if (header === null) return undefined;
  const parsed = Number(header);
  return Number.isFinite(parsed) ? parsed : undefined;
}

async function throwIfNotOk(response: Response): Promise<void> {
  if (response.ok) return;
  const body = await readJson(response);
  const requestId = response.headers.get('x-request-id') ?? undefined;
  const retryAfterSeconds = parseRetryAfter(response.headers.get('retry-after'));
  throw parseHttpError({ httpStatus: response.status, body, requestId, retryAfterSeconds });
}

/**
 * Sign a record path-1 (in-memory Ed25519 / KMS / HSM) and return the final
 * canonical-CBOR bytes ready for /publish. The signature is embedded into
 * the record's `sigs[]` field — the wire `signatures` parameter on /publish
 * is reserved for the path-2 wallet flow (CIP-30 cose_key sidecar).
 */
async function signAndEncodeRecord(record: PoeRecord, signer: Signer): Promise<Uint8Array> {
  const { sigStructureBytes } = prepareSigStructure({
    record,
    signerPubkey: signer.signerPubkey,
  });
  const signature = await signer.sign(sigStructureBytes);
  if (!(signature instanceof Uint8Array) || signature.length !== ED25519_SIGNATURE_LENGTH) {
    throw new PublishError(
      'INVALID_SIGNER_SIGNATURE',
      `signer.sign() must return a Uint8Array(${ED25519_SIGNATURE_LENGTH}); got length ${
        signature instanceof Uint8Array ? signature.length : 'non-Uint8Array'
      }`,
    );
  }
  const { sigEntry } = assembleCoseSign1({
    record,
    signerPubkey: signer.signerPubkey,
    signature,
  });
  const signed: PoeRecord = { ...record, sigs: [sigEntry] };
  return encodePoeRecord(signed);
}

export async function encodeRecord(
  record: PoeRecord,
  signer: Signer | undefined,
): Promise<Uint8Array> {
  if (signer === undefined) return encodePoeRecord(record);
  return signAndEncodeRecord(record, signer);
}

export async function postPublish(
  config: ResolvedPublishConfig,
  recordBytesHex: string,
  quoteId: string,
  idempotencyKey: string | undefined,
): Promise<PublishResponse> {
  const body = { record: recordBytesHex, quote_id: quoteId };
  const response = await config.fetch(`${config.baseUrl}/poe/publish`, {
    method: 'POST',
    headers: buildJsonHeaders(config.apiKey, idempotencyKey),
    body: JSON.stringify(body),
  });
  await throwIfNotOk(response);
  const parsed = (await readJson(response)) as Omit<PublishResponse, 'dedup_hit'>;
  return { ...parsed, dedup_hit: response.status === 200 };
}

/** POST a quote request for the given byte counts and return the price lock. */
export async function postQuote(
  config: ResolvedPublishConfig,
  input: QuoteInput,
): Promise<QuoteResponse> {
  const body = {
    record_bytes: input.recordBytes,
    recipient_count: input.recipientCount,
    file_bytes_total: input.fileBytesTotal,
  };
  const response = await config.fetch(`${config.baseUrl}/poe/quote`, {
    method: 'POST',
    headers: buildJsonHeaders(config.apiKey),
    body: JSON.stringify(body),
  });
  await throwIfNotOk(response);
  return (await readJson(response)) as QuoteResponse;
}

// Single-shot multipart upload of one blob, resolving its `ar://` URI. Backs
// the small-blob branch of `uploadBlob` and the resumable helper's
// below-threshold fast path.
const singleShotUpload =
  (config: ResolvedPublishConfig): SingleShotUpload =>
  async ({ target, bytes, idempotencyKey, signal }) => {
    const form = new FormData();
    form.append('target', target);
    form.append(
      'file_0',
      new Blob([bytes as unknown as ArrayBuffer], { type: 'application/octet-stream' }),
      'file_0.bin',
    );
    const headers = new Headers({ accept: 'application/json' });
    if (config.apiKey !== undefined) headers.set('authorization', `Bearer ${config.apiKey}`);
    if (idempotencyKey !== undefined) headers.set('idempotency-key', idempotencyKey);
    const response = await config.fetch(`${config.baseUrl}/poe/uploads`, {
      method: 'POST',
      headers,
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

// Upload one blob (sealed ciphertext or Merkle leaves-list) and return its
// `ar://` URI. A blob at or below the resumable threshold takes the unchanged
// single-shot multipart path; a larger blob transparently uses the resumable
// session flow so a multi-GB ciphertext clears CDN/proxy single-request caps.
// Both paths end at the same URI, so the publisher helpers' signatures and
// on-chain record shape are unaffected by the blob's size.
export async function uploadBlob(
  config: ResolvedPublishConfig,
  bytes: Uint8Array,
  idempotencyKey: string | undefined,
  chunkBytes: number | undefined,
): Promise<string> {
  const target: StorageTarget = STORAGE_TARGET_ARWEAVE;
  if (bytes.byteLength <= DEFAULT_RESUMABLE_THRESHOLD_BYTES) {
    const single = await singleShotUpload(config)({
      target,
      bytes,
      ...(idempotencyKey !== undefined ? { idempotencyKey } : {}),
    });
    return single.uri;
  }
  const result = await uploadResumable(config, singleShotUpload(config), {
    target,
    source: bytes,
    ...(idempotencyKey !== undefined ? { idempotencyKey } : {}),
    ...(chunkBytes !== undefined ? { chunkBytes } : {}),
  });
  return result.uri;
}

// =============================================================================
// Quote freshness and the price cap
// =============================================================================

/**
 * A worst-case-width stand-in for a not-yet-minted `ar://<tx>` URI, used in
 * pre-upload record-size estimates.
 */
export function arweaveUriPlaceholder(): string {
  return `ar://${'A'.repeat(ARWEAVE_TX_ID_CHARS)}`;
}

// The quote-expiry safety margin: a quote expiring within this window is
// refreshed rather than raced against the gateway's TTL check at consume time.
const QUOTE_EXPIRY_SKEW_MS = 30_000;

/**
 * Parse an RFC 3339 timestamp (date, time, optional fractional seconds, a
 * `Z` or `±HH:MM` offset) to epoch milliseconds. Returns `undefined` for
 * anything else — including a timestamp with no offset, which `Date.parse`
 * would otherwise read in the host's local zone and make the freshness
 * verdict machine-dependent.
 */
function rfc3339ToEpochMs(text: string): number | undefined {
  const match =
    /^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)([Zz]|[+-]\d{2}:\d{2})$/.exec(
      text.trim(),
    );
  if (match === null) return undefined;
  const offset = match[3]!;
  const iso = `${match[1]}T${match[2]}${offset === 'z' ? 'Z' : offset}`;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? undefined : ms;
}

/**
 * Whether the price lock is still comfortably inside its TTL. An unparseable
 * `expires_at` reads as fresh: the client cannot assess it, a re-quote would
 * carry an equally unparseable one, and the gateway stays the authority at
 * consume time.
 */
export function quoteIsFresh(quote: QuoteResponse): boolean {
  const expires = rfc3339ToEpochMs(quote.expires_at);
  if (expires === undefined) return true;
  return Date.now() + QUOTE_EXPIRY_SKEW_MS < expires;
}

/**
 * Normalize a caller-supplied price cap to a non-negative bigint of USD
 * micro-cents. Strings must be plain decimal integers (money never rides a
 * float). Returns `undefined` when no cap was given.
 */
export function normalizeMaxUsdMicros(value: bigint | string | undefined): bigint | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new PublishError('INVALID_MAX_USD', `maxUsdMicros must be non-negative, got ${value}`);
    }
    return value;
  }
  if (!/^\d+$/.test(value)) {
    throw new PublishError(
      'INVALID_MAX_USD',
      `maxUsdMicros must be a decimal micro-USD string, got ${JSON.stringify(value)}`,
    );
  }
  return BigInt(value);
}

/**
 * Refuse to proceed when the quoted price exceeds the caller's cap in USD
 * micro-cents. Money stays an integer in-process and a decimal string on the
 * wire, so the comparison parses the gateway's `amount` string exactly.
 */
export function enforceMaxUsdMicros(maxUsdMicros: bigint | undefined, quote: QuoteResponse): void {
  if (maxUsdMicros === undefined) return;
  if (!/^\d+$/.test(quote.amount)) {
    throw new PublishError(
      'INVALID_QUOTE_AMOUNT',
      `quote amount ${JSON.stringify(quote.amount)} is not a decimal micro-USD string`,
    );
  }
  if (BigInt(quote.amount) > maxUsdMicros) {
    throw new MaxUsdExceededError({ quotedUsdMicros: quote.amount, maxUsdMicros });
  }
}

/**
 * Re-establish the price lock when a slow step (a storage upload) outlived
 * the quote's TTL: fetch a fresh quote for the same shape and re-enforce the
 * price cap against the NEW price — FX may have moved while the upload ran,
 * and the cap is a promise about what gets spent.
 */
export async function refreshQuoteIfStale(
  config: ResolvedPublishConfig,
  quote: QuoteResponse,
  input: QuoteInput,
  maxUsdMicros: bigint | undefined,
): Promise<QuoteResponse> {
  if (quoteIsFresh(quote)) return quote;
  const fresh = await postQuote(config, input);
  enforceMaxUsdMicros(maxUsdMicros, fresh);
  return fresh;
}

/**
 * Hash-only PoE — anchor a single content blob's digest, optionally with
 * one path-1 signature. No Arweave, no /uploads.
 */
export async function publishContent(
  config: ResolvedPublishConfig,
  input: PublishContentInput,
): Promise<PublishResponse> {
  if (input.signer !== undefined) assertSigner(input.signer);
  const hashAlg: SupportedHashAlg = input.hashAlg ?? 'sha2-256';
  const contentBytes = toBytes(input.content);
  const digest = hashContent(contentBytes, hashAlg);

  const record: PoeRecord = {
    v: 1,
    items: [{ hashes: { [hashAlg]: digest } }],
  };
  const recordBytes = await encodeRecord(record, input.signer);
  return postPublish(config, bytesToHex(recordBytes), input.quoteId, input.idempotencyKey);
}

// `sha2-256` and `blake2b-256` both produce 32-byte digests. Kept as a
// per-alg map for forward-compat when wider hash registries land.
const DIGEST_BYTE_LENGTH: Record<SupportedHashAlg, number> = {
  'sha2-256': 32,
  'blake2b-256': 32,
};

/**
 * Hash-already-computed PoE — anchor a precomputed content digest (the user
 * already has it), optionally signed. The SDK does not re-hash; it
 * constructs a single-item record with the supplied digests in
 * `items[0].hashes`.
 */
export async function publishPrehashed(
  config: ResolvedPublishConfig,
  input: PublishPrehashedInput,
): Promise<PublishResponse> {
  if (input.signer !== undefined) assertSigner(input.signer);
  const entries = Object.entries(input.hashes) as Array<[SupportedHashAlg, string | undefined]>;
  const present = entries.filter(([, hex]) => typeof hex === 'string' && hex.length > 0) as Array<
    [SupportedHashAlg, string]
  >;
  if (present.length === 0) {
    throw new PublishError(
      'INVALID_DIGEST',
      'publishPrehashed requires at least one digest in `hashes`',
    );
  }
  const decoded: Record<string, Uint8Array<ArrayBuffer>> = {};
  for (const [alg, hex] of present) {
    if (!(alg in DIGEST_BYTE_LENGTH)) {
      throw new PublishError(
        'UNSUPPORTED_HASH_ALG',
        `unsupported hash algorithm '${alg as string}' (expected 'sha2-256' or 'blake2b-256')`,
      );
    }
    const bytes = hexToBytes(hex, 'INVALID_DIGEST');
    const expected = DIGEST_BYTE_LENGTH[alg];
    if (bytes.length !== expected) {
      throw new PublishError(
        'INVALID_DIGEST',
        `hashes[${alg}] must be a ${expected}-byte digest (got ${bytes.length} bytes)`,
      );
    }
    decoded[alg] = cloneToOwnedBuffer(bytes);
  }

  const record: PoeRecord = {
    v: 1,
    items: [{ hashes: decoded }],
  };
  const recordBytes = await encodeRecord(record, input.signer);
  return postPublish(config, bytesToHex(recordBytes), input.quoteId, input.idempotencyKey);
}

/**
 * The deterministic leaves-list upload idempotency key:
 * `"merkle1-" + sha256(leavesListBytes)[..32]`. The leaves-list encoding is
 * canonical, so the same batch always presents the same key and a
 * crash-and-retry can never double-pay its storage upload.
 */
function merkleUploadIdempotencyKey(leavesList: Uint8Array): string {
  const digest = bytesToHex(sha256(leavesList));
  return `${MERKLE_UPLOAD_KEY_PREFIX}${digest.slice(0, MERKLE_UPLOAD_KEY_DIGEST_CHARS)}`;
}

/**
 * Merkle batch publish — N leaves under one transaction. The leaves-list
 * CBOR is uploaded to Arweave as a single blob; the on-chain record carries
 * `merkle[0] = { alg: 'rfc9162-sha256', root, leaf_count, uris: [ar://<tx>] }`.
 *
 * The helper owns the whole priced flow: it quotes internally from the
 * exact-width record-size estimate (the `ar://` URI exists only after the
 * upload, but an Arweave transaction id is fixed-width, so the estimate is
 * exact), enforces `maxUsdMicros`, uploads the canonical leaves-list under a
 * deterministic idempotency key derived from the leaves-list bytes (a retry
 * of the same batch never pays for its storage twice), refreshes the price
 * lock when the upload outlived it, and publishes. The response carries the
 * exact published record bytes.
 *
 * Only `sha2-256` leaves are supported because `rfc9162-sha256` is the only
 * registered tree algorithm and its underlying hash is SHA-256 (32-byte
 * leaves).
 */
export async function publishMerkle(
  config: ResolvedPublishConfig,
  input: PublishMerkleInput,
): Promise<PublishMerkleResponse> {
  if (input.signer !== undefined) assertSigner(input.signer);
  if (input.hashAlg !== undefined && input.hashAlg !== 'sha2-256') {
    throw new PublishError(
      'UNSUPPORTED_HASH_ALG',
      `publishMerkle only supports 'sha2-256' leaves; got '${input.hashAlg as string}'`,
    );
  }
  if (input.leaves.length < 1) {
    throw new PublishError('INVALID_LEAVES', 'publishMerkle requires at least one leaf hash');
  }
  const maxUsdMicros = normalizeMaxUsdMicros(input.maxUsdMicros);

  const leaves: Uint8Array[] = input.leaves.map((leaf, idx) => {
    const bytes = typeof leaf === 'string' ? hexToBytes(leaf, 'INVALID_LEAVES') : leaf;
    if (!(bytes instanceof Uint8Array) || bytes.length !== LEAF_DIGEST_LENGTH) {
      throw new PublishError(
        'INVALID_LEAVES',
        `leaves[${idx}] must be a ${LEAF_DIGEST_LENGTH}-byte sha2-256 digest`,
      );
    }
    return bytes;
  });

  const root = cloneToOwnedBuffer(merkleSha2256Root(leaves));
  const leavesListCbor = encodeLeavesList({
    leaves,
    root,
    ...(input.leafAlg !== undefined ? { leafAlg: input.leafAlg } : {}),
  });

  // The record side of the quote is the exact-width upper-bound estimate
  // with the fixed-width URI placeholder; the storage side is the exact
  // leaves-list byte count.
  const shape: RecordShape = {
    signed: input.signer !== undefined,
    supersedes: false,
    merkle: { alg: MERKLE_ALG_ID, uris: [arweaveUriPlaceholder()] },
  };
  const quoteInput: QuoteInput = {
    recordBytes: estimateRecordBytes(shape),
    recipientCount: 0,
    fileBytesTotal: leavesListCbor.length,
  };
  let quote = await postQuote(config, quoteInput);
  enforceMaxUsdMicros(maxUsdMicros, quote);

  // Upload the leaves-list to Arweave (resumable for large leaves-lists)
  // under its deterministic content-derived idempotency key.
  const uploadKey = merkleUploadIdempotencyKey(leavesListCbor);
  const uri = await uploadBlob(config, leavesListCbor, uploadKey, input.chunkBytes);

  // A large upload can outlive the price lock; publish only against a live
  // one, re-enforcing the cap against the refreshed price.
  quote = await refreshQuoteIfStale(config, quote, quoteInput, maxUsdMicros);

  // Build the on-chain record with the resulting `ar://` URI.
  const merkleEntry: MerkleCommit = {
    alg: MERKLE_ALG_ID,
    root,
    leaf_count: leaves.length,
    uris: [uri],
  };
  const record: PoeRecord = { v: 1, merkle: [merkleEntry] };
  const recordBytes = await encodeRecord(record, input.signer);
  const published = await postPublish(
    config,
    bytesToHex(recordBytes),
    quote.quote_id,
    input.idempotencyKey,
  );

  return {
    id: published.id,
    tx_hash: published.tx_hash,
    status: published.status,
    root: bytesToHex(root),
    leaf_count: leaves.length,
    ar_uri: uri,
    recordBytes,
    balance_after_usd_micros: published.balance_after_usd_micros,
  };
}
