// Two-phase sealed-PoE publishing.
//
// Sealing is randomized by design (a fresh content key, nonce, and per-slot
// KEM material on every wrap), so any helper that couples encryption to the
// network round-trips makes a failed publish expensive to retry: the retry
// re-encrypts, pays for a second ciphertext upload, and produces different
// record bytes that can never deduplicate gateway-side. This module splits
// the flow at that seam:
//
//   - `sealPrepare` — phase 1, pure and offline: hash and encrypt every item
//     to a shared recipient set under one KEM, returning a `PreparedSeal`.
//     The artifact serializes to the versioned portable
//     `prepared_seal_json_v1` format (`preparedSealToJson` /
//     `preparedSealFromJson`), so a caller can persist it and retry a publish
//     without ever re-encrypting.
//   - `quotePreparedSeal` — a price preview for a prepared seal. Nothing is
//     uploaded; UIs surface the price before committing to storage.
//   - `sealedRecord` / `encodeSealedRecord` — pure assembly seams: prepared
//     material + one uploaded URI per item → the Label 309 record (object
//     form or canonical bytes). Air-gapped flows sign and archive these bytes
//     without a network connection.
//   - `submitSealed` — phase 2, the online orchestrator: exact-size quote
//     (Arweave transaction ids are fixed-width, so the record size is known
//     before any upload) → price-cap check → per-item ciphertext upload under
//     a deterministic idempotency key → quote refresh when a slow upload
//     outlived the price lock → encode (optionally sign) → publish. Every
//     error raised after a completed upload carries the finished
//     `UploadReceipt`s (`SubmitSealedError.uploads`), so a retry resumes from
//     persisted receipts instead of re-paying storage.
//   - `publishSealed` — the one-shot convenience wrapper: `sealPrepare`
//     followed by `submitSealed` in a single call.
//
// # The portable artifact: `prepared_seal_json_v1`
//
// The serialized form is deliberately rigid so every SDK produces identical
// bytes for identical prepared material:
//
//   - snake_case keys; byte fields are base64url WITHOUT padding; integers
//     are JSON numbers; no floats, no timestamps.
//   - The canonical form is compact UTF-8 JSON (no insignificant whitespace)
//     with object keys sorted lexicographically by byte order at every
//     nesting level.
//   - `prepared_sha256` is the lowercase-hex SHA-256 of the canonical form
//     with the `prepared_sha256` member itself omitted. `preparedSealFromJson`
//     recomputes and verifies it, rejecting a corrupted artifact.
//   - Each `item_id` is the lowercase-hex SHA-256 of that item's ciphertext.
//   - The deterministic per-item upload idempotency key is
//     `"seal1-" + prepared_sha256[..32] + "-" + <item index>`, so a
//     crash-and-retry can never double-pay for the same ciphertext upload.

import { sha256 } from '@cardanowall/crypto-core/hash';
import {
  eciesSealedPoeWrap,
  passphraseSealedPoeSeal,
  SEALED_POE_AEAD,
  type PassphraseParams,
  type PassphraseSealedPoeOutput,
  type SealedEnvelope,
  type SealedKem,
} from '@cardanowall/crypto-core/sealed-poe';
import {
  encodePoeRecord,
  isArweaveTxUri,
  isFetchSetUri,
  type EncryptionEnvelope,
  type PoeRecord,
} from '@cardanowall/poe-standard';

import { COSE_SIGN1_PATH1_BYTES, estimateRecordBytes, type RecordShape } from '../estimate/index';
import { bytesToHex } from '../hex';
import { InvalidUploadReceiptError } from './invalid-upload-receipt-error';
import {
  arweaveUriPlaceholder,
  assertSigner,
  encodeRecord,
  enforceMaxUsdMicros,
  hashContent,
  normalizeMaxUsdMicros,
  postPublish,
  postQuote,
  quoteIsFresh,
  refreshQuoteIfStale,
  resolveHashAlgs,
  toBytes,
  uploadBlob,
  type ResolvedPublishConfig,
} from './publish';
import type { PublishResponse, QuoteInput, QuoteResponse, Signer, SupportedHashAlg } from './types';

/** The Label 309 passphrase-KDF identifier carried in the on-chain `enc` block. */
const PASSPHRASE_KDF_ARGON2ID = 'argon2id';

/** The version literal of the portable prepared-seal serialization. */
export const PREPARED_SEAL_JSON_VERSION = 'prepared_seal_json_v1';

// The prefix of the deterministic per-item upload idempotency key, and how
// many leading hex characters of `prepared_sha256` the key carries.
const SEAL_UPLOAD_KEY_PREFIX = 'seal1-';
const UPLOAD_KEY_FINGERPRINT_CHARS = 32;

const X25519_PUBLIC_KEY_LENGTH = 32;
const MLKEM768X25519_PUBLIC_KEY_LENGTH = 1216;
const ENVELOPE_NONCE_LENGTH = 24;
const SLOTS_MAC_LENGTH = 32;
const SLOT_WRAP_LENGTH = 48;
const SLOT_EPK_LENGTH = 32;
const SLOT_KEM_CT_LENGTH = 1120;
const DIGEST_LENGTH = 32;
const SUPERSEDES_HEX_LENGTH = 64;
const CEK_LENGTH = 32;
const X25519_EPHEMERAL_SECRET_LENGTH = 32;
const MLKEM768X25519_ESEED_LENGTH = 64;
const CIPHERTEXT_SHA256_LENGTH = 32;

// =============================================================================
// Errors
// =============================================================================

/**
 * A failure of the pure sealed phases: `sealPrepare` or the `sealedRecord`
 * assembly seam.
 */
export class SealPrepareError extends Error {
  readonly code:
    | 'NO_ITEMS'
    | 'INVALID_RECIPIENT'
    | 'URI_COUNT_MISMATCH'
    | 'INVALID_SUPERSEDES'
    | 'INVALID_URI'
    | 'CRYPTO_FAILURE';

  constructor(code: SealPrepareError['code'], message: string) {
    super(message);
    this.name = 'SealPrepareError';
    this.code = code;
  }
}

/** A failure to parse or verify a `prepared_seal_json_v1` document. */
export class PreparedSealJsonError extends Error {
  /**
   * What failed:
   *
   *   - `PARSE` — not valid JSON for the schema (including unknown members
   *     and wrong member types).
   *   - `UNSUPPORTED_VERSION` — the document declares a version this SDK
   *     does not implement.
   *   - `INVALID` — a field violates the format's structural rules (bad
   *     base64url, a wrong-length component, an `item_id` that does not hash
   *     its ciphertext, an inconsistent KEM, …).
   *   - `FINGERPRINT_MISMATCH` — the stored `prepared_sha256` does not match
   *     the recomputed fingerprint of the canonical form: the artifact was
   *     corrupted in transit (`stored` / `computed` carry both values).
   */
  readonly code: 'PARSE' | 'UNSUPPORTED_VERSION' | 'INVALID' | 'FINGERPRINT_MISMATCH';
  /** The fingerprint the document carries (`FINGERPRINT_MISMATCH` only). */
  readonly stored?: string;
  /** The fingerprint recomputed from the document (`FINGERPRINT_MISMATCH` only). */
  readonly computed?: string;

  constructor(
    code: PreparedSealJsonError['code'],
    message: string,
    fingerprints?: { stored: string; computed: string },
  ) {
    super(message);
    this.name = 'PreparedSealJsonError';
    this.code = code;
    if (fingerprints !== undefined) {
      this.stored = fingerprints.stored;
      this.computed = fingerprints.computed;
    }
  }
}

/**
 * The terminal error of `submitSealed` / `publishSealed`.
 *
 * Storage uploads are paid work, so an error raised after any upload
 * completed carries the finished `UploadReceipt`s: persist them and pass them
 * back via `SubmitSealedInput.uploaded` on the retry, and the
 * already-uploaded ciphertexts are never paid for again. The underlying
 * failure rides on the standard `cause` property.
 */
export class SubmitSealedError extends Error {
  /**
   * Receipts for every ciphertext durably uploaded before the failure — the
   * caller-passed receipts that validated plus those completed during this
   * call, in item order.
   */
  readonly uploads: ReadonlyArray<UploadReceipt>;

  constructor(uploads: ReadonlyArray<UploadReceipt>, cause: unknown) {
    const detail = cause instanceof Error ? `: ${cause.message}` : '';
    super(`sealed submit failed with ${uploads.length} completed upload receipt(s)${detail}`, {
      cause,
    });
    this.name = 'SubmitSealedError';
    this.uploads = uploads;
  }
}

// =============================================================================
// Inputs
// =============================================================================

/** One plaintext item of a `SealPrepareInput`. */
export interface SealPrepareItem {
  /**
   * The plaintext to seal. Hashed for the on-chain claim and encrypted for
   * storage; never uploaded in the clear. Strings are UTF-8 encoded first.
   */
  readonly content: Uint8Array | string;
}

/** Input to `sealPrepare` / `sealPrepareWithRng`. */
export interface SealPrepareInput {
  /**
   * The plaintext items to seal (1..=N). Every item is sealed to the same
   * recipient set under the same KEM.
   */
  readonly items: ReadonlyArray<SealPrepareItem>;
  /**
   * The shared recipient public keys (32 bytes for `x25519`, 1216 bytes for
   * the X-Wing hybrid).
   */
  readonly recipients: ReadonlyArray<Uint8Array>;
  /**
   * The KEM every item's envelope is built under (one KEM for the whole
   * prepared set — mixing is forbidden). Defaults to the X-Wing hybrid
   * `mlkem768x25519`.
   */
  readonly kem?: 'x25519' | 'mlkem768x25519';
  /**
   * The plaintext-bind hash algorithms. Empty (or omitted) defaults to a
   * single `sha2-256` entry; several algorithms co-hash each item into a
   * multi-entry `hashes` map, every digest bound into the envelope's slots MAC.
   */
  readonly hashAlgs?: readonly SupportedHashAlg[];
}

/** Input to `quotePreparedSeal`. */
export interface QuotePreparedSealInput {
  /** The prepared seal to price. */
  readonly prepared: PreparedSeal;
  /**
   * The record-level signer the eventual submit will use, when any. Only its
   * presence affects the price (a signed record is larger); the signer is
   * not invoked.
   */
  readonly signer?: Signer;
  /**
   * The 64-hex transaction hash the eventual record will supersede, when
   * any. Only its presence affects the price.
   */
  readonly supersedes?: string;
}

/** Input to `submitSealed`. */
export interface SubmitSealedInput {
  /** The prepared seal to submit. */
  readonly prepared: PreparedSeal;
  /** The optional record-level signer. */
  readonly signer?: Signer;
  /**
   * Refuse to publish when the quoted price exceeds this many USD
   * micro-cents (1 USD = 1,000,000), given as a `bigint` or a decimal
   * string. Enforced against the initial quote and again against any
   * refreshed quote — FX may move while an upload runs, and the cap is a
   * promise about what gets spent.
   */
  readonly maxUsdMicros?: bigint | string;
  /**
   * An optional prior price preview (from `quotePreparedSeal`). A still-fresh
   * preview is consumed as the price lock; a stale one is silently replaced
   * by a fresh internal quote.
   */
  readonly quote?: QuoteResponse;
  /** The 64-hex transaction hash of the record this one supersedes. */
  readonly supersedes?: string;
  /** Optional idempotency key for the publish call. */
  readonly idempotencyKey?: string;
  /**
   * The intended chunk size in bytes for the ciphertext uploads. Omitted
   * uses the resumable helper's default; the server's `max_chunk_bytes`
   * always clamps it down when tighter.
   */
  readonly chunkBytes?: number;
  /**
   * Receipts from a previous attempt's completed uploads. Each is validated
   * against the prepared material (its `itemId` must belong to the prepared
   * set, its `ciphertextSha256` and `bytes` must match the prepared
   * ciphertext); a validated receipt's item skips the upload.
   */
  readonly uploaded?: ReadonlyArray<UploadReceipt>;
}

/**
 * Input to `publishSealed` — the one-shot sealed publish (`sealPrepare` +
 * `submitSealed` in one call).
 *
 * The helper quotes internally from the exact-width record-size estimate;
 * there is no caller-supplied quote id. Flows that must survive a crash
 * (persist the prepared artifact, resume uploads from receipts) use the
 * two-phase surface instead.
 */
export interface PublishSealedInput {
  /**
   * The plaintext items to seal (1..=N). Every item is sealed to the same
   * recipient set under the same KEM; the published record carries one
   * content item per input item.
   */
  readonly items: ReadonlyArray<SealPrepareItem>;
  /**
   * The recipient public keys (32 bytes for `x25519`, 1216 bytes for the
   * hybrid KEM). At least one recipient is required; the sender SHOULD
   * include themselves as a recipient to retain decrypt access.
   */
  readonly recipients: ReadonlyArray<Uint8Array>;
  /**
   * The plaintext-bind hash algorithms. Empty (or omitted) defaults to a
   * single `sha2-256` entry; several algorithms co-hash each item.
   */
  readonly hashAlgs?: readonly SupportedHashAlg[];
  /**
   * The KEM the envelopes are built under. Defaults to `mlkem768x25519`
   * (X-Wing hybrid, ML-KEM-768 + X25519) — the post-quantum-safe choice.
   * Pass `x25519` only for the classical, higher-capacity path.
   */
  readonly kem?: 'x25519' | 'mlkem768x25519';
  /** The optional record-level signer. */
  readonly signer?: Signer;
  /**
   * Refuse to publish when the quoted price exceeds this many USD
   * micro-cents (1 USD = 1,000,000), given as a `bigint` or a decimal string.
   */
  readonly maxUsdMicros?: bigint | string;
  /** The 64-hex transaction hash of the record this one supersedes. */
  readonly supersedes?: string;
  /**
   * Optional idempotency key for the publish call. Ciphertext uploads use
   * their own deterministic per-item keys.
   */
  readonly idempotencyKey?: string;
  /**
   * The intended chunk size in bytes for the ciphertext uploads. A
   * ciphertext over the resumable threshold uploads in resumable chunks; one
   * at or under it rides the single-shot path unchanged. The server's
   * `max_chunk_bytes` always clamps this down when it is tighter.
   */
  readonly chunkBytes?: number;
}

// =============================================================================
// Receipts and results
// =============================================================================

/**
 * A validated resume token for one completed ciphertext upload — never a
 * bare URI.
 *
 * Plainly constructible: a caller persists the fields (e.g. as JSON of its
 * own shape) and rebuilds the receipt on retry. `submitSealed` validates
 * every field against the prepared material before honouring it.
 */
export interface UploadReceipt {
  /** The prepared item this receipt covers (`PreparedSealItem.itemId`). */
  readonly itemId: string;
  /** The storage URI the upload committed (e.g. `ar://<tx>`). */
  readonly uri: string;
  /** The 32-byte SHA-256 of the uploaded ciphertext. */
  readonly ciphertextSha256: Uint8Array;
  /** The uploaded byte count. */
  readonly bytes: number;
}

/** The result of a successful `submitSealed` / `publishSealed`. */
export interface SealedSubmission {
  /** The gateway's publish response. */
  readonly response: PublishResponse;
  /**
   * The exact canonical-CBOR record bytes that were published — archive them
   * (e.g. as `record_hex` in a receipt).
   */
  readonly recordBytes: Uint8Array;
  /** The storage URI of each item's ciphertext, in item order. */
  readonly uris: ReadonlyArray<string>;
  /**
   * The upload receipts, in item order. Persist them: a retry after a later
   * failure resumes from them via `SubmitSealedInput.uploaded`.
   */
  readonly uploads: ReadonlyArray<UploadReceipt>;
  /** The price lock the publish consumed. */
  readonly quote: QuoteResponse;
}

// =============================================================================
// The prepared artifact
// =============================================================================

// Facade internals live in module-private WeakMaps, keyed by the facade
// instance: the artifact's fields are unreachable from outside this module,
// so an in-memory `PreparedSeal` can never drift from its fingerprint. The
// accessors below hand out defensive copies only.
interface PreparedItemData {
  readonly itemId: string;
  readonly ciphertext: Uint8Array;
  /** Algorithm identifier → digest bytes, keys in byte order. */
  readonly hashes: ReadonlyMap<string, Uint8Array>;
  readonly envelope: SealedEnvelope;
}

interface PreparedSealData {
  readonly kem: SealedKem;
  readonly itemsData: ReadonlyArray<PreparedItemData>;
  readonly items: ReadonlyArray<PreparedSealItem>;
  readonly preparedSha256: string;
}

const CONSTRUCT_GUARD: unique symbol = Symbol('cardanowall.prepared-seal.construct');
const ITEM_DATA = new WeakMap<PreparedSealItem, PreparedItemData>();
const SEAL_DATA = new WeakMap<PreparedSeal, PreparedSealData>();

function cloneBytes(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(src.length));
  out.set(src);
  return out;
}

/**
 * One prepared item: the sealed form of one plaintext. Read-only; every
 * byte-valued accessor returns a defensive copy.
 */
export class PreparedSealItem {
  constructor(guard: symbol) {
    if (guard !== CONSTRUCT_GUARD) {
      throw new TypeError(
        'PreparedSealItem cannot be constructed directly; it is produced by sealPrepare() / preparedSealFromJson()',
      );
    }
  }

  private get data(): PreparedItemData {
    const data = ITEM_DATA.get(this);
    if (data === undefined) throw new TypeError('detached PreparedSealItem');
    return data;
  }

  /**
   * The item's stable identity across persistence and resume: lowercase-hex
   * SHA-256 of its ciphertext.
   */
  get itemId(): string {
    return this.data.itemId;
  }

  /** The segmented-STREAM ciphertext destined for off-chain storage (a copy). */
  ciphertext(): Uint8Array {
    return cloneBytes(this.data.ciphertext);
  }

  /**
   * The item's content-hash map (algorithm identifier → digest bytes, keys
   * in byte order), bound into the envelope's slots MAC. Digests are copies.
   */
  hashes(): Record<string, Uint8Array> {
    const out: Record<string, Uint8Array> = {};
    for (const [alg, digest] of this.data.hashes) out[alg] = cloneBytes(digest);
    return out;
  }

  /** The sealed envelope (the on-chain header material), as a deep copy. */
  envelope(): SealedEnvelope {
    return cloneEnvelope(this.data.envelope);
  }
}

/**
 * The phase-1 artifact: every item sealed, nothing uploaded.
 *
 * Serializable via the versioned portable `prepared_seal_json_v1` format
 * (`preparedSealToJson` / `preparedSealFromJson`); see the module docs for
 * the format's rules. The internals are module-private and every accessor
 * hands out copies, so an in-memory artifact can never drift from its
 * fingerprint.
 */
export class PreparedSeal {
  constructor(guard: symbol) {
    if (guard !== CONSTRUCT_GUARD) {
      throw new TypeError(
        'PreparedSeal cannot be constructed directly; use sealPrepare() or preparedSealFromJson()',
      );
    }
  }

  /** The KEM every item is sealed under. */
  get kem(): 'x25519' | 'mlkem768x25519' {
    return sealDataOf(this).kem;
  }

  /** The prepared items, in input order. */
  get items(): ReadonlyArray<PreparedSealItem> {
    return sealDataOf(this).items;
  }

  /**
   * The lowercase-hex SHA-256 fingerprint of the canonical serialized form
   * (with the fingerprint member itself omitted).
   */
  get preparedSha256(): string {
    return sealDataOf(this).preparedSha256;
  }

  /**
   * The deterministic idempotency key for the item's ciphertext upload:
   * `"seal1-" + prepared_sha256[..32] + "-" + itemIndex`.
   *
   * Deriving the key from the artifact (not from randomness at upload time)
   * closes the crash-before-persist window: a retry of the same prepared
   * item always presents the same key, so the gateway's idempotency layer
   * replays the original upload instead of charging for a second one.
   *
   * Throws a `RangeError` when `itemIndex` is out of range for `items`.
   */
  uploadIdempotencyKey(itemIndex: number): string {
    const data = sealDataOf(this);
    if (!Number.isInteger(itemIndex) || itemIndex < 0 || itemIndex >= data.itemsData.length) {
      throw new RangeError(
        `itemIndex ${itemIndex} out of range for ${data.itemsData.length} prepared item(s)`,
      );
    }
    const fingerprint = data.preparedSha256.slice(0, UPLOAD_KEY_FINGERPRINT_CHARS);
    return `${SEAL_UPLOAD_KEY_PREFIX}${fingerprint}-${itemIndex}`;
  }
}

function sealDataOf(prepared: PreparedSeal): PreparedSealData {
  const data = SEAL_DATA.get(prepared);
  if (data === undefined) {
    throw new TypeError(
      'PreparedSeal must come from sealPrepare(), sealPrepareWithRng(), or preparedSealFromJson()',
    );
  }
  return data;
}

/** Build the facade pair over validated item data. */
function newPreparedSeal(
  kem: SealedKem,
  itemsData: ReadonlyArray<PreparedItemData>,
  preparedSha256: string,
): PreparedSeal {
  const items = Object.freeze(
    itemsData.map((data) => {
      const item = new PreparedSealItem(CONSTRUCT_GUARD);
      ITEM_DATA.set(item, data);
      return item;
    }),
  );
  const prepared = new PreparedSeal(CONSTRUCT_GUARD);
  SEAL_DATA.set(prepared, { kem, itemsData, items, preparedSha256 });
  return prepared;
}

function cloneEnvelope(env: SealedEnvelope): SealedEnvelope {
  if (env.kem === 'x25519') {
    return {
      scheme: 1,
      aead: env.aead,
      kem: 'x25519',
      nonce: cloneBytes(env.nonce),
      slots: env.slots.map((slot) => ({
        epk: cloneBytes(slot.epk),
        wrap: cloneBytes(slot.wrap),
      })),
      slots_mac: cloneBytes(env.slots_mac),
    };
  }
  return {
    scheme: 1,
    aead: env.aead,
    kem: 'mlkem768x25519',
    nonce: cloneBytes(env.nonce),
    slots: env.slots.map((slot) => ({
      kem_ct: cloneBytes(slot.kem_ct),
      wrap: cloneBytes(slot.wrap),
    })),
    slots_mac: cloneBytes(env.slots_mac),
  };
}

// =============================================================================
// prepared_seal_json_v1 serialization
// =============================================================================

interface PreparedSlotDocument {
  epk?: string;
  kem_ct?: string;
  wrap: string;
}

interface PreparedEnvelopeDocument {
  scheme: number;
  aead: string;
  kem: string;
  nonce: string;
  slots: PreparedSlotDocument[];
  slots_mac: string;
}

interface PreparedItemDocument {
  item_id: string;
  ciphertext: string;
  hashes: Record<string, string>;
  envelope: PreparedEnvelopeDocument;
}

interface PreparedSealDocument {
  version: string;
  kem: string;
  items: PreparedItemDocument[];
  prepared_sha256?: string;
}

const utf8Encoder = new TextEncoder();

/** Bytewise UTF-8 order — the sort the canonical form pins for object keys. */
function compareUtf8(a: string, b: string): number {
  const aBytes = utf8Encoder.encode(a);
  const bBytes = utf8Encoder.encode(b);
  const length = Math.min(aBytes.length, bBytes.length);
  for (let i = 0; i < length; i++) {
    const delta = aBytes[i]! - bBytes[i]!;
    if (delta !== 0) return delta;
  }
  return aBytes.length - bBytes.length;
}

/**
 * The canonical serialization: compact JSON with object keys sorted by byte
 * order at every nesting level. `JSON.stringify` alone preserves insertion
 * order, so the sort is explicit.
 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => compareUtf8(a, b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/**
 * Lowercase-hex SHA-256 of the canonical form without the fingerprint
 * member. The caller must pass a document whose `prepared_sha256` is absent.
 */
function fingerprintOf(document: PreparedSealDocument): string {
  return bytesToHex(sha256(utf8Encoder.encode(canonicalJson(document))));
}

/** Whether two strings encode to identical UTF-8 bytes. */
function utf8BytesEqual(a: string, b: string): boolean {
  const aBytes = utf8Encoder.encode(a);
  const bBytes = utf8Encoder.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  for (let i = 0; i < aBytes.length; i++) {
    if (aBytes[i] !== bBytes[i]) return false;
  }
  return true;
}

/** Lower validated item data to the serialization document (no fingerprint). */
function toDocument(
  kem: SealedKem,
  itemsData: ReadonlyArray<PreparedItemData>,
): PreparedSealDocument {
  return {
    version: PREPARED_SEAL_JSON_VERSION,
    kem,
    items: itemsData.map((item) => {
      const hashes: Record<string, string> = {};
      for (const [alg, digest] of item.hashes) hashes[alg] = base64urlEncode(digest);
      const env = item.envelope;
      const slots: PreparedSlotDocument[] =
        env.kem === 'x25519'
          ? env.slots.map((slot) => ({
              epk: base64urlEncode(slot.epk),
              wrap: base64urlEncode(slot.wrap),
            }))
          : env.slots.map((slot) => ({
              kem_ct: base64urlEncode(slot.kem_ct),
              wrap: base64urlEncode(slot.wrap),
            }));
      return {
        item_id: item.itemId,
        ciphertext: base64urlEncode(item.ciphertext),
        hashes,
        envelope: {
          scheme: 1,
          aead: env.aead,
          kem: env.kem,
          nonce: base64urlEncode(env.nonce),
          slots,
          slots_mac: base64urlEncode(env.slots_mac),
        },
      };
    }),
  };
}

/**
 * Serialize a prepared seal to the portable `prepared_seal_json_v1` form
 * (canonical: compact, byte-order-sorted keys, `prepared_sha256` included).
 */
export function preparedSealToJson(prepared: PreparedSeal): string {
  const data = sealDataOf(prepared);
  const document = toDocument(data.kem, data.itemsData);
  document.prepared_sha256 = data.preparedSha256;
  return canonicalJson(document);
}

// --- strict document walk ----------------------------------------------------

function parseError(message: string): PreparedSealJsonError {
  return new PreparedSealJsonError('PARSE', message);
}

function invalidError(message: string): PreparedSealJsonError {
  return new PreparedSealJsonError('INVALID', message);
}

function asStrictObject(
  value: unknown,
  context: string,
  allowedKeys: ReadonlyArray<string>,
): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw parseError(`${context} must be a JSON object`);
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) {
      throw parseError(`${context} carries an unknown member ${JSON.stringify(key)}`);
    }
  }
  return record;
}

function requireString(record: Record<string, unknown>, key: string, context: string): string {
  const value = record[key];
  if (typeof value !== 'string') {
    throw parseError(`${context}.${key} must be a string`);
  }
  return value;
}

function requireArray(record: Record<string, unknown>, key: string, context: string): unknown[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw parseError(`${context}.${key} must be an array`);
  }
  return value;
}

/** Walk the raw parse into the typed document, rejecting unknown members. */
function walkDocument(raw: unknown): PreparedSealDocument {
  const top = asStrictObject(raw, 'document', ['version', 'kem', 'items', 'prepared_sha256']);
  const version = requireString(top, 'version', 'document');
  const kem = requireString(top, 'kem', 'document');
  const rawItems = requireArray(top, 'items', 'document');
  let preparedSha256: string | undefined;
  if (top['prepared_sha256'] !== undefined) {
    preparedSha256 = requireString(top, 'prepared_sha256', 'document');
  }

  const items = rawItems.map((rawItem, index) => {
    const context = `items[${index}]`;
    const item = asStrictObject(rawItem, context, ['item_id', 'ciphertext', 'hashes', 'envelope']);
    const itemId = requireString(item, 'item_id', context);
    const ciphertext = requireString(item, 'ciphertext', context);

    const rawHashes = item['hashes'];
    if (rawHashes === null || typeof rawHashes !== 'object' || Array.isArray(rawHashes)) {
      throw parseError(`${context}.hashes must be a JSON object`);
    }
    const hashes: Record<string, string> = {};
    for (const [alg, digest] of Object.entries(rawHashes as Record<string, unknown>)) {
      if (typeof digest !== 'string') {
        throw parseError(`${context}.hashes[${JSON.stringify(alg)}] must be a string`);
      }
      hashes[alg] = digest;
    }

    const rawEnvelope = asStrictObject(item['envelope'], `${context}.envelope`, [
      'scheme',
      'aead',
      'kem',
      'nonce',
      'slots',
      'slots_mac',
    ]);
    const scheme = rawEnvelope['scheme'];
    if (typeof scheme !== 'number' || !Number.isInteger(scheme) || scheme < 0) {
      throw parseError(`${context}.envelope.scheme must be a non-negative integer`);
    }
    const slots = requireArray(rawEnvelope, 'slots', `${context}.envelope`).map(
      (rawSlot, slotIndex) => {
        const slotContext = `${context}.envelope.slots[${slotIndex}]`;
        const slot = asStrictObject(rawSlot, slotContext, ['epk', 'kem_ct', 'wrap']);
        const out: PreparedSlotDocument = {
          wrap: requireString(slot, 'wrap', slotContext),
        };
        if (slot['epk'] !== undefined) out.epk = requireString(slot, 'epk', slotContext);
        if (slot['kem_ct'] !== undefined) out.kem_ct = requireString(slot, 'kem_ct', slotContext);
        return out;
      },
    );

    const envelope: PreparedEnvelopeDocument = {
      scheme,
      aead: requireString(rawEnvelope, 'aead', `${context}.envelope`),
      kem: requireString(rawEnvelope, 'kem', `${context}.envelope`),
      nonce: requireString(rawEnvelope, 'nonce', `${context}.envelope`),
      slots,
      slots_mac: requireString(rawEnvelope, 'slots_mac', `${context}.envelope`),
    };
    return { item_id: itemId, ciphertext, hashes, envelope } satisfies PreparedItemDocument;
  });

  const document: PreparedSealDocument = { version, kem, items };
  if (preparedSha256 !== undefined) document.prepared_sha256 = preparedSha256;
  return document;
}

/** Decode and structurally validate one serialized item. */
function decodeItem(index: number, item: PreparedItemDocument, kem: SealedKem): PreparedItemData {
  const invalid = (detail: string): PreparedSealJsonError =>
    invalidError(`items[${index}]: ${detail}`);

  const ciphertext = base64urlDecode(item.ciphertext);
  if (ciphertext === undefined) {
    throw invalid('ciphertext is not unpadded base64url');
  }
  if (!isLowercaseHex(item.item_id, 64)) {
    throw invalid('item_id must be 64 lowercase-hex characters');
  }
  if (item.item_id !== bytesToHex(sha256(ciphertext))) {
    throw invalid('item_id is not the SHA-256 of the ciphertext');
  }

  const hashEntries = Object.entries(item.hashes);
  if (hashEntries.length === 0) {
    throw invalid('hashes must be non-empty');
  }
  const hashes = new Map<string, Uint8Array>();
  for (const [alg, digest] of hashEntries.sort(([a], [b]) => compareUtf8(a, b))) {
    const bytes = base64urlDecode(digest);
    if (bytes === undefined) {
      throw invalid(`hashes[${JSON.stringify(alg)}] is not unpadded base64url`);
    }
    if (bytes.length !== DIGEST_LENGTH) {
      throw invalid(`hashes[${JSON.stringify(alg)}] must be ${DIGEST_LENGTH} bytes`);
    }
    hashes.set(alg, bytes);
  }

  const envelope = item.envelope;
  if (envelope.scheme !== 1) {
    throw invalid(`envelope.scheme must be 1, got ${envelope.scheme}`);
  }
  if (envelope.aead !== SEALED_POE_AEAD) {
    throw invalid(`envelope.aead must be ${JSON.stringify(SEALED_POE_AEAD)}`);
  }
  if (envelope.kem !== kem) {
    throw invalid("envelope.kem must match the document's kem");
  }
  const nonce = base64urlDecode(envelope.nonce);
  if (nonce === undefined || nonce.length !== ENVELOPE_NONCE_LENGTH) {
    throw invalid(`envelope.nonce must be ${ENVELOPE_NONCE_LENGTH} bytes of unpadded base64url`);
  }
  const slotsMac = base64urlDecode(envelope.slots_mac);
  if (slotsMac === undefined || slotsMac.length !== SLOTS_MAC_LENGTH) {
    throw invalid(`envelope.slots_mac must be ${SLOTS_MAC_LENGTH} bytes of unpadded base64url`);
  }
  if (envelope.slots.length === 0) {
    throw invalid('envelope.slots must be non-empty');
  }

  const wrapOf = (slot: PreparedSlotDocument, slotIndex: number): Uint8Array => {
    const wrap = base64urlDecode(slot.wrap);
    if (wrap === undefined || wrap.length !== SLOT_WRAP_LENGTH) {
      throw invalid(
        `envelope.slots[${slotIndex}].wrap must be ${SLOT_WRAP_LENGTH} bytes of unpadded base64url`,
      );
    }
    return wrap;
  };

  let sealed: SealedEnvelope;
  if (kem === 'x25519') {
    const slots = envelope.slots.map((slot, slotIndex) => {
      if (slot.kem_ct !== undefined) {
        throw invalid(`envelope.slots[${slotIndex}] carries kem_ct on an x25519 envelope`);
      }
      const epk = slot.epk === undefined ? undefined : base64urlDecode(slot.epk);
      if (epk === undefined || epk.length !== SLOT_EPK_LENGTH) {
        throw invalid(
          `envelope.slots[${slotIndex}].epk must be ${SLOT_EPK_LENGTH} bytes of unpadded base64url`,
        );
      }
      return { epk, wrap: wrapOf(slot, slotIndex) };
    });
    sealed = {
      scheme: 1,
      aead: SEALED_POE_AEAD,
      kem: 'x25519',
      nonce,
      slots,
      slots_mac: slotsMac,
    };
  } else {
    const slots = envelope.slots.map((slot, slotIndex) => {
      if (slot.epk !== undefined) {
        throw invalid(`envelope.slots[${slotIndex}] carries epk on an mlkem768x25519 envelope`);
      }
      const kemCt = slot.kem_ct === undefined ? undefined : base64urlDecode(slot.kem_ct);
      if (kemCt === undefined || kemCt.length !== SLOT_KEM_CT_LENGTH) {
        throw invalid(
          `envelope.slots[${slotIndex}].kem_ct must be ${SLOT_KEM_CT_LENGTH} bytes of unpadded base64url`,
        );
      }
      return { kem_ct: kemCt, wrap: wrapOf(slot, slotIndex) };
    });
    sealed = {
      scheme: 1,
      aead: SEALED_POE_AEAD,
      kem: 'mlkem768x25519',
      nonce,
      slots,
      slots_mac: slotsMac,
    };
  }

  return { itemId: item.item_id, ciphertext, hashes, envelope: sealed };
}

/**
 * Parse and verify a portable `prepared_seal_json_v1` document.
 *
 * The stored `prepared_sha256` is recomputed over the canonical form and
 * must match; every structural rule of the format (component lengths,
 * `item_id` = SHA-256 of the ciphertext, one consistent KEM) is
 * re-validated, so a document that parses is safe to submit.
 *
 * Throws `PreparedSealJsonError` on malformed JSON, an unsupported version,
 * a structural violation, or a fingerprint mismatch.
 */
export function preparedSealFromJson(json: string): PreparedSeal {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch (error) {
    throw parseError(error instanceof Error ? error.message : 'invalid JSON');
  }
  const document = walkDocument(raw);

  if (document.version !== PREPARED_SEAL_JSON_VERSION) {
    throw new PreparedSealJsonError(
      'UNSUPPORTED_VERSION',
      `${JSON.stringify(document.version)} (expected ${JSON.stringify(PREPARED_SEAL_JSON_VERSION)})`,
    );
  }
  const stored = document.prepared_sha256;
  if (stored === undefined) {
    throw invalidError('prepared_sha256 is required');
  }
  if (!isLowercaseHex(stored, 64)) {
    throw invalidError('prepared_sha256 must be 64 lowercase-hex characters');
  }
  delete document.prepared_sha256;
  const computed = fingerprintOf(document);
  if (computed !== stored) {
    throw new PreparedSealJsonError(
      'FINGERPRINT_MISMATCH',
      `stored ${stored} != computed ${computed}`,
      { stored, computed },
    );
  }

  if (document.kem !== 'x25519' && document.kem !== 'mlkem768x25519') {
    throw invalidError(`unknown kem ${JSON.stringify(document.kem)}`);
  }
  const kem: SealedKem = document.kem;
  if (document.items.length === 0) {
    throw invalidError('items must be non-empty');
  }
  const itemsData = document.items.map((item, index) => decodeItem(index, item, kem));
  const prepared = newPreparedSeal(kem, itemsData, stored);

  // Final gate: the only accepted form is the canonical serialization. The
  // structural walk above tolerates lexical variants that parse to the same
  // value — a float-typed `scheme` (`1.0`, `1e0`), an explicit `null` for an
  // absent optional slot member, a duplicate object key (last one wins),
  // reordered keys, base64url padding, or insignificant whitespace — but for a
  // single shared artifact every SDK must reach the identical accept/reject
  // verdict. Re-serializing the reconstructed seal and requiring the input to
  // equal it byte-for-byte collapses the whole class: `preparedSealToJson`
  // only ever emits the canonical form, so any non-canonical input differs
  // here and is refused, by construction, in every language.
  if (!utf8BytesEqual(json, preparedSealToJson(prepared))) {
    throw invalidError('input is not the canonical serialization');
  }
  return prepared;
}

// =============================================================================
// Phase 1 — sealPrepare
// =============================================================================

/**
 * A caller-supplied byte source for `sealPrepareWithRng`: fill the given
 * buffer with the next bytes of the stream.
 */
export type DeterministicRng = (out: Uint8Array) => void;

/**
 * Seal every item to the shared recipient set, drawing every secret from the
 * platform CSPRNG. Pure and offline: no I/O, no network.
 *
 * One KEM covers the whole prepared set (mixing KEMs across slots is
 * forbidden by the standard, and mixing them across the items of one record
 * would silently weaken the strongest envelope to the weakest).
 *
 * Throws `SealPrepareError` when the input carries no items, the recipient
 * set is empty or a key is the wrong length for the chosen KEM, or the
 * cryptographic wrap fails.
 */
export function sealPrepare(input: SealPrepareInput): PreparedSeal {
  return prepare(input, undefined);
}

/**
 * Deterministic twin of `sealPrepare` for known-answer tests and
 * reproducible vectors: every secret (content keys, nonces, per-slot KEM
 * material, shuffle draws) is drawn from the caller-supplied `rng`, in item
 * order.
 *
 * SECURITY: `rng` carries the entire confidentiality guarantee — a weak
 * source yields predictable content keys with no error. Production code
 * calls `sealPrepare`, which pins the platform CSPRNG.
 */
export function sealPrepareWithRng(input: SealPrepareInput, rng: DeterministicRng): PreparedSeal {
  return prepare(input, rng);
}

/**
 * Draw an unbiased index in `[0, m)` from the rng via rejection sampling:
 * four little-endian bytes per draw, rejecting any value at or above the
 * largest multiple of `m` below 2^32 (so the residues map uniformly).
 */
function uniformIndexBelow(rng: DeterministicRng, m: number): number {
  const limit = 0x1_0000_0000 - (0x1_0000_0000 % m);
  const buf = new Uint8Array(4);
  for (;;) {
    rng(buf);
    const x = (buf[0]! | (buf[1]! << 8) | (buf[2]! << 16) | (buf[3]! << 24)) >>> 0;
    if (x < limit) return x % m;
  }
}

/**
 * The final slot order a Fisher-Yates shuffle keyed by `rng` would produce
 * over `n` slots: `order[position] = input index`. Computing the permutation
 * (instead of shuffling wrapped slots) lets the deterministic prepare hand
 * the crypto layer recipients already in wire order, with the shuffle's rng
 * draws consumed at exactly the same point of the stream as the secure path.
 */
function shuffledOrder(n: number, rng: DeterministicRng): number[] {
  const order = Array.from({ length: n }, (_, i) => i);
  if (n < 2) return order;
  for (let i = n - 1; i >= 1; i--) {
    const j = uniformIndexBelow(rng, i + 1);
    const tmp = order[i]!;
    order[i] = order[j]!;
    order[j] = tmp;
  }
  return order;
}

/** The shared prepare path: no `rng` sources secrets from the platform CSPRNG. */
function prepare(input: SealPrepareInput, rng: DeterministicRng | undefined): PreparedSeal {
  if (input.items.length === 0) {
    throw new SealPrepareError('NO_ITEMS', 'at least one item is required');
  }
  if (input.recipients.length === 0) {
    throw new SealPrepareError(
      'INVALID_RECIPIENT',
      'at least one recipient public key is required',
    );
  }
  const kem: SealedKem = input.kem ?? 'mlkem768x25519';
  const expectedLength =
    kem === 'x25519' ? X25519_PUBLIC_KEY_LENGTH : MLKEM768X25519_PUBLIC_KEY_LENGTH;
  for (let i = 0; i < input.recipients.length; i++) {
    const recipient = input.recipients[i]!;
    if (!(recipient instanceof Uint8Array) || recipient.length !== expectedLength) {
      throw new SealPrepareError(
        'INVALID_RECIPIENT',
        `recipients[${i}] must be a ${expectedLength}-byte public key for kem='${kem}'`,
      );
    }
  }
  const hashAlgs = resolveHashAlgs(undefined, input.hashAlgs);

  const itemsData: PreparedItemData[] = [];
  for (const item of input.items) {
    const plaintext = toBytes(item.content);
    // The item's hash claim is an input to the wrap: every digest is bound
    // into the slot-set MAC, so the envelope commits to exactly the `hashes`
    // map this record will carry. A single algorithm produces the same
    // one-entry map (and identical bytes) as before co-hashing; canonical CBOR
    // sorts the map, so the ciphertext is independent of the algorithm order.
    const hashes: Record<string, Uint8Array> = {};
    const hashesMap = new Map<string, Uint8Array>();
    for (const alg of hashAlgs) {
      const digest = hashContent(plaintext, alg);
      hashes[alg] = digest;
      hashesMap.set(alg, digest);
    }
    let sealed: { envelope: SealedEnvelope; ciphertext: Uint8Array };
    try {
      if (rng === undefined) {
        sealed = eciesSealedPoeWrap({
          plaintext,
          hashes,
          recipientPublicKeys: input.recipients.map((r) => r),
          kem,
        });
      } else {
        // The deterministic stream is consumed exactly as the secure wrap
        // draws randomness: content key, nonce, one per-slot secret per
        // recipient in input order, then the shuffle's index draws. The wire
        // slot order is applied by pre-permuting the (recipient, secret)
        // pairs, which commutes with wrapping because a slot depends only on
        // its own pair plus the shared key material.
        const cek = new Uint8Array(CEK_LENGTH);
        rng(cek);
        const nonce = new Uint8Array(ENVELOPE_NONCE_LENGTH);
        rng(nonce);
        const secretLength =
          kem === 'x25519' ? X25519_EPHEMERAL_SECRET_LENGTH : MLKEM768X25519_ESEED_LENGTH;
        const secrets = input.recipients.map(() => {
          const secret = new Uint8Array(secretLength);
          rng(secret);
          return secret;
        });
        const order = shuffledOrder(input.recipients.length, rng);
        const orderedRecipients = order.map((index) => input.recipients[index]!);
        const orderedSecrets = order.map((index) => secrets[index]!);
        sealed = eciesSealedPoeWrap({
          plaintext,
          hashes,
          recipientPublicKeys: orderedRecipients,
          kem,
          cek,
          nonce,
          ...(kem === 'x25519' ? { ephemeralSecrets: orderedSecrets } : { eseeds: orderedSecrets }),
          skipShuffle: true,
        });
      }
    } catch (error) {
      throw new SealPrepareError(
        'CRYPTO_FAILURE',
        error instanceof Error ? error.message : String(error),
      );
    }
    itemsData.push({
      itemId: bytesToHex(sha256(sealed.ciphertext)),
      ciphertext: sealed.ciphertext,
      hashes: hashesMap,
      envelope: sealed.envelope,
    });
  }

  return newPreparedSeal(kem, itemsData, fingerprintOf(toDocument(kem, itemsData)));
}

// =============================================================================
// Pure assembly seams
// =============================================================================

/**
 * Parse a supersedes value into the 32-byte transaction hash the record
 * carries.
 */
function parseSupersedesHex(value: string): Uint8Array<ArrayBuffer> {
  if (value.length !== SUPERSEDES_HEX_LENGTH || !/^[0-9a-fA-F]+$/.test(value)) {
    throw new SealPrepareError(
      'INVALID_SUPERSEDES',
      'supersedes must be the 64-hex transaction hash',
    );
  }
  const out = new Uint8Array(new ArrayBuffer(SUPERSEDES_HEX_LENGTH / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Lower an in-memory sealed envelope to the record `enc` shape. */
function buildRecordEnvelope(env: SealedEnvelope): EncryptionEnvelope {
  const slots =
    env.kem === 'x25519'
      ? env.slots.map((slot) => ({
          epk: cloneBytes(slot.epk),
          wrap: cloneBytes(slot.wrap),
        }))
      : env.slots.map((slot) => ({
          // The record carries `kem_ct` as the single 1120-byte X-Wing
          // encapsulation, exactly as the crypto layer holds it.
          kem_ct: cloneBytes(slot.kem_ct),
          wrap: cloneBytes(slot.wrap),
        }));
  return {
    scheme: 1,
    aead: env.aead,
    kem: env.kem,
    nonce: cloneBytes(env.nonce),
    slots,
    slots_mac: cloneBytes(env.slots_mac),
  };
}

/**
 * Reject any storage URI that is not a well-formed fetch-set member before it
 * is embedded as a record URI. This is the one seam every sealed URI — a fresh
 * gateway upload, a resumed receipt, or an air-gapped caller's out-of-band URI —
 * flows through on its way into the record, and it enforces the exact grammar
 * the canonical validator uses (via the single-sourced `isFetchSetUri`), so no
 * assembled record can carry a URI a downstream verifier would reject.
 */
function validateAssembledUris(uris: ReadonlyArray<string>): void {
  for (const uri of uris) {
    if (!isFetchSetUri(uri)) {
      throw new SealPrepareError(
        'INVALID_URI',
        `${uri} is not a valid ar:// or ipfs:// fetch-set uri`,
      );
    }
  }
}

/**
 * Assemble the Label 309 record from prepared material and the uploaded
 * storage URIs — the pure seam air-gapped flows build on.
 *
 * `uris` must carry exactly one storage URI per prepared item, in item
 * order. `supersedes` is the 64-hex hash of the transaction this record
 * replaces, when any.
 *
 * Throws `SealPrepareError` with code `URI_COUNT_MISMATCH` on a wrong URI
 * count, `INVALID_URI` on a malformed storage URI, and `INVALID_SUPERSEDES`
 * on a malformed supersedes hash.
 */
export function sealedRecord(
  prepared: PreparedSeal,
  uris: ReadonlyArray<string>,
  supersedes?: string,
): PoeRecord {
  const data = sealDataOf(prepared);
  if (uris.length !== data.itemsData.length) {
    throw new SealPrepareError(
      'URI_COUNT_MISMATCH',
      `expected ${data.itemsData.length} storage uri(s), one per item, got ${uris.length}`,
    );
  }
  validateAssembledUris(uris);
  const supersedesBytes = supersedes === undefined ? undefined : parseSupersedesHex(supersedes);
  const items = data.itemsData.map((item, index) => {
    const hashes: Record<string, Uint8Array<ArrayBuffer>> = {};
    for (const [alg, digest] of item.hashes) hashes[alg] = cloneBytes(digest);
    return {
      hashes,
      uris: [uris[index]!],
      enc: buildRecordEnvelope(item.envelope),
    };
  });
  return {
    v: 1,
    items,
    ...(supersedesBytes !== undefined ? { supersedes: supersedesBytes } : {}),
  };
}

/**
 * Canonical-bytes twin of `sealedRecord`: assemble the record and encode it,
 * attaching a path-1 COSE_Sign1 first when a signer is supplied. Air-gapped
 * flows archive these exact bytes.
 */
export async function encodeSealedRecord(
  prepared: PreparedSeal,
  uris: ReadonlyArray<string>,
  supersedes?: string,
  signer?: Signer,
): Promise<Uint8Array> {
  if (signer !== undefined) assertSigner(signer);
  const record = sealedRecord(prepared, uris, supersedes);
  return encodeRecord(record, signer);
}

// =============================================================================
// Quoting
// =============================================================================

/**
 * The byte counts a prepared seal is priced against.
 *
 * The record side is the exact-width upper-bound estimate over the prepared
 * shape with a fixed-width Arweave URI placeholder per item (a real `ar://`
 * URI is always 5 + 43 characters, so the estimate is exact before any
 * upload); the storage side is the exact ciphertext total.
 */
function preparedQuoteInput(
  data: PreparedSealData,
  signed: boolean,
  supersedes: boolean,
): QuoteInput {
  const shape: RecordShape = {
    items: data.itemsData.map((item) => ({
      hashAlgs: [...item.hashes.keys()],
      uris: [arweaveUriPlaceholder()],
      enc: { kind: 'kem', kem: data.kem, recipientCount: item.envelope.slots.length },
    })),
    signed,
    supersedes,
  };
  let recipientCount = 0;
  let fileBytesTotal = 0;
  for (const item of data.itemsData) {
    recipientCount += item.envelope.slots.length;
    fileBytesTotal += item.ciphertext.length;
  }
  return {
    recordBytes: estimateRecordBytes(shape),
    recipientCount,
    fileBytesTotal,
  };
}

/**
 * Price a prepared seal without uploading anything — the preview UIs show
 * before the user commits to storage. The returned quote may later be passed
 * to `submitSealed` via `SubmitSealedInput.quote`.
 */
export async function quotePreparedSeal(
  config: ResolvedPublishConfig,
  input: QuotePreparedSealInput,
): Promise<QuoteResponse> {
  if (input.signer !== undefined) assertSigner(input.signer);
  const quoteInput = preparedQuoteInput(
    sealDataOf(input.prepared),
    input.signer !== undefined,
    input.supersedes !== undefined,
  );
  return postQuote(config, quoteInput);
}

// =============================================================================
// Phase 2 — submitSealed
// =============================================================================

/**
 * Validate resume receipts against the prepared material, keyed by item
 * index. Every field must match — an unknown `itemId`, a digest or byte count
 * that differs from the prepared ciphertext, a URI that is not a valid Arweave
 * `ar://<43-char txid>` (a sealed ciphertext is always stored on Arweave, so
 * the receipt URI is fixed-width — this both rejects a hand-crafted URI that
 * would fail canonical validation and keeps the pre-upload exact-size quote
 * exact), or a duplicate receipt is rejected outright rather than skipped.
 */
function validateReceipts(
  itemsData: ReadonlyArray<{ readonly itemId: string; readonly ciphertext: Uint8Array }>,
  uploaded: ReadonlyArray<UploadReceipt>,
): Map<number, UploadReceipt> {
  const byIndex = new Map<number, UploadReceipt>();
  for (const receipt of uploaded) {
    const index = itemsData.findIndex((item) => item.itemId === receipt.itemId);
    if (index < 0) {
      throw new InvalidUploadReceiptError(
        `item_id ${receipt.itemId} does not belong to the prepared seal`,
      );
    }
    const item = itemsData[index]!;
    const digest = receipt.ciphertextSha256;
    if (
      !(digest instanceof Uint8Array) ||
      digest.length !== CIPHERTEXT_SHA256_LENGTH ||
      bytesToHex(digest) !== bytesToHex(sha256(item.ciphertext))
    ) {
      throw new InvalidUploadReceiptError(
        `receipt for ${receipt.itemId} has a ciphertext_sha256 that does not match the prepared ciphertext`,
      );
    }
    if (receipt.bytes !== item.ciphertext.length) {
      throw new InvalidUploadReceiptError(
        `receipt for ${receipt.itemId} declares ${receipt.bytes} byte(s), prepared ciphertext is ${item.ciphertext.length}`,
      );
    }
    if (!isArweaveTxUri(receipt.uri)) {
      throw new InvalidUploadReceiptError(
        `receipt for ${receipt.itemId} carries ${JSON.stringify(
          receipt.uri,
        )}, not a valid Arweave ar://<43-char txid> uri`,
      );
    }
    if (byIndex.has(index)) {
      throw new InvalidUploadReceiptError(`duplicate receipt for ${receipt.itemId}`);
    }
    byIndex.set(index, {
      itemId: receipt.itemId,
      uri: receipt.uri,
      ciphertextSha256: cloneBytes(digest),
      bytes: receipt.bytes,
    });
  }
  return byIndex;
}

/** The map's receipts in ascending item order (for error carry). */
function receiptsInIndexOrder(byIndex: Map<number, UploadReceipt>): UploadReceipt[] {
  return [...byIndex.entries()].sort(([a], [b]) => a - b).map(([, receipt]) => receipt);
}

/**
 * Submit a prepared seal: quote → price-cap check → per-item ciphertext
 * upload (skipping items covered by validated receipts) → quote refresh if
 * an upload outlived the price lock → encode (optionally sign) → publish.
 *
 * Uploads carry the deterministic per-item idempotency key
 * (`PreparedSeal.uploadIdempotencyKey`), so a crash-and-retry of the same
 * prepared item can never pay for its storage twice.
 *
 * Rejects with `SubmitSealedError`; when the failure happened after any
 * upload completed, `SubmitSealedError.uploads` carries the finished
 * receipts — persist them and resume via `SubmitSealedInput.uploaded`.
 */
export async function submitSealed(
  config: ResolvedPublishConfig,
  input: SubmitSealedInput,
): Promise<SealedSubmission> {
  const data = sealDataOf(input.prepared);

  // Everything that can be validated without the network fails before the
  // quote is spent: the signer shape, the supersedes format, the price cap's
  // own format, the receipts.
  let maxUsdMicros: bigint | undefined;
  let resumed: Map<number, UploadReceipt>;
  try {
    if (input.signer !== undefined) assertSigner(input.signer);
    if (input.supersedes !== undefined) parseSupersedesHex(input.supersedes);
    maxUsdMicros = normalizeMaxUsdMicros(input.maxUsdMicros);
    resumed = validateReceipts(data.itemsData, input.uploaded ?? []);
  } catch (error) {
    throw new SubmitSealedError([], error);
  }

  const quoteInput = preparedQuoteInput(
    data,
    input.signer !== undefined,
    input.supersedes !== undefined,
  );

  // A caller-passed preview is consumed only while it is still comfortably
  // inside its TTL; anything else re-quotes so the publish never races the
  // gateway's expiry check.
  let quote: QuoteResponse;
  try {
    quote =
      input.quote !== undefined && quoteIsFresh(input.quote)
        ? input.quote
        : await postQuote(config, quoteInput);
    enforceMaxUsdMicros(maxUsdMicros, quote);
  } catch (error) {
    throw new SubmitSealedError(receiptsInIndexOrder(resumed), error);
  }

  const uploads: UploadReceipt[] = [];
  for (let index = 0; index < data.itemsData.length; index++) {
    const item = data.itemsData[index]!;
    const receipt = resumed.get(index);
    if (receipt !== undefined) {
      resumed.delete(index);
      uploads.push(receipt);
      continue;
    }
    const key = input.prepared.uploadIdempotencyKey(index);
    try {
      const uri = await uploadBlob(config, item.ciphertext, key, input.chunkBytes);
      uploads.push({
        itemId: item.itemId,
        uri,
        ciphertextSha256: cloneBytes(sha256(item.ciphertext)),
        bytes: item.ciphertext.length,
      });
    } catch (error) {
      // Receipts for later items were validated but not yet folded into the
      // ordered list; return every completed upload.
      uploads.push(...receiptsInIndexOrder(resumed));
      throw new SubmitSealedError(uploads, error);
    }
  }

  try {
    // A large upload can outlive the price lock; publish only against a live
    // one, re-enforcing the cap against the refreshed price.
    quote = await refreshQuoteIfStale(config, quote, quoteInput, maxUsdMicros);

    const uris = uploads.map((receipt) => receipt.uri);
    const recordBytes = await encodeSealedRecord(
      input.prepared,
      uris,
      input.supersedes,
      input.signer,
    );
    const response = await postPublish(
      config,
      bytesToHex(recordBytes),
      quote.quote_id,
      input.idempotencyKey,
    );
    return { response, recordBytes, uris, uploads, quote };
  } catch (error) {
    throw new SubmitSealedError(uploads, error);
  }
}

// =============================================================================
// One-shot wrapper
// =============================================================================

/**
 * One-shot sealed publish: `sealPrepare` followed by `submitSealed`.
 *
 * Convenient when nothing needs to survive a process crash; a flow that must
 * resume (CI jobs, large ciphertexts) runs the two phases itself and
 * persists the `PreparedSeal` and the `UploadReceipt`s.
 *
 * Rejects with `SubmitSealedError`; see `submitSealed`.
 */
export async function publishSealed(
  config: ResolvedPublishConfig,
  input: PublishSealedInput,
): Promise<SealedSubmission> {
  let prepared: PreparedSeal;
  try {
    prepared = sealPrepare({
      items: input.items,
      recipients: input.recipients,
      ...(input.kem !== undefined ? { kem: input.kem } : {}),
      ...(input.hashAlgs !== undefined ? { hashAlgs: input.hashAlgs } : {}),
    });
  } catch (error) {
    throw new SubmitSealedError([], error);
  }
  return submitSealed(config, {
    prepared,
    ...(input.signer !== undefined ? { signer: input.signer } : {}),
    ...(input.maxUsdMicros !== undefined ? { maxUsdMicros: input.maxUsdMicros } : {}),
    ...(input.supersedes !== undefined ? { supersedes: input.supersedes } : {}),
    ...(input.idempotencyKey !== undefined ? { idempotencyKey: input.idempotencyKey } : {}),
    ...(input.chunkBytes !== undefined ? { chunkBytes: input.chunkBytes } : {}),
  });
}

// =============================================================================
// Passphrase sealed publishing (the shared-secret key path)
// =============================================================================
//
// A passphrase seal delivers the content key through an Argon2id-stretched
// passphrase instead of per-recipient KEM slots, so its envelope carries a
// `passphrase` block (`{alg, salt, params}`) and no `slots` / `slots_mac` /
// `kem`; the key commitment lives inside the ciphertext blob. The two-phase
// shape mirrors the recipient path exactly — a pure offline
// `passphraseSealPrepare`, a `quotePreparedPassphraseSeal` price preview, and
// an online `submitPassphraseSealed` with resumable `UploadReceipt`s — so a
// caller prepares and publishes a passphrase-sealed record the same way it does
// a recipient-sealed one.

// The 16-byte Argon2id salt and 24-byte content nonce drawn per envelope, the
// deterministic per-item upload-key prefix, and the domain tag the fingerprint
// is computed over.
const PASSPHRASE_SALT_BYTES = 16;
const PASSPHRASE_NONCE_BYTES = 24;
const PASSPHRASE_UPLOAD_KEY_PREFIX = 'pwseal1-';
const PASSPHRASE_FINGERPRINT_DOMAIN = 'prepared_passphrase_seal_v1';

/**
 * The Argon2id cost parameters a passphrase seal is built under. The default is
 * the product's producer default: the registry floors for memory (`m = 65536`
 * KiB) and iterations (`t = 3`) plus the RFC 9106 §4 recommended parallelism
 * (`p = 4`). Every SDK uses the same default so a CLI-sealed passphrase record
 * and a web-sealed one share work factors.
 */
export type PassphraseKdfParams = PassphraseParams;

/** The producer-default Argon2id cost parameters (`m = 65536`, `t = 3`, `p = 4`). */
export const DEFAULT_PASSPHRASE_KDF_PARAMS: PassphraseKdfParams = { m: 65536, t: 3, p: 4 };

// =============================================================================
// Passphrase inputs
// =============================================================================

/** Input to `passphraseSealPrepare` / `passphraseSealPrepareWithRng`. */
export interface PassphraseSealPrepareInput {
  /**
   * The plaintext items to seal (1..=N). Every item is sealed under the same
   * passphrase; the published record carries one content item per input item.
   */
  readonly items: ReadonlyArray<SealPrepareItem>;
  /** The shared passphrase. Normalized under the pinned profile before the KDF. */
  readonly passphrase: string;
  /**
   * The plaintext-bind hash algorithms. Empty (or omitted) defaults to a single
   * `sha2-256` entry; several algorithms co-hash each item into a multi-entry
   * `hashes` map, bound into the in-ciphertext key commitment.
   */
  readonly hashAlgs?: readonly SupportedHashAlg[];
  /** The Argon2id cost parameters (defaults to `DEFAULT_PASSPHRASE_KDF_PARAMS`). */
  readonly params?: PassphraseKdfParams;
}

/** Input to `quotePreparedPassphraseSeal`. */
export interface QuotePreparedPassphraseSealInput {
  /** The prepared passphrase seal to price. */
  readonly prepared: PreparedPassphraseSeal;
  /**
   * The record-level signer the eventual submit will use, when any. Only its
   * presence affects the price (a signed record is larger); the signer is not
   * invoked.
   */
  readonly signer?: Signer;
  /**
   * The 64-hex transaction hash the eventual record will supersede, when any.
   * Only its presence affects the price.
   */
  readonly supersedes?: string;
}

/** Input to `submitPassphraseSealed`. */
export interface SubmitPassphraseSealedInput {
  /** The prepared passphrase seal to submit. */
  readonly prepared: PreparedPassphraseSeal;
  /** The optional record-level signer. */
  readonly signer?: Signer;
  /**
   * Refuse to publish when the quoted price exceeds this many USD micro-cents
   * (1 USD = 1,000,000), given as a `bigint` or a decimal string. Enforced
   * against the initial quote and again against any refreshed quote.
   */
  readonly maxUsdMicros?: bigint | string;
  /**
   * An optional prior price preview (from `quotePreparedPassphraseSeal`). A
   * still-fresh preview is consumed as the price lock; a stale one is silently
   * replaced by a fresh internal quote.
   */
  readonly quote?: QuoteResponse;
  /** The 64-hex transaction hash of the record this one supersedes. */
  readonly supersedes?: string;
  /** Optional idempotency key for the publish call. */
  readonly idempotencyKey?: string;
  /**
   * The intended chunk size in bytes for the ciphertext uploads. Omitted uses
   * the resumable helper's default; the server's `max_chunk_bytes` always
   * clamps it down when tighter.
   */
  readonly chunkBytes?: number;
  /**
   * Receipts from a previous attempt's completed uploads. Each is validated
   * against the prepared material; a validated receipt's item skips the upload.
   */
  readonly uploaded?: ReadonlyArray<UploadReceipt>;
}

/**
 * Input to `publishPassphraseSealed` — the one-shot passphrase publish
 * (`passphraseSealPrepare` + `submitPassphraseSealed` in one call).
 */
export interface PublishPassphraseSealedInput {
  /** The plaintext items to seal (1..=N). */
  readonly items: ReadonlyArray<SealPrepareItem>;
  /** The shared passphrase. */
  readonly passphrase: string;
  /** The plaintext-bind hash algorithms (empty/omitted defaults to a single `sha2-256`). */
  readonly hashAlgs?: readonly SupportedHashAlg[];
  /** The Argon2id cost parameters (defaults to `DEFAULT_PASSPHRASE_KDF_PARAMS`). */
  readonly params?: PassphraseKdfParams;
  /** The optional record-level signer. */
  readonly signer?: Signer;
  /**
   * Refuse to publish when the quoted price exceeds this many USD micro-cents,
   * given as a `bigint` or a decimal string.
   */
  readonly maxUsdMicros?: bigint | string;
  /** The 64-hex transaction hash of the record this one supersedes. */
  readonly supersedes?: string;
  /** Optional idempotency key for the publish call. */
  readonly idempotencyKey?: string;
  /** The intended chunk size in bytes for the ciphertext uploads. */
  readonly chunkBytes?: number;
}

// =============================================================================
// The prepared passphrase artifact
// =============================================================================

// Facade internals live in module-private WeakMaps (as with `PreparedSeal`),
// so an in-memory artifact carries no own enumerable state: it can never drift
// from its fingerprint, and — critically — it never stores the passphrase, the
// content key, or any plaintext, so logging or serializing a prepared seal
// cannot leak a secret. The accessors hand out defensive copies only.
interface PreparedPassphraseItemData {
  readonly itemId: string;
  readonly ciphertext: Uint8Array;
  readonly hashes: ReadonlyMap<string, Uint8Array>;
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly params: PassphraseKdfParams;
}

interface PreparedPassphraseSealData {
  readonly itemsData: ReadonlyArray<PreparedPassphraseItemData>;
  readonly items: ReadonlyArray<PreparedPassphraseItem>;
  readonly preparedSha256: string;
}

const PASSPHRASE_ITEM_DATA = new WeakMap<PreparedPassphraseItem, PreparedPassphraseItemData>();
const PASSPHRASE_SEAL_DATA = new WeakMap<PreparedPassphraseSeal, PreparedPassphraseSealData>();

/**
 * One prepared passphrase item: the sealed form of one plaintext. Read-only;
 * every byte-valued accessor returns a defensive copy.
 */
export class PreparedPassphraseItem {
  constructor(guard: symbol) {
    if (guard !== CONSTRUCT_GUARD) {
      throw new TypeError(
        'PreparedPassphraseItem cannot be constructed directly; it is produced by passphraseSealPrepare()',
      );
    }
  }

  private get data(): PreparedPassphraseItemData {
    const data = PASSPHRASE_ITEM_DATA.get(this);
    if (data === undefined) throw new TypeError('detached PreparedPassphraseItem');
    return data;
  }

  /** The item's stable identity: lowercase-hex SHA-256 of its ciphertext blob. */
  get itemId(): string {
    return this.data.itemId;
  }

  /** The `commitment(32) || STREAM` ciphertext blob destined for storage (a copy). */
  ciphertext(): Uint8Array {
    return cloneBytes(this.data.ciphertext);
  }

  /**
   * The item's content-hash map (algorithm identifier → digest bytes, keys in
   * byte order). Digests are copies.
   */
  hashes(): Record<string, Uint8Array> {
    const out: Record<string, Uint8Array> = {};
    for (const [alg, digest] of this.data.hashes) out[alg] = cloneBytes(digest);
    return out;
  }
}

/** The phase-1 artifact of a passphrase seal: every item sealed, nothing uploaded. */
export class PreparedPassphraseSeal {
  constructor(guard: symbol) {
    if (guard !== CONSTRUCT_GUARD) {
      throw new TypeError(
        'PreparedPassphraseSeal cannot be constructed directly; use passphraseSealPrepare()',
      );
    }
  }

  /** The prepared items, in input order. */
  get items(): ReadonlyArray<PreparedPassphraseItem> {
    return passphraseSealDataOf(this).items;
  }

  /**
   * The lowercase-hex SHA-256 fingerprint over the prepared items — a stable
   * identity for the whole prepared set that seeds the upload keys.
   */
  get preparedSha256(): string {
    return passphraseSealDataOf(this).preparedSha256;
  }

  /**
   * The deterministic idempotency key for the item's ciphertext upload:
   * `"pwseal1-" + prepared_sha256[..32] + "-" + itemIndex`. Deriving the key
   * from the artifact (not from upload-time randomness) lets a crash-and-retry
   * replay the original upload instead of paying for a second one.
   *
   * Throws a `RangeError` when `itemIndex` is out of range for `items`.
   */
  uploadIdempotencyKey(itemIndex: number): string {
    const data = passphraseSealDataOf(this);
    if (!Number.isInteger(itemIndex) || itemIndex < 0 || itemIndex >= data.itemsData.length) {
      throw new RangeError(
        `itemIndex ${itemIndex} out of range for ${data.itemsData.length} prepared item(s)`,
      );
    }
    const fingerprint = data.preparedSha256.slice(0, UPLOAD_KEY_FINGERPRINT_CHARS);
    return `${PASSPHRASE_UPLOAD_KEY_PREFIX}${fingerprint}-${itemIndex}`;
  }
}

function passphraseSealDataOf(prepared: PreparedPassphraseSeal): PreparedPassphraseSealData {
  const data = PASSPHRASE_SEAL_DATA.get(prepared);
  if (data === undefined) {
    throw new TypeError(
      'PreparedPassphraseSeal must come from passphraseSealPrepare() or passphraseSealPrepareWithRng()',
    );
  }
  return data;
}

/** Build the facade pair over validated item data. */
function newPreparedPassphraseSeal(
  itemsData: ReadonlyArray<PreparedPassphraseItemData>,
  preparedSha256: string,
): PreparedPassphraseSeal {
  const items = Object.freeze(
    itemsData.map((data) => {
      const item = new PreparedPassphraseItem(CONSTRUCT_GUARD);
      PASSPHRASE_ITEM_DATA.set(item, data);
      return item;
    }),
  );
  const prepared = new PreparedPassphraseSeal(CONSTRUCT_GUARD);
  PASSPHRASE_SEAL_DATA.set(prepared, { itemsData, items, preparedSha256 });
  return prepared;
}

/**
 * The lowercase-hex SHA-256 fingerprint over the prepared items: the domain tag
 * followed by each item's `item_id` (a 64-char hex string, hashed as its ASCII
 * bytes) in order. Each ciphertext (and thus its `item_id`) already binds the
 * passphrase, salt, params, nonce, and hashes, so this is a complete content
 * fingerprint of the prepared set.
 */
function passphraseFingerprint(itemsData: ReadonlyArray<PreparedPassphraseItemData>): string {
  const parts: Uint8Array[] = [utf8Encoder.encode(PASSPHRASE_FINGERPRINT_DOMAIN)];
  for (const item of itemsData) parts.push(utf8Encoder.encode(item.itemId));
  let total = 0;
  for (const part of parts) total += part.length;
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buf.set(part, offset);
    offset += part.length;
  }
  return bytesToHex(sha256(buf));
}

// =============================================================================
// Phase 1 — passphraseSealPrepare
// =============================================================================

/**
 * Seal every item under the shared passphrase, drawing every salt and nonce
 * from the platform CSPRNG. Pure and offline: no I/O, no network.
 *
 * Rejects with `SealPrepareError` when the input carries no items or the
 * cryptographic seal fails (a passphrase that normalizes to the empty string,
 * below-floor Argon2id parameters, or an unavailable platform CSPRNG).
 */
export async function passphraseSealPrepare(
  input: PassphraseSealPrepareInput,
): Promise<PreparedPassphraseSeal> {
  return preparePassphrase(input, undefined);
}

/**
 * Deterministic twin of `passphraseSealPrepare` for known-answer tests: every
 * salt and nonce is drawn from the caller-supplied `rng`, in item order (salt
 * before nonce per item).
 *
 * SECURITY: `rng` carries the salt/nonce separation guarantee — a weak source
 * yields predictable salts with no error. Production code calls
 * `passphraseSealPrepare`, which pins the platform CSPRNG.
 */
export async function passphraseSealPrepareWithRng(
  input: PassphraseSealPrepareInput,
  rng: DeterministicRng,
): Promise<PreparedPassphraseSeal> {
  return preparePassphrase(input, rng);
}

/** The shared passphrase-prepare path: no `rng` sources secrets from the CSPRNG. */
async function preparePassphrase(
  input: PassphraseSealPrepareInput,
  rng: DeterministicRng | undefined,
): Promise<PreparedPassphraseSeal> {
  if (input.items.length === 0) {
    throw new SealPrepareError('NO_ITEMS', 'at least one item is required');
  }
  const hashAlgs = resolveHashAlgs(undefined, input.hashAlgs);
  const params = input.params ?? DEFAULT_PASSPHRASE_KDF_PARAMS;

  const itemsData: PreparedPassphraseItemData[] = [];
  for (const item of input.items) {
    const plaintext = toBytes(item.content);
    // Every digest is bound into the in-ciphertext key commitment, so the
    // envelope commits to exactly the `hashes` map this record will carry.
    const hashes: Record<string, Uint8Array> = {};
    const hashesMap = new Map<string, Uint8Array>();
    for (const alg of hashAlgs) {
      const digest = hashContent(plaintext, alg);
      hashes[alg] = digest;
      hashesMap.set(alg, digest);
    }
    // The deterministic path draws salt (16 bytes) then nonce (24 bytes) from
    // the caller's rng and passes them; the secure path lets the crypto layer
    // draw them and reads them back off the returned envelope.
    let sealArgs: {
      plaintext: Uint8Array;
      hashes: Record<string, Uint8Array>;
      passphrase: string;
      params: PassphraseKdfParams;
      salt?: Uint8Array;
      nonce?: Uint8Array;
    } = { plaintext, hashes, passphrase: input.passphrase, params };
    if (rng !== undefined) {
      const salt = new Uint8Array(PASSPHRASE_SALT_BYTES);
      rng(salt);
      const nonce = new Uint8Array(PASSPHRASE_NONCE_BYTES);
      rng(nonce);
      sealArgs = { ...sealArgs, salt, nonce };
    }
    let sealed: PassphraseSealedPoeOutput;
    try {
      sealed = await passphraseSealedPoeSeal(sealArgs);
    } catch (error) {
      throw new SealPrepareError(
        'CRYPTO_FAILURE',
        error instanceof Error ? error.message : String(error),
      );
    }
    itemsData.push({
      itemId: bytesToHex(sha256(sealed.blob)),
      ciphertext: sealed.blob,
      hashes: hashesMap,
      salt: sealed.envelope.passphrase.salt,
      nonce: sealed.envelope.nonce,
      params: sealed.envelope.passphrase.params,
    });
  }

  return newPreparedPassphraseSeal(itemsData, passphraseFingerprint(itemsData));
}

// =============================================================================
// Pure assembly seams
// =============================================================================

/** Lower one prepared passphrase item to the record `enc` shape. */
function buildPassphraseEnvelope(item: PreparedPassphraseItemData): EncryptionEnvelope {
  return {
    scheme: 1,
    aead: SEALED_POE_AEAD,
    nonce: cloneBytes(item.nonce),
    passphrase: {
      alg: PASSPHRASE_KDF_ARGON2ID,
      salt: cloneBytes(item.salt),
      params: { m: item.params.m, t: item.params.t, p: item.params.p },
    },
  };
}

/**
 * Assemble the Label 309 record from prepared passphrase material and the
 * uploaded storage URIs.
 *
 * `uris` must carry exactly one storage URI per prepared item, in item order.
 * `supersedes` is the 64-hex hash of the transaction this record replaces.
 *
 * Throws `SealPrepareError` with code `URI_COUNT_MISMATCH` on a wrong URI
 * count, `INVALID_URI` on a malformed storage URI, and `INVALID_SUPERSEDES`
 * on a malformed supersedes hash.
 */
export function passphraseSealedRecord(
  prepared: PreparedPassphraseSeal,
  uris: ReadonlyArray<string>,
  supersedes?: string,
): PoeRecord {
  const data = passphraseSealDataOf(prepared);
  if (uris.length !== data.itemsData.length) {
    throw new SealPrepareError(
      'URI_COUNT_MISMATCH',
      `expected ${data.itemsData.length} storage uri(s), one per item, got ${uris.length}`,
    );
  }
  validateAssembledUris(uris);
  const supersedesBytes = supersedes === undefined ? undefined : parseSupersedesHex(supersedes);
  const items = data.itemsData.map((item, index) => {
    const hashes: Record<string, Uint8Array<ArrayBuffer>> = {};
    for (const [alg, digest] of item.hashes) hashes[alg] = cloneBytes(digest);
    return {
      hashes,
      uris: [uris[index]!],
      enc: buildPassphraseEnvelope(item),
    };
  });
  return {
    v: 1,
    items,
    ...(supersedesBytes !== undefined ? { supersedes: supersedesBytes } : {}),
  };
}

/**
 * Canonical-bytes twin of `passphraseSealedRecord`: assemble and encode the
 * record, attaching a path-1 COSE_Sign1 first when a signer is supplied.
 */
export async function encodePassphraseSealedRecord(
  prepared: PreparedPassphraseSeal,
  uris: ReadonlyArray<string>,
  supersedes?: string,
  signer?: Signer,
): Promise<Uint8Array> {
  if (signer !== undefined) assertSigner(signer);
  const record = passphraseSealedRecord(prepared, uris, supersedes);
  return encodeRecord(record, signer);
}

// =============================================================================
// Quoting
// =============================================================================

/**
 * The byte counts a prepared passphrase seal is priced against.
 *
 * Unlike the recipient path (whose slot count feeds a size estimate), a
 * passphrase envelope is fixed-shape, so the record side is measured exactly:
 * assemble the record over fixed-width `ar://` URI placeholders — plus a
 * fixed-width path-1 signature placeholder when signed — and canonically encode
 * it. A real `ar://` URI and a real path-1 COSE_Sign1 are both fixed-width, so
 * the measured length is the exact published `record_bytes`.
 */
function passphraseQuoteInput(
  prepared: PreparedPassphraseSeal,
  signed: boolean,
  supersedes: string | undefined,
): QuoteInput {
  const data = passphraseSealDataOf(prepared);
  const placeholders = data.itemsData.map(() => arweaveUriPlaceholder());
  const base = passphraseSealedRecord(prepared, placeholders, supersedes);
  const record: PoeRecord = signed
    ? { ...base, sigs: [{ cose_sign1: new Uint8Array(COSE_SIGN1_PATH1_BYTES) }] }
    : base;
  let fileBytesTotal = 0;
  for (const item of data.itemsData) fileBytesTotal += item.ciphertext.length;
  return {
    recordBytes: encodePoeRecord(record).length,
    recipientCount: 0,
    fileBytesTotal,
  };
}

/**
 * Price a prepared passphrase seal without uploading anything — the preview UIs
 * show before the user commits to storage.
 */
export async function quotePreparedPassphraseSeal(
  config: ResolvedPublishConfig,
  input: QuotePreparedPassphraseSealInput,
): Promise<QuoteResponse> {
  if (input.signer !== undefined) assertSigner(input.signer);
  const quoteInput = passphraseQuoteInput(
    input.prepared,
    input.signer !== undefined,
    input.supersedes,
  );
  return postQuote(config, quoteInput);
}

// =============================================================================
// Phase 2 — submitPassphraseSealed
// =============================================================================

/**
 * Submit a prepared passphrase seal: quote → price-cap check → per-item
 * ciphertext upload (skipping items covered by validated receipts) → quote
 * refresh if an upload outlived the price lock → encode (optionally sign) →
 * publish.
 *
 * Rejects with `SubmitSealedError`; a failure after any upload completed
 * carries the finished receipts for resume via
 * `SubmitPassphraseSealedInput.uploaded`.
 */
export async function submitPassphraseSealed(
  config: ResolvedPublishConfig,
  input: SubmitPassphraseSealedInput,
): Promise<SealedSubmission> {
  const data = passphraseSealDataOf(input.prepared);

  // Everything that can be validated without the network fails before the
  // quote is spent: the signer shape, the supersedes format, the price cap's
  // own format, the receipts.
  let maxUsdMicros: bigint | undefined;
  let resumed: Map<number, UploadReceipt>;
  try {
    if (input.signer !== undefined) assertSigner(input.signer);
    if (input.supersedes !== undefined) parseSupersedesHex(input.supersedes);
    maxUsdMicros = normalizeMaxUsdMicros(input.maxUsdMicros);
    resumed = validateReceipts(data.itemsData, input.uploaded ?? []);
  } catch (error) {
    throw new SubmitSealedError([], error);
  }

  const quoteInput = passphraseQuoteInput(
    input.prepared,
    input.signer !== undefined,
    input.supersedes,
  );

  let quote: QuoteResponse;
  try {
    quote =
      input.quote !== undefined && quoteIsFresh(input.quote)
        ? input.quote
        : await postQuote(config, quoteInput);
    enforceMaxUsdMicros(maxUsdMicros, quote);
  } catch (error) {
    throw new SubmitSealedError(receiptsInIndexOrder(resumed), error);
  }

  const uploads: UploadReceipt[] = [];
  for (let index = 0; index < data.itemsData.length; index++) {
    const item = data.itemsData[index]!;
    const receipt = resumed.get(index);
    if (receipt !== undefined) {
      resumed.delete(index);
      uploads.push(receipt);
      continue;
    }
    const key = input.prepared.uploadIdempotencyKey(index);
    try {
      const uri = await uploadBlob(config, item.ciphertext, key, input.chunkBytes);
      uploads.push({
        itemId: item.itemId,
        uri,
        ciphertextSha256: cloneBytes(sha256(item.ciphertext)),
        bytes: item.ciphertext.length,
      });
    } catch (error) {
      uploads.push(...receiptsInIndexOrder(resumed));
      throw new SubmitSealedError(uploads, error);
    }
  }

  try {
    quote = await refreshQuoteIfStale(config, quote, quoteInput, maxUsdMicros);

    const uris = uploads.map((receipt) => receipt.uri);
    const recordBytes = await encodePassphraseSealedRecord(
      input.prepared,
      uris,
      input.supersedes,
      input.signer,
    );
    const response = await postPublish(
      config,
      bytesToHex(recordBytes),
      quote.quote_id,
      input.idempotencyKey,
    );
    return { response, recordBytes, uris, uploads, quote };
  } catch (error) {
    throw new SubmitSealedError(uploads, error);
  }
}

// =============================================================================
// One-shot wrapper
// =============================================================================

/**
 * One-shot passphrase publish: `passphraseSealPrepare` followed by
 * `submitPassphraseSealed`.
 *
 * Rejects with `SubmitSealedError`; see `submitPassphraseSealed`.
 */
export async function publishPassphraseSealed(
  config: ResolvedPublishConfig,
  input: PublishPassphraseSealedInput,
): Promise<SealedSubmission> {
  let prepared: PreparedPassphraseSeal;
  try {
    prepared = await passphraseSealPrepare({
      items: input.items,
      passphrase: input.passphrase,
      ...(input.hashAlgs !== undefined ? { hashAlgs: input.hashAlgs } : {}),
      ...(input.params !== undefined ? { params: input.params } : {}),
    });
  } catch (error) {
    throw new SubmitSealedError([], error);
  }
  return submitPassphraseSealed(config, {
    prepared,
    ...(input.signer !== undefined ? { signer: input.signer } : {}),
    ...(input.maxUsdMicros !== undefined ? { maxUsdMicros: input.maxUsdMicros } : {}),
    ...(input.supersedes !== undefined ? { supersedes: input.supersedes } : {}),
    ...(input.idempotencyKey !== undefined ? { idempotencyKey: input.idempotencyKey } : {}),
    ...(input.chunkBytes !== undefined ? { chunkBytes: input.chunkBytes } : {}),
  });
}

// =============================================================================
// base64url (RFC 4648 §5, unpadded)
// =============================================================================

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Unpadded base64url of a byte array. */
function base64urlEncode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    const triple = (b0 << 16) | ((b1 ?? 0) << 8) | (b2 ?? 0);
    out += BASE64URL_ALPHABET[(triple >> 18) & 0x3f]!;
    out += BASE64URL_ALPHABET[(triple >> 12) & 0x3f]!;
    if (b1 !== undefined) out += BASE64URL_ALPHABET[(triple >> 6) & 0x3f]!;
    if (b2 !== undefined) out += BASE64URL_ALPHABET[triple & 0x3f]!;
  }
  return out;
}

function base64urlValue(code: number): number | undefined {
  if (code >= 65 && code <= 90) return code - 65; // A-Z
  if (code >= 97 && code <= 122) return code - 97 + 26; // a-z
  if (code >= 48 && code <= 57) return code - 48 + 52; // 0-9
  if (code === 45) return 62; // '-'
  if (code === 95) return 63; // '_'
  return undefined;
}

/**
 * Strict unpadded-base64url decode: rejects padding, characters outside the
 * alphabet, an impossible remainder length, and non-zero trailing bits (so
 * every byte string has exactly one accepted encoding).
 */
function base64urlDecode(text: string): Uint8Array | undefined {
  if (text.length % 4 === 1) return undefined;
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let outIndex = 0;
  for (let i = 0; i < text.length; i += 4) {
    const chunkLength = Math.min(4, text.length - i);
    let acc = 0;
    for (let j = 0; j < chunkLength; j++) {
      const value = base64urlValue(text.charCodeAt(i + j));
      if (value === undefined) return undefined;
      acc = (acc << 6) | value;
    }
    if (chunkLength === 4) {
      out[outIndex++] = (acc >> 16) & 0xff;
      out[outIndex++] = (acc >> 8) & 0xff;
      out[outIndex++] = acc & 0xff;
    } else if (chunkLength === 3) {
      // 18 significant bits carry 2 bytes; the low 2 bits must be 0.
      if ((acc & 0b11) !== 0) return undefined;
      out[outIndex++] = (acc >> 10) & 0xff;
      out[outIndex++] = (acc >> 2) & 0xff;
    } else {
      // 12 significant bits carry 1 byte; the low 4 bits must be 0.
      if ((acc & 0b1111) !== 0) return undefined;
      out[outIndex++] = (acc >> 4) & 0xff;
    }
  }
  return out.subarray(0, outIndex);
}

/** Whether `text` is exactly `length` lowercase-hex characters. */
function isLowercaseHex(text: string, length: number): boolean {
  if (text.length !== length) return false;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const isDigit = code >= 48 && code <= 57;
    const isLowerHex = code >= 97 && code <= 102;
    if (!isDigit && !isLowerHex) return false;
  }
  return true;
}
