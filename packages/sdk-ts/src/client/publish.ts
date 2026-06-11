// High-level publish helpers — collapse the new uploads + publish flow into
// single calls for the three common shapes:
//
//   1. `publishContent({content, signer?})` — anchor a single content blob by
//      its `sha2-256` (or `blake2b-256`) digest. No Arweave, no /uploads —
//      the record is constructed entirely client-side and posted directly to
//      /publish.
//
//   2. `publishSealed({content, recipients, signer?})` — encrypt the content
//      to the recipient X25519 public keys (age-style sealed envelope),
//      upload the ciphertext to Arweave via /uploads, build a Label 309 record
//      with the resulting `ar://` URI, sign, and post to /publish.
//
//   3. `publishMerkle({leaves, signer?})` — anchor an arbitrary number of leaf
//      hashes under a single RFC 9162 §2.1.1 root, with the leaves-list CBOR
//      uploaded to Arweave via /uploads. The Merkle root + leaf_count are
//      bound into the on-chain record via `merkle[0]`.
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
import { eciesSealedPoeWrap } from '@cardanowall/crypto-core/sealed-poe';
import {
  encodePoeRecord,
  type EncryptionEnvelope,
  type MerkleCommit,
  type PoeRecord,
} from '@cardanowall/poe-standard';

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
  PublishSealedInput,
  Signer,
  StorageTarget,
  SupportedHashAlg,
  UploadsResponse,
  UploadSuccessEntry,
} from './types';

const ED25519_PUBLIC_KEY_LENGTH = 32;
const ED25519_SIGNATURE_LENGTH = 64;
const X25519_PUBLIC_KEY_LENGTH = 32;
const MLKEM768X25519_PUBLIC_KEY_LENGTH = 1216;
const LEAF_DIGEST_LENGTH = 32;
const STORAGE_TARGET_ARWEAVE = 'arweave' as const;

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
    | 'UNSUPPORTED_HASH_ALG';

  constructor(code: PublishError['code'], message: string) {
    super(message);
    this.name = 'PublishError';
    this.code = code;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new PublishError('INVALID_LEAVES', `hex string has odd length: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new PublishError('INVALID_LEAVES', `invalid hex byte at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

function toBytes(content: Uint8Array | string): Uint8Array {
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

function hashContent(bytes: Uint8Array, alg: SupportedHashAlg): Uint8Array<ArrayBuffer> {
  if (alg === 'sha2-256') return cloneToOwnedBuffer(sha256(bytes));
  if (alg === 'blake2b-256') return cloneToOwnedBuffer(blake2b256(bytes));
  throw new PublishError(
    'UNSUPPORTED_HASH_ALG',
    `hashAlg must be 'sha2-256' or 'blake2b-256', got '${alg as string}'`,
  );
}

function assertSigner(signer: Signer): void {
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

function buildMultipartHeaders(apiKey: string | undefined, idempotencyKey?: string): Headers {
  const headers = new Headers({ accept: 'application/json' });
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

async function encodeRecord(record: PoeRecord, signer: Signer | undefined): Promise<Uint8Array> {
  if (signer === undefined) return encodePoeRecord(record);
  return signAndEncodeRecord(record, signer);
}

async function postPublish(
  config: ResolvedPublishConfig,
  recordBytesHex: string,
  quoteId: string,
  idempotencyKey: string | undefined,
): Promise<PublishResponse> {
  const body = { record: recordBytesHex, quote_id: quoteId };
  const response = await config.fetch(`${config.baseUrl}/api/v1/poe/publish`, {
    method: 'POST',
    headers: buildJsonHeaders(config.apiKey, idempotencyKey),
    body: JSON.stringify(body),
  });
  await throwIfNotOk(response);
  const parsed = (await readJson(response)) as Omit<PublishResponse, 'dedup_hit'>;
  return { ...parsed, dedup_hit: response.status === 200 };
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
    const response = await config.fetch(`${config.baseUrl}/api/v1/poe/uploads`, {
      method: 'POST',
      headers: buildMultipartHeaders(config.apiKey, idempotencyKey),
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
async function uploadBlob(
  config: ResolvedPublishConfig,
  bytes: Uint8Array,
  idempotencyKey: string | undefined,
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
  });
  return result.uri;
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
    const bytes = hexToBytes(hex);
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
 * Sealed-PoE: encrypt content to N X25519 recipients (age-style envelope),
 * upload the ciphertext to Arweave, build a single-item record with the
 * resulting `ar://` URI and the sealed envelope in `items[0].enc`, sign
 * (optional), and post to /publish.
 *
 * The plaintext content-hash is bound into `items[0].hashes` so any verifier
 * that successfully decrypts the ciphertext can reconstruct the plaintext
 * and prove the chain of custody from the on-chain hash to the decrypted
 * bytes.
 */
export async function publishSealed(
  config: ResolvedPublishConfig,
  input: PublishSealedInput,
): Promise<PublishResponse> {
  if (input.signer !== undefined) assertSigner(input.signer);
  if (input.recipients.length < 1) {
    throw new PublishError(
      'INVALID_RECIPIENT',
      'publishSealed requires at least one recipient public key',
    );
  }
  // Default to the post-quantum-safe X-Wing hybrid KEM; x25519 is the explicit
  // classical opt-out. The recipient length guard is KEM-aware: 32 B for
  // x25519, 1216 B for the hybrid path.
  const kem = input.kem ?? 'mlkem768x25519';
  const expectedRecipientLength =
    kem === 'x25519' ? X25519_PUBLIC_KEY_LENGTH : MLKEM768X25519_PUBLIC_KEY_LENGTH;
  for (let i = 0; i < input.recipients.length; i++) {
    const pub = input.recipients[i]!;
    if (!(pub instanceof Uint8Array) || pub.length !== expectedRecipientLength) {
      throw new PublishError(
        'INVALID_RECIPIENT',
        `recipients[${i}] must be a ${expectedRecipientLength}-byte public key for kem='${kem}'`,
      );
    }
  }

  const hashAlg: SupportedHashAlg = input.hashAlg ?? 'sha2-256';
  const plaintext = toBytes(input.content);
  const plaintextDigest = hashContent(plaintext, hashAlg);
  const hashes = { [hashAlg]: plaintextDigest };

  // Encrypt the plaintext to the recipient public keys under the chosen KEM.
  // The item's plaintext-hash claim is bound into the slots transcript, so
  // the envelope cannot later be spliced onto a different hashes map.
  const sealed = eciesSealedPoeWrap({
    plaintext,
    hashes,
    recipientPublicKeys: input.recipients.map((r) => r),
    kem,
  });

  // Upload the ciphertext to Arweave (resumable for large ciphertexts).
  const uri = await uploadBlob(config, sealed.ciphertext, input.idempotencyKey);

  // Build the sealed record: one item with the plaintext-bind hash, the
  // `ar://<tx>` URI of the ciphertext, and the discriminated envelope shape.
  // Narrow on the envelope `kem` to emit the correct per-slot fields:
  // classical slots carry `{ epk, wrap }`, hybrid slots carry the single
  // 1120-byte `{ kem_ct, wrap }`.
  const env = sealed.envelope;
  const slots =
    env.kem === 'mlkem768x25519'
      ? env.slots.map((s) => ({
          kem_ct: cloneToOwnedBuffer(s.kem_ct),
          wrap: cloneToOwnedBuffer(s.wrap),
        }))
      : env.slots.map((s) => ({
          epk: cloneToOwnedBuffer(s.epk),
          wrap: cloneToOwnedBuffer(s.wrap),
        }));
  const envelope: EncryptionEnvelope = {
    scheme: 1,
    aead: env.aead,
    kem: env.kem,
    nonce: cloneToOwnedBuffer(env.nonce),
    slots,
    slots_mac: cloneToOwnedBuffer(env.slots_mac),
  };

  const record: PoeRecord = {
    v: 1,
    items: [
      {
        hashes,
        uris: [uri],
        enc: envelope,
      },
    ],
  };
  const recordBytes = await encodeRecord(record, input.signer);
  return postPublish(config, bytesToHex(recordBytes), input.quoteId, input.idempotencyKey);
}

/**
 * Merkle batch publish via /uploads + /publish — N leaves under one
 * transaction. The leaves-list CBOR is uploaded to Arweave as a single
 * blob; the on-chain record carries
 * `merkle[0] = { alg: 'rfc9162-sha256', root, leaf_count, uris: [ar://<tx>] }`.
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

  const leaves: Uint8Array[] = input.leaves.map((leaf, idx) => {
    const bytes = typeof leaf === 'string' ? hexToBytes(leaf) : leaf;
    if (!(bytes instanceof Uint8Array) || bytes.length !== LEAF_DIGEST_LENGTH) {
      throw new PublishError(
        'INVALID_LEAVES',
        `leaves[${idx}] must be a ${LEAF_DIGEST_LENGTH}-byte sha2-256 digest`,
      );
    }
    return bytes;
  });

  const root = cloneToOwnedBuffer(merkleSha2256Root(leaves));
  const leavesListCbor = encodeLeavesList({ leaves, root });

  // Upload the leaves-list to Arweave (resumable for large leaves-lists).
  const uri = await uploadBlob(config, leavesListCbor, input.idempotencyKey);

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
    input.quoteId,
    input.idempotencyKey,
  );

  return {
    id: published.id,
    tx_hash: published.tx_hash,
    status: published.status,
    root: bytesToHex(root),
    leaf_count: leaves.length,
    ar_uri: uri,
    balance_after_usd_micros: published.balance_after_usd_micros,
  };
}
