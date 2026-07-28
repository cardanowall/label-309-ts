// Passphrase-path sealed PoE: the CEK is derived directly from a normalised
// passphrase via Argon2id — no ephemeral keypair, no slots, no trial-decrypt
// loop, and no on-chain slots_mac. The key commitment that `slots_mac`
// provides on the slots path lives instead in a 32-byte header prepended
// INSIDE the ciphertext blob (same object, same URI, same fetch), so a
// chain-only observer gets no offline passphrase-test oracle: testing a guess
// requires possession of the blob itself.
//
//   blob = commitment(32) || STREAM chunks
//
// The commitment is an HMAC keyed by an HKDF leaf of the CEK over the
// passphrase-transcript hash, which binds the header fields, the Argon2id
// parameters, the normalization profile, and the item's hash claim. Open
// verifies it in constant time BEFORE any chunk is opened; a wrong passphrase
// is indistinguishable from a tampered record by design.

import { randomBytes } from '@noble/ciphers/utils.js';

import { argon2idV13 } from '../kdf/argon2id';
import { compareCt } from '../util/compare-ct';

import { EciesSealedPoeError } from './errors';
import { normalizePassphrase } from './passphrase-normalize';
import { rechunkPlaintext, rechunkSealed } from './rechunk';
import {
  streamOpen,
  StreamOpener,
  streamSeal,
  StreamSealer,
  StreamTamperedError,
  TAG_SIZE,
} from './stream';
import {
  computePassphraseCommitment,
  computePassphraseHash,
  itemHashesHash,
  passphrasePayloadKey,
  type ItemHashes,
} from './transcript';
import { SEALED_POE_AEAD } from './wrap';

const CEK_LENGTH = 32 as const;
const NONCE_LENGTH = 24 as const;
const COMMITMENT_LENGTH = 32 as const;
// The smallest well-formed passphrase-path blob: the 32-byte commitment header
// plus the lone tag of an empty final STREAM chunk. Shared by the buffered
// open's length check and the streaming open's lookahead, so both enforce the
// same pre-KDF floor.
const MIN_PASSPHRASE_BLOB_LENGTH = COMMITMENT_LENGTH + TAG_SIZE;
// Registry-pinned Argon2id constraints: salt 16..64 bytes; m (KiB) ≥ 65536,
// t ≥ 3, p ≥ 1; each parameter a uint ≤ 2^32 − 1. The floors are exported so
// a consumer that must stay in lockstep with them — e.g. a record-size
// estimator charging the canonical producer parameters — reads the one
// authoritative value instead of pinning its own copy.
export const PASSPHRASE_SALT_MIN_LENGTH = 16 as const;
const SALT_MAX_LENGTH = 64 as const;
export const PASSPHRASE_ARGON2_M_MIN = 65536 as const;
export const PASSPHRASE_ARGON2_T_MIN = 3 as const;
export const PASSPHRASE_ARGON2_P_MIN = 1 as const;
const PARAM_VALUE_MAX = 0xffff_ffff;

export interface PassphraseParams {
  readonly m: number;
  readonly t: number;
  readonly p: number;
}

// Producer default: the registry floors for memory and iterations plus the
// RFC 9106 §4 recommended parallelism.
const DEFAULT_PARAMS: PassphraseParams = { m: 65536, t: 3, p: 4 };

// The passphrase-path `enc` envelope as carried on chain: no kem, no slots, no
// slots_mac — the commitment lives in the ciphertext blob.
export interface PassphraseSealedEnvelope {
  readonly scheme: 1;
  readonly aead: typeof SEALED_POE_AEAD;
  readonly nonce: Uint8Array;
  readonly passphrase: {
    readonly alg: 'argon2id';
    readonly salt: Uint8Array;
    readonly params: PassphraseParams;
  };
}

export interface PassphraseSealArgs {
  readonly plaintext: Uint8Array;
  // The item's plaintext-hash claim; bound into the commitment so a spliced
  // envelope fails the header check before any chunk opens.
  readonly hashes: ItemHashes;
  readonly passphrase: string;
  // Fresh CSPRNG salt per envelope by default; a fixed or derived salt makes
  // equal passphrases yield equal CEKs across records.
  readonly salt?: Uint8Array;
  readonly params?: PassphraseParams;
  readonly nonce?: Uint8Array;
}

export interface PassphraseSealedPoeOutput {
  readonly envelope: PassphraseSealedEnvelope;
  // commitment(32) || STREAM chunks — published as one object.
  readonly blob: Uint8Array;
}

export interface PassphraseOpenArgs {
  readonly envelope: PassphraseSealedEnvelope;
  readonly blob: Uint8Array;
  readonly passphrase: string;
  readonly hashes: ItemHashes;
}

// Every decryption-layer failure — wrong passphrase, tampered salt/params/
// header, tampered commitment, malformed or tampered stream — collapses to the
// single TAMPERED_CIPHERTEXT outcome: the response gives an untrusted caller
// nothing to distinguish.
export type PassphraseOpenResult =
  | { readonly matched: true; readonly plaintext: Uint8Array }
  | { readonly matched: false; readonly reason: 'TAMPERED_CIPHERTEXT' };

function assertUint32(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 0 || value > PARAM_VALUE_MAX) {
    throw new EciesSealedPoeError(
      'INVALID_PASSPHRASE_PARAMS',
      `passphrase.params.${name} MUST be a uint in 0..2^32-1, got ${String(value)}`,
    );
  }
}

// Shape checks shared by seal (over caller inputs) and open (over wire data),
// run before any KDF or AEAD primitive.
function assertPassphraseBlock(args: {
  salt: Uint8Array;
  params: PassphraseParams;
  nonce: Uint8Array;
}): void {
  if (args.nonce.length !== NONCE_LENGTH) {
    throw new EciesSealedPoeError(
      'NONCE_LENGTH_MISMATCH',
      `nonce MUST be exactly ${NONCE_LENGTH} bytes, got ${args.nonce.length}`,
    );
  }
  if (args.salt.length < PASSPHRASE_SALT_MIN_LENGTH) {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_SALT_TOO_SHORT',
      `passphrase.salt MUST be at least ${PASSPHRASE_SALT_MIN_LENGTH} bytes, got ${args.salt.length}`,
    );
  }
  if (args.salt.length > SALT_MAX_LENGTH) {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_SALT_TOO_LONG',
      `passphrase.salt MUST be at most ${SALT_MAX_LENGTH} bytes, got ${args.salt.length}`,
    );
  }
  assertUint32(args.params.m, 'm');
  assertUint32(args.params.t, 't');
  assertUint32(args.params.p, 'p');
  if (
    args.params.m < PASSPHRASE_ARGON2_M_MIN ||
    args.params.t < PASSPHRASE_ARGON2_T_MIN ||
    args.params.p < PASSPHRASE_ARGON2_P_MIN
  ) {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
      `passphrase.params MUST satisfy m >= ${PASSPHRASE_ARGON2_M_MIN}, t >= ${PASSPHRASE_ARGON2_T_MIN}, p >= ${PASSPHRASE_ARGON2_P_MIN}; got m=${args.params.m}, t=${args.params.t}, p=${args.params.p}`,
    );
  }
}

// CEK = argon2id(password, salt, params, 32) with the Argon2 version pinned at
// 0x13. `password` is the already-normalized passphrase byte string
// (cardano-poe-pw-norm-v1 via `normalizePassphrase`) — normalization is a
// separate, earlier step so its typed rejections fire before any
// blob-dependent work on the open path.
async function argon2Cek(
  password: Uint8Array,
  salt: Uint8Array,
  params: PassphraseParams,
): Promise<Uint8Array> {
  try {
    return await argon2idV13({
      password,
      salt,
      memSizeKB: params.m,
      iterations: params.t,
      parallelism: params.p,
      outBytes: CEK_LENGTH,
    });
  } catch (cause) {
    throw new EciesSealedPoeError('KDF_DERIVATION_FAILED', 'argon2id rejected the derivation', {
      cause,
    });
  }
}

function commitmentFor(
  envelope: PassphraseSealedEnvelope,
  cek: Uint8Array,
  hashesHash: Uint8Array,
): Uint8Array {
  const pwHash = computePassphraseHash({
    aead: envelope.aead,
    nonce: envelope.nonce,
    hashesHash,
    salt: envelope.passphrase.salt,
    params: envelope.passphrase.params,
  });
  return computePassphraseCommitment({ cek, pwHash });
}

export async function passphraseSealedPoeSeal(
  args: PassphraseSealArgs,
): Promise<PassphraseSealedPoeOutput> {
  const salt = args.salt ?? randomBytes(PASSPHRASE_SALT_MIN_LENGTH);
  const params = args.params ?? DEFAULT_PARAMS;
  const nonce = args.nonce ?? randomBytes(NONCE_LENGTH);
  assertPassphraseBlock({ salt, params, nonce });
  // The hash claim is digested before any KDF work: a sealed item commits to
  // the plaintext only through it, so an item without a content hash cannot be
  // sealed.
  const hashesHash = itemHashesHash(args.hashes);

  const envelope: PassphraseSealedEnvelope = {
    scheme: 1,
    aead: SEALED_POE_AEAD,
    nonce,
    passphrase: { alg: 'argon2id', salt, params: { m: params.m, t: params.t, p: params.p } },
  };

  const cek = await argon2Cek(normalizePassphrase(args.passphrase), salt, params);
  const commitment = commitmentFor(envelope, cek, hashesHash);
  const stream = streamSeal({
    payloadKey: passphrasePayloadKey({ cek, nonce }),
    plaintext: args.plaintext,
  });

  const blob = new Uint8Array(commitment.length + stream.length);
  blob.set(commitment, 0);
  blob.set(stream, commitment.length);
  return { envelope, blob };
}

export async function passphraseSealedPoeOpen(
  args: PassphraseOpenArgs,
): Promise<PassphraseOpenResult> {
  const { envelope, blob } = args;

  // Typed caller-input rejections fire in a pinned order — the item's hash
  // claim, then passphrase normalization, then the envelope shape — and every
  // one of them strictly precedes any blob-dependent generic failure, so a
  // malformed call is reported the same way whatever blob accompanies it.
  const hashesHash = itemHashesHash(args.hashes);
  const password = normalizePassphrase(args.passphrase);

  if (envelope.scheme !== 1) {
    throw new EciesSealedPoeError(
      'UNSUPPORTED_ENVELOPE_SCHEME',
      `envelope.scheme=${String(envelope.scheme)} unsupported (expected 1)`,
    );
  }
  if (envelope.aead !== SEALED_POE_AEAD) {
    throw new EciesSealedPoeError(
      'UNSUPPORTED_AEAD_ALG',
      `envelope.aead=${String(envelope.aead)} unsupported (expected '${SEALED_POE_AEAD}')`,
    );
  }
  if (envelope.passphrase.alg !== 'argon2id') {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_ALG_UNSUPPORTED',
      `passphrase.alg=${String(envelope.passphrase.alg)} unsupported (expected 'argon2id')`,
    );
  }
  assertPassphraseBlock({
    salt: envelope.passphrase.salt,
    params: envelope.passphrase.params,
    nonce: envelope.nonce,
  });

  // A passphrase-path blob shorter than the 32-byte commitment header plus the
  // 16-byte minimum STREAM (the lone tag of an empty final chunk) cannot be
  // well-formed — rejected before the KDF, so no Argon2 work is spent on it.
  // The blob is public input; the early return reveals nothing.
  if (blob.length < MIN_PASSPHRASE_BLOB_LENGTH) {
    return { matched: false, reason: 'TAMPERED_CIPHERTEXT' };
  }

  const cek = await argon2Cek(password, envelope.passphrase.salt, envelope.passphrase.params);

  // Constant-time commitment check BEFORE any chunk is opened: the commitment
  // (not merely a Poly1305 tag deep in the stream) is what a correct passphrase
  // must reproduce, and a mismatch never begins streaming.
  const expected = commitmentFor(envelope, cek, hashesHash);
  if (!compareCt(expected, blob.subarray(0, COMMITMENT_LENGTH))) {
    return { matched: false, reason: 'TAMPERED_CIPHERTEXT' };
  }

  try {
    const plaintext = streamOpen({
      payloadKey: passphrasePayloadKey({ cek, nonce: envelope.nonce }),
      ciphertext: blob.subarray(COMMITMENT_LENGTH),
    });
    return { matched: true, plaintext };
  } catch (e) {
    if (!(e instanceof StreamTamperedError)) throw e;
    return { matched: false, reason: 'TAMPERED_CIPHERTEXT' };
  }
}

// =============================================================================
// Streaming twins
// =============================================================================
//
// `passphraseSealStream` / `passphraseOpenStream` are the async-iterable twins
// of the buffered pair above, mirroring the KEM-slots streaming pair
// (`sealStream` / `unwrapStream` in `stream-seal.ts`): AsyncIterable in/out,
// AbortSignal checked at chunk boundaries, and a multi-gigabyte payload sealed
// or opened without ever buffering the whole plaintext or blob. The output is
// byte-identical to the buffered pair for the same passphrase / salt / params
// / nonce / hashes: the commitment header and the content payload key are a
// pure function of those inputs — never the plaintext — so they are derived up
// front through the exact same helpers the buffered pair uses, and the body is
// then driven through the same re-chunking machine (`rechunk.ts`) as the
// KEM-slots streams.
//
// Bytes yielded by `passphraseOpenStream`'s `plaintext` iterable are TENTATIVE
// exactly as on `unwrapStream`: per-chunk Poly1305 plus the final flag give
// per-segment authentication and truncation resistance, but the whole-item
// hash recompute is the caller's release gate and is not performed here. The
// caller MUST await `outcome`, confirm `matched`, AND recompute the plaintext
// item hash against the record's `hashes` before releasing the bytes.

// Input to `passphraseSealStream`: the buffered `PassphraseSealArgs` with the
// plaintext supplied as an async stream instead of a buffer. `signal` is the
// house cancellation primitive — checked at every chunk boundary while the
// body streams.
export interface PassphraseSealStreamArgs {
  readonly plaintext: AsyncIterable<Uint8Array>;
  // The item's plaintext-hash claim; bound into the commitment so a spliced
  // envelope fails the header check before any chunk opens.
  readonly hashes: ItemHashes;
  readonly passphrase: string;
  // Fresh CSPRNG salt per envelope by default; a fixed or derived salt makes
  // equal passphrases yield equal CEKs across records.
  readonly salt?: Uint8Array;
  readonly params?: PassphraseParams;
  readonly nonce?: Uint8Array;
  readonly signal?: AbortSignal;
}

export interface PassphraseSealStreamResult {
  // Fully resolved before the first body byte is read.
  readonly envelope: PassphraseSealedEnvelope;
  // Drains the blob: the 32-byte commitment header first, then the sealed
  // STREAM one chunk at a time. Consume it to completion; the concatenation is
  // byte-identical to `passphraseSealedPoeSeal(...).blob` for the same inputs.
  readonly blob: AsyncIterable<Uint8Array>;
}

/**
 * Seal a plaintext stream under a passphrase. The envelope and the 32-byte
 * commitment header depend only on the passphrase, the KDF inputs, the nonce,
 * and the item's `hashes` — never on the plaintext — so they are resolved up
 * front through the same validated path as `passphraseSealedPoeSeal`; the
 * `blob` iterable then yields the commitment first and drives the body seal
 * lazily as it is consumed. Peak memory is one CHUNK_SIZE plaintext block plus
 * one sealed (CHUNK_SIZE + TAG_SIZE) block.
 *
 * Typed input rejections fire in the buffered seal's exact order (envelope
 * shape, then the hash claim, then passphrase normalization, then the Argon2id
 * derivation), all from this call — before any iterable is handed back.
 * `signal` aborts the body seal at the next chunk boundary.
 */
export async function passphraseSealStream(
  args: PassphraseSealStreamArgs,
): Promise<PassphraseSealStreamResult> {
  args.signal?.throwIfAborted();
  const salt = args.salt ?? randomBytes(PASSPHRASE_SALT_MIN_LENGTH);
  const params = args.params ?? DEFAULT_PARAMS;
  const nonce = args.nonce ?? randomBytes(NONCE_LENGTH);
  assertPassphraseBlock({ salt, params, nonce });
  // The hash claim is digested before any KDF work: a sealed item commits to
  // the plaintext only through it, so an item without a content hash cannot be
  // sealed.
  const hashesHash = itemHashesHash(args.hashes);

  const envelope: PassphraseSealedEnvelope = {
    scheme: 1,
    aead: SEALED_POE_AEAD,
    nonce,
    passphrase: { alg: 'argon2id', salt, params: { m: params.m, t: params.t, p: params.p } },
  };

  const cek = await argon2Cek(normalizePassphrase(args.passphrase), salt, params);
  const commitment = commitmentFor(envelope, cek, hashesHash);
  const payloadKey = passphrasePayloadKey({ cek, nonce });

  async function* drive(): AsyncGenerator<Uint8Array> {
    yield commitment;
    const sealer = new StreamSealer(payloadKey);
    for await (const { chunk, final } of rechunkPlaintext(args.plaintext, args.signal)) {
      yield sealer.sealChunk(chunk, final);
    }
  }

  return { envelope, blob: drive() };
}

export interface PassphraseOpenStreamArgs {
  readonly envelope: PassphraseSealedEnvelope;
  // The ciphertext blob source: commitment(32) || STREAM chunks.
  readonly blob: AsyncIterable<Uint8Array>;
  readonly passphrase: string;
  readonly hashes: ItemHashes;
  readonly signal?: AbortSignal;
}

// The open outcome the caller MUST check: the buffered `PassphraseOpenResult`
// minus the plaintext (which streams instead). `matched` means the commitment
// verified and every content chunk authenticated — the bytes stay tentative
// until the caller's whole-item hash recompute passes. The single generic
// rejection covers a short blob, a wrong passphrase, tampered header fields,
// and a tampered body, indistinguishable by design.
export type PassphraseStreamOpenOutcome =
  | { readonly matched: true }
  | { readonly matched: false; readonly reason: 'TAMPERED_CIPHERTEXT' };

export interface PassphraseOpenStreamResult {
  // Resolves (never rejects) once the `plaintext` iterable has been fully
  // driven — or immediately, when the header phase already rejected (short
  // blob or commitment mismatch: nothing is yielded). A mid-stream tamper
  // resolves this to the generic rejection AND throws from the `plaintext`
  // iterable, so neither a draining nor a checking consumer can miss it.
  readonly outcome: Promise<PassphraseStreamOpenOutcome>;
  // Yields verified plaintext, CHUNK_SIZE at a time. TENTATIVE until `outcome`
  // is `matched` and the caller's item-hash recompute passes.
  readonly plaintext: AsyncIterable<Uint8Array>;
}

const PASSPHRASE_STREAM_REJECTED = {
  matched: false,
  reason: 'TAMPERED_CIPHERTEXT',
} as const satisfies PassphraseStreamOpenOutcome;

// A header-phase rejection: the outcome is already settled and the plaintext
// iterable yields nothing (mirrors `unwrapStream`'s no-match arm).
function passphraseStreamRejected(): PassphraseOpenStreamResult {
  // eslint-disable-next-line require-yield -- an empty body: nothing to yield.
  const empty = (async function* (): AsyncGenerator<Uint8Array> {
    return;
  })();
  return { outcome: Promise.resolve(PASSPHRASE_STREAM_REJECTED), plaintext: empty };
}

/**
 * Open a passphrase-path blob while streaming its body.
 *
 * Typed caller-input rejections fire in the buffered open's pinned order —
 * the item's hash claim, then passphrase normalization, then the envelope
 * shape — and every one of them strictly precedes any blob-dependent work, so
 * a malformed call rejects this promise identically whatever blob accompanies
 * it.
 *
 * The blob's first 48 bytes (the commitment header plus the lone tag of the
 * smallest well-formed STREAM) are read into a lookahead before any KDF work:
 * a source that ends below that floor is the same generic rejection the
 * buffered open gives a short blob, and Argon2id is never run for it. The
 * candidate CEK is then derived and the commitment verified in constant time
 * BEFORE any chunk is opened — preserving the buffered open's order — so a
 * header-phase rejection yields nothing. On a match the lookahead's body
 * bytes are replayed ahead of the remaining source and the body is opened
 * CHUNK_SIZE at a time; a tag failure or truncation mid-body resolves
 * `outcome` to the generic rejection and throws from the iterable.
 *
 * Yielded bytes are TENTATIVE: the caller MUST await `outcome`, confirm
 * `matched`, and recompute the whole-item hash against the record's `hashes`
 * before releasing them.
 */
export async function passphraseOpenStream(
  args: PassphraseOpenStreamArgs,
): Promise<PassphraseOpenStreamResult> {
  args.signal?.throwIfAborted();
  const { envelope } = args;

  // Typed caller-input rejections in the buffered open's pinned order: the
  // hash claim, then normalization, then the envelope identifiers and shape.
  const hashesHash = itemHashesHash(args.hashes);
  const password = normalizePassphrase(args.passphrase);

  if (envelope.scheme !== 1) {
    throw new EciesSealedPoeError(
      'UNSUPPORTED_ENVELOPE_SCHEME',
      `envelope.scheme=${String(envelope.scheme)} unsupported (expected 1)`,
    );
  }
  if (envelope.aead !== SEALED_POE_AEAD) {
    throw new EciesSealedPoeError(
      'UNSUPPORTED_AEAD_ALG',
      `envelope.aead=${String(envelope.aead)} unsupported (expected '${SEALED_POE_AEAD}')`,
    );
  }
  if (envelope.passphrase.alg !== 'argon2id') {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_ALG_UNSUPPORTED',
      `passphrase.alg=${String(envelope.passphrase.alg)} unsupported (expected 'argon2id')`,
    );
  }
  assertPassphraseBlock({
    salt: envelope.passphrase.salt,
    params: envelope.passphrase.params,
    nonce: envelope.nonce,
  });

  // Fill the 48-byte lookahead. The iterator is consumed manually (instead of
  // `for await`) so any bytes the source hands over past the floor are kept
  // and replayed into the body; in exchange, every early exit below closes the
  // source explicitly — the finalization `for await` would have performed.
  const iterator = args.blob[Symbol.asyncIterator]();
  const closeSource = async (): Promise<void> => {
    await iterator.return?.();
  };
  const lookahead = new Uint8Array(MIN_PASSPHRASE_BLOB_LENGTH);
  let filled = 0;
  let leftover: Uint8Array | null = null;
  try {
    while (filled < MIN_PASSPHRASE_BLOB_LENGTH) {
      args.signal?.throwIfAborted();
      const step = await iterator.next();
      if (step.done === true) break;
      const raw = step.value;
      if (raw.length === 0) continue;
      const take = Math.min(MIN_PASSPHRASE_BLOB_LENGTH - filled, raw.length);
      lookahead.set(raw.subarray(0, take), filled);
      filled += take;
      if (take < raw.length) leftover = raw.subarray(take);
    }
    args.signal?.throwIfAborted();
  } catch (e) {
    await closeSource();
    throw e;
  }

  // A source ending below the well-formedness floor cannot be a passphrase-path
  // blob; rejecting it from the lookahead spends no Argon2 work on it, exactly
  // as the buffered open's length check does.
  if (filled < MIN_PASSPHRASE_BLOB_LENGTH) {
    await closeSource();
    return passphraseStreamRejected();
  }

  const cek = await argon2Cek(password, envelope.passphrase.salt, envelope.passphrase.params);

  // Constant-time commitment check BEFORE any chunk is opened: the commitment
  // (not merely a Poly1305 tag deep in the stream) is what a correct passphrase
  // must reproduce, and a mismatch never begins streaming.
  const expected = commitmentFor(envelope, cek, hashesHash);
  if (!compareCt(expected, lookahead.subarray(0, COMMITMENT_LENGTH))) {
    await closeSource();
    return passphraseStreamRejected();
  }

  const payloadKey = passphrasePayloadKey({ cek, nonce: envelope.nonce });

  // Replay the lookahead's body bytes (past the commitment header), then any
  // bytes over-read while filling it, then the rest of the source. The
  // `finally` closes the source when this generator finishes or is abandoned
  // mid-body (tamper throw, abort, or a consumer that stops early).
  async function* remainingBlob(): AsyncGenerator<Uint8Array> {
    try {
      yield lookahead.subarray(COMMITMENT_LENGTH);
      if (leftover !== null) yield leftover;
      for (;;) {
        const step = await iterator.next();
        if (step.done === true) return;
        yield step.value;
      }
    } finally {
      await closeSource();
    }
  }

  let resolveOutcome!: (outcome: PassphraseStreamOpenOutcome) => void;
  const outcome = new Promise<PassphraseStreamOpenOutcome>((resolve) => {
    resolveOutcome = resolve;
  });

  async function* drive(): AsyncGenerator<Uint8Array> {
    const opener = new StreamOpener(payloadKey);
    try {
      for await (const { chunk, final } of rechunkSealed(remainingBlob(), args.signal)) {
        yield opener.openChunk(chunk, final);
      }
    } catch (e) {
      if (e instanceof StreamTamperedError) {
        // A per-chunk tag failure or a truncated/over-long stream: the bytes
        // already yielded are quarantine the caller discards. Settle the
        // outcome AND re-throw so a draining consumer cannot mistake it for
        // success. The wrong-key arm of the KEM-slots stream cannot occur
        // here: the commitment already matched.
        resolveOutcome(PASSPHRASE_STREAM_REJECTED);
      }
      throw e;
    }
    resolveOutcome({ matched: true });
  }

  return { outcome, plaintext: drive() };
}
