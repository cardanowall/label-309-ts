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
import { streamOpen, streamSeal, StreamTamperedError, TAG_SIZE } from './stream';
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
// Registry-pinned Argon2id constraints: salt 16..64 bytes; m (KiB) ≥ 65536,
// t ≥ 3, p ≥ 1; each parameter a uint ≤ 2^32 − 1.
const SALT_MIN_LENGTH = 16 as const;
const SALT_MAX_LENGTH = 64 as const;
const ARGON2_M_MIN = 65536 as const;
const ARGON2_T_MIN = 3 as const;
const ARGON2_P_MIN = 1 as const;
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
  if (args.salt.length < SALT_MIN_LENGTH) {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_SALT_TOO_SHORT',
      `passphrase.salt MUST be at least ${SALT_MIN_LENGTH} bytes, got ${args.salt.length}`,
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
    args.params.m < ARGON2_M_MIN ||
    args.params.t < ARGON2_T_MIN ||
    args.params.p < ARGON2_P_MIN
  ) {
    throw new EciesSealedPoeError(
      'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
      `passphrase.params MUST satisfy m >= ${ARGON2_M_MIN}, t >= ${ARGON2_T_MIN}, p >= ${ARGON2_P_MIN}; got m=${args.params.m}, t=${args.params.t}, p=${args.params.p}`,
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
  const salt = args.salt ?? randomBytes(SALT_MIN_LENGTH);
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
  if (blob.length < COMMITMENT_LENGTH + TAG_SIZE) {
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
