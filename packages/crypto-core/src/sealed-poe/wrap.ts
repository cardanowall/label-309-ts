// Multi-recipient sealed-PoE wrap (age-style KEM-then-wrap slots + segmented
// STREAM content). Wire-field names are fixed by the standard: scheme, aead,
// kem, nonce, slots, slots_mac.
//
// Two KEM branches share one envelope shape, discriminated on the envelope-level
// `kem` field:
//
//   • kem: 'x25519'            — classical age-style ECIES. Per-slot epk(32) + wrap(48).
//   • kem: 'mlkem768x25519'    — X-Wing hybrid (ML-KEM-768 + X25519). Per-slot the
//                                1120-byte X-Wing ciphertext as a single byte
//                                string (`kem_ct`) + wrap(48). No per-slot epk.
//
// The slot type is a discriminated union so every consumer is forced — at compile
// time — to branch on the KEM before touching kem-specific fields.

import { randomBytes } from '@noble/ciphers/utils.js';

import { chacha20Poly1305Encrypt } from '../aead/chacha20-poly1305';
import {
  mlkem768x25519Encapsulate,
  MLKEM768X25519_ENC_LENGTH,
  MLKEM768X25519_ESEED_LENGTH,
  MLKEM768X25519_PUBLIC_KEY_LENGTH,
} from '../kem/mlkem768x25519';
import { x25519Ecdh, x25519PublicKey } from '../kem/x25519';
import { hkdfSha256 } from '../kdf/hkdf';

import { EciesSealedPoeError } from './errors';
import { streamSeal } from './stream';
import {
  computeSlotsHash,
  computeSlotsMac,
  itemHashesHash,
  slotsPayloadKey,
  x25519KekSalt,
  xwingKekSalt,
  type ItemHashes,
} from './transcript';

// The envelope-level KEM discriminator.
export type SealedKem = 'x25519' | 'mlkem768x25519';

// The sole registered content format under enc.scheme 1: ChaCha20-Poly1305 in
// the 64 KiB segmented STREAM layout. Producers MUST emit this identifier
// byte-exact.
export const SEALED_POE_AEAD = 'chacha20-poly1305-stream64k' as const;

// HKDF info strings — fixed protocol labels for KEK derivation. Each doubles as
// the per-slot wrap AEAD AAD (never empty AAD). Byte-length invariants enforce
// that the SCREAMING_SNAKE constants stay in sync with the ASCII literals every
// conformant verifier hashes against.
export const CARDANO_POE_HKDF_INFO_KEK: Uint8Array = new TextEncoder().encode('cardano-poe-kek-v1');
// Hybrid (X-Wing) per-slot KEK label. Distinct from the classical label so a
// KEK derived under one KEM can never collide with the other.
export const CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519: Uint8Array = new TextEncoder().encode(
  'cardano-poe-kek-mlkem768x25519-v1',
);

const ZERO_NONCE_12: Uint8Array = new Uint8Array(12);
const X25519_PUBLIC_KEY_LENGTH = 32 as const;
const X25519_SECRET_KEY_LENGTH = 32 as const;
const CEK_LENGTH = 32 as const;
const NONCE_LENGTH = 24 as const;
const WRAP_LENGTH = 48 as const;
const SLOTS_MAC_LENGTH = 32 as const;

if (CARDANO_POE_HKDF_INFO_KEK.length !== 18) {
  throw new Error('CARDANO_POE_HKDF_INFO_KEK byte-length invariant violated (expected 18)');
}
if (CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519.length !== 33) {
  throw new Error(
    'CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519 byte-length invariant violated (expected 33)',
  );
}
if (ZERO_NONCE_12.length !== 12) {
  throw new Error('ZERO_NONCE_12 byte-length invariant violated (expected 12)');
}

// Classical per-slot wire shape: { epk: bstr(32), wrap: bstr(48) }.
export interface X25519Slot {
  readonly epk: Uint8Array;
  readonly wrap: Uint8Array;
}

// Hybrid per-slot wire shape: { kem_ct: bstr(1120), wrap: bstr(48) }. `kem_ct`
// is the X-Wing ciphertext as a single byte string. There is NO per-slot epk
// (the X25519 ephemeral is the trailing 32 bytes of kem_ct) and NO per-slot kem
// field — the KEM identifier is hoisted to envelope scope (every slot shares it).
export interface Mlkem768X25519Slot {
  readonly kem_ct: Uint8Array;
  readonly wrap: Uint8Array;
}

// Sealed envelope wire shape (discriminated on `kem`).
export type SealedEnvelope =
  | {
      readonly scheme: 1;
      readonly aead: typeof SEALED_POE_AEAD;
      readonly kem: 'x25519';
      readonly nonce: Uint8Array;
      readonly slots: ReadonlyArray<X25519Slot>;
      readonly slots_mac: Uint8Array;
    }
  | {
      readonly scheme: 1;
      readonly aead: typeof SEALED_POE_AEAD;
      readonly kem: 'mlkem768x25519';
      readonly nonce: Uint8Array;
      readonly slots: ReadonlyArray<Mlkem768X25519Slot>;
      readonly slots_mac: Uint8Array;
    };

export interface SealedPoeOutput {
  readonly envelope: SealedEnvelope;
  readonly ciphertext: Uint8Array;
}

export interface WrapArgs {
  readonly plaintext: Uint8Array;
  // The item's plaintext-hash claim (registered algorithm id → digest bytes).
  // Its labelled digest is bound into the slots transcript, so the on-chain
  // slots_mac match also confirms the envelope belongs to this hash claim.
  readonly hashes: ItemHashes;
  readonly recipientPublicKeys: ReadonlyArray<Uint8Array>;
  // KEM branch selector. Defaults to 'x25519' for the classical path. The
  // recipient public-key length is validated against the chosen KEM.
  readonly kem?: SealedKem;
  readonly cek?: Uint8Array;
  readonly nonce?: Uint8Array;
  // Deterministic X25519 ephemeral scalars — x25519 branch only.
  readonly ephemeralSecrets?: ReadonlyArray<Uint8Array>;
  // Deterministic X-Wing encapsulation randomness (64 bytes each) — hybrid
  // branch only. One per recipient, parallel to recipientPublicKeys.
  readonly eseeds?: ReadonlyArray<Uint8Array>;
  readonly skipShuffle?: boolean;
}

// Anonymity invariant: wire ordering MUST NOT encode "primary
// recipient first". A CSPRNG-keyed Fisher-Yates shuffle uniformly permutes the
// slot array so trial-decrypt order leaks no recipient identity. The
// slot-set HMAC is computed AFTER this shuffle, binding the on-wire order.
//
// Draw an unbiased index in [0, m) from a CSPRNG uint32 via rejection sampling.
// A plain `u32 % m` skews toward the low residues whenever `m` does not divide
// 2^32 evenly: the values [0, 2^32 mod m) each occur one extra time. This
// function exists purely to produce a UNIFORM permutation, so the bias — though
// cryptographically negligible — is exactly the property we cannot tolerate.
// We reject any draw landing in the final partial block [limit, 2^32) and
// redraw, leaving only the residues that map uniformly onto [0, m).
// Exported so the rejection-bound arithmetic can be asserted directly in tests
// without relying on a flaky statistical-distribution check.
export function uniformIndexBelow(m: number): number {
  // 2^32 mod m, computed without overflowing the 32-bit space.
  const limit = 0x1_0000_0000 - (0x1_0000_0000 % m);
  const buf = new Uint32Array(1);
  let x: number;
  do {
    crypto.getRandomValues(buf);
    x = buf[0] as number;
  } while (x >= limit);
  return x % m;
}

function csprngShuffle<T>(arr: T[]): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = uniformIndexBelow(i + 1);
    const tmp = arr[i] as T;
    arr[i] = arr[j] as T;
    arr[j] = tmp;
  }
}

// Wrap the CEK for one classical recipient: age-style ECIES stanza with the
// labelled-hash KEK salt binding nonce, epk, and pub_R.
function wrapSlotX25519(args: {
  pubR: Uint8Array;
  privEph: Uint8Array | undefined;
  cek: Uint8Array;
  nonce: Uint8Array;
  slotIdx: number;
}): X25519Slot {
  const privEph = args.privEph ?? randomBytes(X25519_SECRET_KEY_LENGTH);
  if (privEph.length !== X25519_SECRET_KEY_LENGTH) {
    throw new EciesSealedPoeError(
      'INVALID_EPHEMERAL_SECRET_LENGTH',
      `ephemeralSecrets[${args.slotIdx}] MUST be exactly ${X25519_SECRET_KEY_LENGTH} bytes, got ${privEph.length}`,
    );
  }
  const epk = x25519PublicKey({ secretKey: privEph });
  const shared = x25519Ecdh({ secretKey: privEph, theirPublicKey: args.pubR });
  const kek = hkdfSha256({
    ikm: shared,
    salt: x25519KekSalt({ nonce: args.nonce, epk, pubR: args.pubR }),
    info: CARDANO_POE_HKDF_INFO_KEK,
    length: 32,
  });
  // Per-slot wrap AAD MUST be the 18-byte ASCII literal of the KEK info
  // string (never empty AAD).
  const wrap = chacha20Poly1305Encrypt({
    key: kek,
    nonce: ZERO_NONCE_12,
    aad: CARDANO_POE_HKDF_INFO_KEK,
    plaintext: args.cek,
  });
  if (wrap.length !== WRAP_LENGTH) {
    throw new Error(`internal: wrap.length=${wrap.length}, expected ${WRAP_LENGTH}`);
  }
  return { epk, wrap };
}

// Wrap the CEK for one hybrid recipient: X-Wing encapsulation → HKDF → AEAD.
// The KEK info label doubles as the wrap AEAD AAD, mirroring the classical path.
function wrapSlotMlkem768X25519(args: {
  pubR: Uint8Array;
  eseed: Uint8Array | undefined;
  cek: Uint8Array;
  nonce: Uint8Array;
}): Mlkem768X25519Slot {
  const { enc, ss } = mlkem768x25519Encapsulate({
    publicKey: args.pubR,
    ...(args.eseed !== undefined ? { eseed: args.eseed } : {}),
  });
  if (enc.length !== MLKEM768X25519_ENC_LENGTH) {
    throw new Error(`internal: enc.length=${enc.length}, expected ${MLKEM768X25519_ENC_LENGTH}`);
  }
  // The hybrid KEK salt binds the envelope nonce, the slot's own X-Wing
  // ciphertext, and the recipient public key, mirroring the classical salt: the
  // ciphertext anchors the KEK to a slot-unique value and `pub_R` binds it to
  // the specific recipient. It is computed outside the KEM, over the slot's wire
  // bytes, so it holds X-Wing as a black-box KEM.
  const kek = hkdfSha256({
    ikm: ss,
    salt: xwingKekSalt({ nonce: args.nonce, kemCt: enc, pubR: args.pubR }),
    info: CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
    length: 32,
  });
  const wrap = chacha20Poly1305Encrypt({
    key: kek,
    nonce: ZERO_NONCE_12,
    aad: CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
    plaintext: args.cek,
  });
  if (wrap.length !== WRAP_LENGTH) {
    throw new Error(`internal: wrap.length=${wrap.length}, expected ${WRAP_LENGTH}`);
  }
  return { kem_ct: enc, wrap };
}

// The envelope half of the wrap, factored out so the streaming sealer can reuse
// it verbatim. It performs all input validation, derives the CEK+nonce, builds
// (and shuffles) the slots, and computes slots_mac — everything EXCEPT sealing
// the body. It returns the finished envelope plus the derived `payloadKey`, so a
// caller can stream the content under the same key the buffered `streamSeal`
// would use. The envelope depends only on CEK, nonce, recipients, and hashes —
// never on the plaintext — so it is fully resolved before a single content byte
// is read.
export interface SealedEnvelopeBuild {
  readonly envelope: SealedEnvelope;
  readonly payloadKey: Uint8Array;
}

// Input to `buildSealedEnvelope`: the wrap args minus `plaintext` (the body is
// the streaming/buffered caller's concern, not the envelope's).
export type EnvelopeArgs = Omit<WrapArgs, 'plaintext'>;

export function buildSealedEnvelope(args: EnvelopeArgs): SealedEnvelopeBuild {
  const { recipientPublicKeys } = args;
  const kem: SealedKem = args.kem ?? 'x25519';
  const n = recipientPublicKeys.length;

  // The hash-claim digest is computed before any KEM/AEAD work: an item without
  // a content hash cannot be sealed (the ciphertext is bound to the plaintext
  // only through that digest).
  const hashesHash = itemHashesHash(args.hashes);

  // There is no fixed upper bound on slot count; the producer SDK polices the
  // per-record byte budget. Only the lower bound is enforced here.
  if (n < 1) {
    throw new EciesSealedPoeError(
      'ENC_SLOTS_EMPTY',
      `recipientPublicKeys.length=${n} must be >= 1`,
    );
  }

  const expectedPubLen =
    kem === 'x25519' ? X25519_PUBLIC_KEY_LENGTH : MLKEM768X25519_PUBLIC_KEY_LENGTH;
  for (let i = 0; i < n; i++) {
    const pub = recipientPublicKeys[i];
    if (pub === undefined || pub.length !== expectedPubLen) {
      throw new EciesSealedPoeError(
        'KEM_EPK_LENGTH_MISMATCH',
        `recipientPublicKeys[${i}] MUST be exactly ${expectedPubLen} bytes for kem='${kem}'`,
      );
    }
  }

  if (kem === 'x25519') {
    if (args.eseeds !== undefined) {
      throw new EciesSealedPoeError(
        'EPHEMERAL_SECRETS_COUNT_MISMATCH',
        "eseeds is an X-Wing (mlkem768x25519) override and MUST NOT be supplied for kem='x25519'",
      );
    }
    if (args.ephemeralSecrets !== undefined && args.ephemeralSecrets.length !== n) {
      throw new EciesSealedPoeError(
        'EPHEMERAL_SECRETS_COUNT_MISMATCH',
        `ephemeralSecrets.length=${args.ephemeralSecrets.length} must match recipientPublicKeys.length=${n}`,
      );
    }
  } else {
    if (args.ephemeralSecrets !== undefined) {
      throw new EciesSealedPoeError(
        'EPHEMERAL_SECRETS_COUNT_MISMATCH',
        "ephemeralSecrets is an X25519 override and MUST NOT be supplied for kem='mlkem768x25519'",
      );
    }
    if (args.eseeds !== undefined) {
      if (args.eseeds.length !== n) {
        throw new EciesSealedPoeError(
          'EPHEMERAL_SECRETS_COUNT_MISMATCH',
          `eseeds.length=${args.eseeds.length} must match recipientPublicKeys.length=${n}`,
        );
      }
      for (let i = 0; i < n; i++) {
        const eseed = args.eseeds[i]!;
        if (eseed.length !== MLKEM768X25519_ESEED_LENGTH) {
          throw new EciesSealedPoeError(
            'INVALID_EPHEMERAL_SECRET_LENGTH',
            `eseeds[${i}] MUST be exactly ${MLKEM768X25519_ESEED_LENGTH} bytes, got ${eseed.length}`,
          );
        }
      }
    }
  }

  const cek = args.cek ?? randomBytes(CEK_LENGTH);
  const nonce = args.nonce ?? randomBytes(NONCE_LENGTH);
  if (cek.length !== CEK_LENGTH) {
    throw new EciesSealedPoeError(
      'INVALID_CEK_LENGTH',
      `cek MUST be exactly ${CEK_LENGTH} bytes, got ${cek.length}`,
    );
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new EciesSealedPoeError(
      'NONCE_LENGTH_MISMATCH',
      `nonce MUST be exactly ${NONCE_LENGTH} bytes, got ${nonce.length}`,
    );
  }

  let envelope: SealedEnvelope;
  if (kem === 'x25519') {
    const slots: X25519Slot[] = [];
    for (let i = 0; i < n; i++) {
      slots.push(
        wrapSlotX25519({
          pubR: recipientPublicKeys[i]!,
          privEph: args.ephemeralSecrets ? (args.ephemeralSecrets[i] as Uint8Array) : undefined,
          cek,
          nonce,
          slotIdx: i,
        }),
      );
    }
    // Anonymity invariant (see csprngShuffle comment). The transcript is built
    // AFTER the shuffle so the MAC binds the on-wire slot order.
    if (args.skipShuffle !== true) {
      csprngShuffle(slots);
    }
    const slotsHash = computeSlotsHash({
      aead: SEALED_POE_AEAD,
      kem: 'x25519',
      nonce,
      slots,
      hashesHash,
    });
    envelope = {
      scheme: 1,
      aead: SEALED_POE_AEAD,
      kem: 'x25519',
      nonce,
      slots,
      slots_mac: sizedSlotsMac(cek, slotsHash),
    };
  } else {
    const slots: Mlkem768X25519Slot[] = [];
    for (let i = 0; i < n; i++) {
      slots.push(
        wrapSlotMlkem768X25519({
          pubR: recipientPublicKeys[i]!,
          eseed: args.eseeds ? (args.eseeds[i] as Uint8Array) : undefined,
          cek,
          nonce,
        }),
      );
    }
    if (args.skipShuffle !== true) {
      csprngShuffle(slots);
    }
    const slotsHash = computeSlotsHash({
      aead: SEALED_POE_AEAD,
      kem: 'mlkem768x25519',
      nonce,
      slots,
      hashesHash,
    });
    envelope = {
      scheme: 1,
      aead: SEALED_POE_AEAD,
      kem: 'mlkem768x25519',
      nonce,
      slots,
      slots_mac: sizedSlotsMac(cek, slotsHash),
    };
  }

  // Content is encrypted under a derived `payload_key` (a separate HKDF leaf of
  // the CEK salted by the envelope-unique nonce), never under the CEK directly,
  // in the segmented STREAM format. There is no content AAD: the content binds
  // to the header transitively — payload_key derives from the CEK, and the CEK
  // is committed to the full header (including hashes_hash) by slots_mac. The
  // key is derived here (not in the caller) so the buffered and streaming seal
  // paths share one derivation.
  return { envelope, payloadKey: slotsPayloadKey({ cek, nonce }) };
}

export function eciesSealedPoeWrap(args: WrapArgs): SealedPoeOutput {
  const { envelope, payloadKey } = buildSealedEnvelope(args);
  const ciphertext = streamSeal({ payloadKey, plaintext: args.plaintext });
  return { envelope, ciphertext };
}

function sizedSlotsMac(cek: Uint8Array, slotsHash: Uint8Array): Uint8Array {
  const slotsMac = computeSlotsMac({ cek, slotsHash });
  if (slotsMac.length !== SLOTS_MAC_LENGTH) {
    throw new Error(`internal: slots_mac.length=${slotsMac.length}, expected ${SLOTS_MAC_LENGTH}`);
  }
  return slotsMac;
}
