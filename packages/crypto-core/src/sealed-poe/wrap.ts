// Multi-recipient sealed-PoE wrap (age-style ECIES + AEAD-bound slots).
// Wire-field names are fixed by the standard: scheme, aead, kem, nonce, slots, slots_mac.
//
// Two KEM branches share one envelope shape, discriminated on the envelope-level
// `kem` field:
//
//   • kem: 'x25519'            — classical age-style ECIES. Per-slot epk(32) + wrap(48).
//   • kem: 'mlkem768x25519'    — X-Wing hybrid (ML-KEM-768 + X25519). Per-slot the
//                                1120-byte X-Wing enc carried as a chunked byte-string
//                                array (`kem_ct`) + wrap(48). No per-slot epk.
//
// The slot type is a discriminated union so every consumer is forced — at compile
// time — to branch on the KEM before touching kem-specific fields.

import { randomBytes } from '@noble/ciphers/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { chacha20Poly1305Encrypt } from '../aead/chacha20-poly1305';
import { xchacha20Poly1305Encrypt } from '../aead/xchacha20-poly1305';
import { hkdfSha256 } from '../kdf/hkdf';
import {
  mlkem768x25519Encapsulate,
  MLKEM768X25519_ENC_LENGTH,
  MLKEM768X25519_ESEED_LENGTH,
  MLKEM768X25519_PUBLIC_KEY_LENGTH,
} from '../kem/mlkem768x25519';
import { x25519Ecdh, x25519PublicKey } from '../kem/x25519';

import { EciesSealedPoeError } from './errors';
import { chunkKemCt, type SealedKem } from './slots-codec';
import {
  adContentSlots,
  assertPlaintextWithinBound,
  computeSlotsHash,
  slotsPayloadKey,
  xwingKekSalt,
} from './transcript';

// HKDF info strings — fixed protocol labels for KEK derivation and the slot MAC.
// Byte-length invariants enforce that the SCREAMING_SNAKE constants stay in sync
// with the on-wire ASCII literals every conformant verifier hashes against.
export const CARDANO_POE_HKDF_INFO_KEK: Uint8Array = new TextEncoder().encode('cardano-poe-kek-v1');
// Hybrid (X-Wing) per-slot KEK label. Distinct from the classical label so a
// KEK derived under one KEM can never collide with the other. Reused verbatim as
// the per-slot wrap AEAD AAD, exactly as the classical path reuses its own label.
export const CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519: Uint8Array = new TextEncoder().encode(
  'cardano-poe-kek-mlkem768x25519-v1',
);
export const CARDANO_POE_HKDF_INFO_SLOTS_MAC: Uint8Array = new TextEncoder().encode(
  'cardano-poe-slots-mac-v1',
);

const ZERO_NONCE_12: Uint8Array = new Uint8Array(12);
const EMPTY_SALT: Uint8Array = new Uint8Array(0);
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
if (CARDANO_POE_HKDF_INFO_SLOTS_MAC.length !== 24) {
  throw new Error('CARDANO_POE_HKDF_INFO_SLOTS_MAC byte-length invariant violated (expected 24)');
}
if (ZERO_NONCE_12.length !== 12) {
  throw new Error('ZERO_NONCE_12 byte-length invariant violated (expected 12)');
}

// Classical per-slot wire shape: { epk: bstr(32), wrap: bstr(48) }.
export interface X25519Slot {
  readonly epk: Uint8Array;
  readonly wrap: Uint8Array;
}

// Hybrid per-slot wire shape: { kem_ct: [ bstr .size (1..64) ], wrap: bstr(48) }.
// `kem_ct` is the 1120-byte X-Wing enc carried as a chunked byte-string array
// (the Cardano ledger caps any single metadatum bstr at 64 bytes). There is NO
// per-slot epk and NO per-slot kem field — the KEM identifier is hoisted to
// envelope scope (every slot shares it).
export interface Mlkem768X25519Slot {
  readonly kem_ct: ReadonlyArray<Uint8Array>;
  readonly wrap: Uint8Array;
}

// Back-compat alias retired: callers branch on the envelope `kem` and use the
// concrete slot type. The discriminated `SealedEnvelope` below is the only
// shape consumers should depend on.

// Sealed envelope wire shape (discriminated on `kem`).
export type SealedEnvelope =
  | {
      readonly scheme: 1;
      readonly aead: 'xchacha20-poly1305';
      readonly kem: 'x25519';
      readonly nonce: Uint8Array;
      readonly slots: ReadonlyArray<X25519Slot>;
      readonly slots_mac: Uint8Array;
    }
  | {
      readonly scheme: 1;
      readonly aead: 'xchacha20-poly1305';
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

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
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

// Wrap the CEK for one classical recipient: age-style ECIES stanza.
function wrapSlotX25519(args: {
  pubR: Uint8Array;
  privEph: Uint8Array | undefined;
  cek: Uint8Array;
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
  // age v1 stanza salt is `epk || pub_R`.
  const kek = hkdfSha256({
    ikm: shared,
    salt: concat(epk, args.pubR),
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
}): Mlkem768X25519Slot {
  const { enc, ss } = mlkem768x25519Encapsulate({
    publicKey: args.pubR,
    ...(args.eseed !== undefined ? { eseed: args.eseed } : {}),
  });
  if (enc.length !== MLKEM768X25519_ENC_LENGTH) {
    throw new Error(`internal: enc.length=${enc.length}, expected ${MLKEM768X25519_ENC_LENGTH}`);
  }
  // The hybrid KEK salt binds the slot's own reassembled X-Wing ciphertext and
  // the recipient public key, mirroring the classical `epk || pub_R` salt: the
  // ciphertext anchors the KEK to a slot-unique value and `pub_R` binds it to
  // the specific recipient. It is computed outside the KEM, over the slot's wire
  // bytes, so it holds X-Wing as a black-box KEM.
  const kek = hkdfSha256({
    ikm: ss,
    salt: xwingKekSalt({ kemCt: enc, pubR: args.pubR }),
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
  return { kem_ct: chunkKemCt(enc), wrap };
}

export function eciesSealedPoeWrap(args: WrapArgs): SealedPoeOutput {
  const { plaintext, recipientPublicKeys } = args;
  const kem: SealedKem = args.kem ?? 'x25519';
  const n = recipientPublicKeys.length;

  // Reject a plaintext at or above the single-shot keystream capacity before any
  // KEM or AEAD work, so an over-large input never reaches the content cipher.
  assertPlaintextWithinBound(plaintext.length);

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
  // `slots_hash` is the SHA-256 of the header-bound slots transcript. It is
  // computed once here, fed into both the slot-set MAC and the content AAD.
  let slotsHash: Uint8Array;
  if (kem === 'x25519') {
    const slots: X25519Slot[] = [];
    for (let i = 0; i < n; i++) {
      slots.push(
        wrapSlotX25519({
          pubR: recipientPublicKeys[i]!,
          privEph: args.ephemeralSecrets ? (args.ephemeralSecrets[i] as Uint8Array) : undefined,
          cek,
          slotIdx: i,
        }),
      );
    }
    // Anonymity invariant (see csprngShuffle comment). The transcript is built
    // AFTER the shuffle so the MAC binds the on-wire slot order.
    if (args.skipShuffle !== true) {
      csprngShuffle(slots);
    }
    slotsHash = computeSlotsHash({ kem: 'x25519', nonce, slots });
    envelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'x25519',
      nonce,
      slots,
      slots_mac: computeSlotsMac(cek, slotsHash),
    };
  } else {
    const slots: Mlkem768X25519Slot[] = [];
    for (let i = 0; i < n; i++) {
      slots.push(
        wrapSlotMlkem768X25519({
          pubR: recipientPublicKeys[i]!,
          eseed: args.eseeds ? (args.eseeds[i] as Uint8Array) : undefined,
          cek,
        }),
      );
    }
    if (args.skipShuffle !== true) {
      csprngShuffle(slots);
    }
    slotsHash = computeSlotsHash({ kem: 'mlkem768x25519', nonce, slots });
    envelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'mlkem768x25519',
      nonce,
      slots,
      slots_mac: computeSlotsMac(cek, slotsHash),
    };
  }

  // Content is encrypted under a derived `payload_key` (a separate HKDF leaf of
  // the CEK keyed on the nonce), never under the CEK directly, so the wrap layer
  // and the content layer never key the same primitive on the same bytes. The
  // AAD re-binds the slots-path header and carries both `slots_hash` and
  // `slots_mac`.
  const payloadKey = slotsPayloadKey({ cek, nonce });
  const adContent = adContentSlots({
    kem: envelope.kem,
    nonce,
    slotsHash,
    slotsMac: envelope.slots_mac,
  });
  const ciphertext = xchacha20Poly1305Encrypt({
    key: payloadKey,
    nonce,
    aad: adContent,
    plaintext,
  });

  return { envelope, ciphertext };
}

// Slot-set MAC binds the slots transcript to the CEK. The transcript is pre-
// hashed to a 32-byte `slots_hash` (header fields + canonicalised slot set,
// including the entire chunked kem_ct on the hybrid path), and that hash is the
// message of a CEK-keyed HMAC. Pre-hashing only changes the HMAC message from
// the full transcript to its SHA-256, leaving the CEK-keyed commitment intact.
function computeSlotsMac(cek: Uint8Array, slotsHash: Uint8Array): Uint8Array {
  const hmacKey = hkdfSha256({
    ikm: cek,
    salt: EMPTY_SALT,
    info: CARDANO_POE_HKDF_INFO_SLOTS_MAC,
    length: 32,
  });
  const slotsMac = hmac(sha256, hmacKey, slotsHash);
  if (slotsMac.length !== SLOTS_MAC_LENGTH) {
    throw new Error(`internal: slots_mac.length=${slotsMac.length}, expected ${SLOTS_MAC_LENGTH}`);
  }
  return slotsMac;
}
