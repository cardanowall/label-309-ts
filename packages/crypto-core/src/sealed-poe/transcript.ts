// Shared, byte-critical pieces of the slots-path sealed-PoE construction that
// the producer (wrap) and every verifier (unwrap, trial-decrypt) MUST compute
// byte-for-byte identically:
//
//   1. The slots transcript and its SHA-256 hash `slots_hash`.
//   2. The content-AEAD additional-authenticated-data object `AD_CONTENT_SLOTS`.
//   3. The content `payload_key` derivation from the CEK.
//   4. The hybrid (X-Wing) per-slot KEK salt.
//   5. The single-shot XChaCha20-Poly1305 maximum-payload guard.
//
// Keeping these in one module is the interop guarantee: a single divergence in
// the canonical encoding silently yields a `slots_mac` or AEAD tag that another
// implementation cannot reproduce, with no typed error to localise the fault.
// There is exactly one shared implementation, imported by both sides.

import { sha256 } from '@noble/hashes/sha2.js';

import { encodeCanonicalCbor, type CanonicalCborValue } from '../cbor/canonical';
import { hkdfSha256 } from '../kdf/hkdf';

import { canonicalizeSlots, type SealedKem } from './slots-codec';
import type { Mlkem768X25519Slot, X25519Slot } from './wrap';

// Internal domain-separation labels. Each is exact ASCII with no terminator and
// no length prefix; each is a fixed constant of the scheme, never serialised on
// the wire and never registry-selectable. The byte-length invariants below keep
// the SCREAMING_SNAKE constants in sync with the ASCII literals every conformant
// verifier hashes against.

// SHA-256 prefix for the slots-transcript hash `slots_hash`.
export const CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX: Uint8Array = new TextEncoder().encode(
  'cardano-poe-slots-transcript-v1',
);
// HKDF info for the slots-path content `payload_key`.
export const CARDANO_POE_HKDF_INFO_PAYLOAD: Uint8Array = new TextEncoder().encode(
  'cardano-poe-payload-v1',
);
// HKDF info for the passphrase-path content `payload_key`.
export const CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE: Uint8Array = new TextEncoder().encode(
  'cardano-poe-payload-passphrase-v1',
);
// SHA-256 prefix for the hybrid (X-Wing) per-slot KEK HKDF salt.
export const CARDANO_POE_XWING_KEK_SALT_PREFIX: Uint8Array = new TextEncoder().encode(
  'cardano-poe-xwing-kek-salt-v1',
);

if (CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX.length !== 31) {
  throw new Error(
    'CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX byte-length invariant violated (expected 31)',
  );
}
if (CARDANO_POE_HKDF_INFO_PAYLOAD.length !== 22) {
  throw new Error('CARDANO_POE_HKDF_INFO_PAYLOAD byte-length invariant violated (expected 22)');
}
if (CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE.length !== 33) {
  throw new Error(
    'CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE byte-length invariant violated (expected 33)',
  );
}
if (CARDANO_POE_XWING_KEK_SALT_PREFIX.length !== 29) {
  throw new Error('CARDANO_POE_XWING_KEK_SALT_PREFIX byte-length invariant violated (expected 29)');
}

// Scheme-fixed constant pinning the passphrase normalization profile the CEK was
// derived under. Fed into the passphrase-path AAD; never serialised on the wire.
export const CARDANO_POE_PW_NORM_PROFILE = 'cardano-poe-pw-norm-v1' as const;

// Verifier-side resource bounds a public parser MUST enforce BEFORE invoking any
// KEM/AEAD primitive, so a malformed envelope cannot drive unbounded work. Both
// are deployment-pinned reference constants (not wire fields); deployments MAY
// tighten them. They sit far above the ~16 KiB Cardano transaction-metadata
// ceiling that bounds honest records, so a conformant record never trips them.
//
//   • MAX_SLOTS — the maximum slot count; an envelope with more slots is
//     rejected outright.
//   • MAX_DECODED_ENVELOPE_BYTES — a backstop on the decoded envelope's
//     aggregate byte size (nonce + slots_mac + every per-slot wire field),
//     bounding the work even before the slot-count cap would.
export const MAX_SLOTS = 1024;
export const MAX_DECODED_ENVELOPE_BYTES = 65536;

// XChaCha20-Poly1305 is a single-shot AEAD over the whole plaintext; its 32-bit
// internal block counter bounds one (key, nonce) invocation at 2^32 64-byte
// ChaCha20 blocks, the first of which is consumed by the Poly1305 one-time key.
// MAX_SEALED_PLAINTEXT is therefore (2^32 - 1) * 64 = 2^38 - 64 bytes; a plaintext
// at or above it risks a counter-overflow keystream collision and MUST be
// rejected before the AEAD is invoked on either side. This constant is identical
// across all conformant implementations.
export const MAX_SEALED_PLAINTEXT = 274877906880; // 2^38 - 64
// Poly1305 appends a 16-byte tag, so the corresponding ciphertext bound is + 16.
export const MAX_SEALED_CIPHERTEXT = MAX_SEALED_PLAINTEXT + 16;

if (MAX_SEALED_PLAINTEXT !== 2 ** 38 - 64) {
  throw new Error('MAX_SEALED_PLAINTEXT invariant violated (expected 2^38 - 64)');
}

// Reject a slots-path plaintext at or above the single-shot keystream capacity,
// before any AEAD call. Thrown on the producer side.
export function assertPlaintextWithinBound(plaintextLength: number): void {
  if (plaintextLength >= MAX_SEALED_PLAINTEXT) {
    throw new SealedPayloadTooLargeError(
      `plaintext length ${plaintextLength} is at or above the maximum sealed payload size ${MAX_SEALED_PLAINTEXT}`,
    );
  }
}

// Reject a slots-/passphrase-path ciphertext at or above the single-shot bound,
// before any AEAD open. Thrown on the verifier side. The ciphertext carries the
// plaintext plus a 16-byte Poly1305 tag.
export function assertCiphertextWithinBound(ciphertextLength: number): void {
  if (ciphertextLength >= MAX_SEALED_CIPHERTEXT) {
    throw new SealedPayloadTooLargeError(
      `ciphertext length ${ciphertextLength} is at or above the maximum sealed ciphertext size ${MAX_SEALED_CIPHERTEXT}`,
    );
  }
}

export class SealedPayloadTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SealedPayloadTooLargeError';
  }
}

// SHA-256("cardano-poe-slots-transcript-v1" || canonicalEncode(SLOTS_TRANSCRIPT)).
// SLOTS_TRANSCRIPT is the closed six-key map binding the cross-KEM header fields
// (scheme, path, aead, kem, nonce) to the canonicalised slot set, so a relay
// that flips any header field while leaving slot shapes valid yields a different
// `slots_hash` and the MAC fails. Computed ONCE per envelope and held constant
// across the recipient trial-decrypt loop. The map keys are a SET — their wire
// order is fixed by the canonical-encode sort, never hand-arranged here.
export function computeSlotsHash(args: {
  kem: SealedKem;
  nonce: Uint8Array;
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>;
}): Uint8Array {
  const transcript: CanonicalCborValue = {
    scheme: 1,
    path: 'slots',
    aead: 'xchacha20-poly1305',
    kem: args.kem,
    nonce: args.nonce,
    slots: canonicalizeSlots(args.slots, args.kem),
  };
  const encoded = encodeCanonicalCbor(transcript);
  const message = new Uint8Array(CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX.length + encoded.length);
  message.set(CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX, 0);
  message.set(encoded, CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX.length);
  return sha256(message);
}

// canonicalEncode(AD_CONTENT_SLOTS): the closed seven-key content-AEAD AAD for
// the slots path. It re-binds the slots-path header AND carries both `slots_hash`
// (binding to the exact transcript) and `slots_mac` (tying the content layer to
// the CEK-keyed MAC the recipient matched). Both are deliberate, not redundant.
export function adContentSlots(args: {
  kem: SealedKem;
  nonce: Uint8Array;
  slotsHash: Uint8Array;
  slotsMac: Uint8Array;
}): Uint8Array {
  const ad: CanonicalCborValue = {
    scheme: 1,
    path: 'slots',
    aead: 'xchacha20-poly1305',
    kem: args.kem,
    nonce: args.nonce,
    slots_hash: args.slotsHash,
    slots_mac: args.slotsMac,
  };
  return encodeCanonicalCbor(ad);
}

// canonicalEncode(AD_CONTENT_PASSPHRASE): the closed content-AEAD AAD for the
// passphrase path. It binds the passphrase KDF parameters into the content tag,
// so tampering with `salt` or any `params` value after encryption changes the
// AAD and makes the AEAD open fail. The `normalization` profile id is a
// scheme-fixed constant pinned into the AAD, never serialised on the wire. There
// is NO `kem` key on this path.
export function adContentPassphrase(args: {
  nonce: Uint8Array;
  passphrase: {
    alg: string;
    salt: Uint8Array;
    params: { m: number; t: number; p: number };
  };
}): Uint8Array {
  const ad: CanonicalCborValue = {
    scheme: 1,
    path: 'passphrase',
    aead: 'xchacha20-poly1305',
    nonce: args.nonce,
    passphrase: {
      alg: args.passphrase.alg,
      salt: args.passphrase.salt,
      params: {
        m: args.passphrase.params.m,
        t: args.passphrase.params.t,
        p: args.passphrase.params.p,
      },
      normalization: CARDANO_POE_PW_NORM_PROFILE,
    },
  };
  return encodeCanonicalCbor(ad);
}

// Slots-path content key: HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-v1).
// The content is encrypted under this leaf of the CEK, never under the CEK
// directly, so the wrap layer and the content layer never key the same primitive
// on the same bytes.
export function slotsPayloadKey(args: { cek: Uint8Array; nonce: Uint8Array }): Uint8Array {
  return hkdfSha256({
    ikm: args.cek,
    salt: args.nonce,
    info: CARDANO_POE_HKDF_INFO_PAYLOAD,
    length: 32,
  });
}

// Passphrase-path content key: HKDF-SHA-256(ikm=CEK, salt=nonce,
// info=payload-passphrase-v1).
export function passphrasePayloadKey(args: { cek: Uint8Array; nonce: Uint8Array }): Uint8Array {
  return hkdfSha256({
    ikm: args.cek,
    salt: args.nonce,
    info: CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE,
    length: 32,
  });
}

// Hybrid (mlkem768x25519) per-slot KEK salt:
// SHA-256("cardano-poe-xwing-kek-salt-v1" || kem_ct || pub_R). `kem_ct` is the
// REASSEMBLED 1120-byte X-Wing ciphertext (the kem_ct anchors the KEK to a
// slot-unique value) and `pub_R` the 1216-byte X-Wing recipient public key
// (binding the KEK to the specific recipient) — the same two bindings the
// classical `epk || pub_R` salt provides, expressed through a fixed-length
// SHA-256 digest because the hybrid inputs are oversized.
export function xwingKekSalt(args: { kemCt: Uint8Array; pubR: Uint8Array }): Uint8Array {
  const message = new Uint8Array(
    CARDANO_POE_XWING_KEK_SALT_PREFIX.length + args.kemCt.length + args.pubR.length,
  );
  let offset = 0;
  message.set(CARDANO_POE_XWING_KEK_SALT_PREFIX, offset);
  offset += CARDANO_POE_XWING_KEK_SALT_PREFIX.length;
  message.set(args.kemCt, offset);
  offset += args.kemCt.length;
  message.set(args.pubR, offset);
  return sha256(message);
}
