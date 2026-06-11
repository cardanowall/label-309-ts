// Shared, byte-critical pieces of the sealed-PoE construction that the producer
// (wrap / passphrase seal) and every verifier (unwrap, trial-decrypt,
// passphrase open) MUST compute byte-for-byte identically:
//
//   1. The item-hashes digest `hashes_hash`.
//   2. The slots transcript, its SHA-256 `slots_hash`, and the CEK-keyed
//      `slots_mac`.
//   3. The passphrase transcript, its SHA-256 `pw_hash`, and the CEK-keyed
//      in-ciphertext `commitment`.
//   4. The content `payload_key` derivations (both key paths).
//   5. Both per-slot KEK HKDF salts (classical and hybrid).
//
// Keeping these in one module is the interop guarantee: a single divergence in
// the canonical encoding silently yields a `slots_mac`, a commitment, or an
// AEAD tag that another implementation cannot reproduce, with no typed error to
// localise the fault. There is exactly one shared implementation, imported by
// both sides.

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { encodeCanonicalCbor, type CanonicalCborValue } from '../cbor/canonical';
import { hkdfSha256 } from '../kdf/hkdf';

import { EciesSealedPoeError } from './errors';
import type { Mlkem768X25519Slot, SealedKem, X25519Slot } from './wrap';

// Internal domain-separation labels. Each is exact ASCII with no terminator and
// no length prefix; each is a fixed constant of the scheme, never serialised on
// the wire and never registry-selectable. The byte-length invariants below keep
// the SCREAMING_SNAKE constants in sync with the ASCII literals every conformant
// verifier hashes against.

// SHA-256 prefix for the item-hashes digest `hashes_hash`.
export const CARDANO_POE_ITEM_HASHES_PREFIX: Uint8Array = new TextEncoder().encode(
  'cardano-poe-item-hashes-v1',
);
// SHA-256 prefix for the slots-transcript hash `slots_hash`.
export const CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX: Uint8Array = new TextEncoder().encode(
  'cardano-poe-slots-transcript-v1',
);
// SHA-256 prefix for the passphrase-transcript hash `pw_hash`.
export const CARDANO_POE_PASSPHRASE_TRANSCRIPT_PREFIX: Uint8Array = new TextEncoder().encode(
  'cardano-poe-passphrase-transcript-v1',
);
// HKDF info for the slot-set MAC key.
export const CARDANO_POE_HKDF_INFO_SLOTS_MAC: Uint8Array = new TextEncoder().encode(
  'cardano-poe-slots-mac-v1',
);
// HKDF info for the passphrase commitment MAC key.
export const CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC: Uint8Array = new TextEncoder().encode(
  'cardano-poe-passphrase-mac-v1',
);
// HKDF info for the slots-path content `payload_key`.
export const CARDANO_POE_HKDF_INFO_PAYLOAD: Uint8Array = new TextEncoder().encode(
  'cardano-poe-payload-v1',
);
// HKDF info for the passphrase-path content `payload_key`.
export const CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE: Uint8Array = new TextEncoder().encode(
  'cardano-poe-payload-passphrase-v1',
);
// SHA-256 prefix for the classical (x25519) per-slot KEK HKDF salt.
export const CARDANO_POE_X25519_KEK_SALT_PREFIX: Uint8Array = new TextEncoder().encode(
  'cardano-poe-x25519-kek-salt-v1',
);
// SHA-256 prefix for the hybrid (X-Wing) per-slot KEK HKDF salt.
export const CARDANO_POE_XWING_KEK_SALT_PREFIX: Uint8Array = new TextEncoder().encode(
  'cardano-poe-xwing-kek-salt-v1',
);

if (CARDANO_POE_ITEM_HASHES_PREFIX.length !== 26) {
  throw new Error('CARDANO_POE_ITEM_HASHES_PREFIX byte-length invariant violated (expected 26)');
}
if (CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX.length !== 31) {
  throw new Error(
    'CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX byte-length invariant violated (expected 31)',
  );
}
if (CARDANO_POE_PASSPHRASE_TRANSCRIPT_PREFIX.length !== 36) {
  throw new Error(
    'CARDANO_POE_PASSPHRASE_TRANSCRIPT_PREFIX byte-length invariant violated (expected 36)',
  );
}
if (CARDANO_POE_HKDF_INFO_SLOTS_MAC.length !== 24) {
  throw new Error('CARDANO_POE_HKDF_INFO_SLOTS_MAC byte-length invariant violated (expected 24)');
}
if (CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC.length !== 29) {
  throw new Error(
    'CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC byte-length invariant violated (expected 29)',
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
if (CARDANO_POE_X25519_KEK_SALT_PREFIX.length !== 30) {
  throw new Error(
    'CARDANO_POE_X25519_KEK_SALT_PREFIX byte-length invariant violated (expected 30)',
  );
}
if (CARDANO_POE_XWING_KEK_SALT_PREFIX.length !== 29) {
  throw new Error('CARDANO_POE_XWING_KEK_SALT_PREFIX byte-length invariant violated (expected 29)');
}

// Scheme-fixed constant pinning the passphrase normalization profile the CEK was
// derived under. Fed into the passphrase transcript; never serialised on the
// wire.
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

const EMPTY_SALT: Uint8Array = new Uint8Array(0);

// The item's plaintext-hash claim: registered algorithm identifier → digest
// bytes, exactly as carried in the record body. Both key paths bind this map
// (via `hashes_hash`) into their commitment, so an envelope spliced onto an
// item with a different hash claim is rejected before any ciphertext work.
export type ItemHashes = Readonly<Record<string, Uint8Array>>;

function labelledSha256(prefix: Uint8Array, ...parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = prefix.length;
  for (const p of parts) total += p.length;
  const message = new Uint8Array(total);
  message.set(prefix, 0);
  let offset = prefix.length;
  for (const p of parts) {
    message.set(p, offset);
    offset += p.length;
  }
  return sha256(message);
}

// SHA-256("cardano-poe-item-hashes-v1" || canonicalEncode(item.hashes)).
// The hashes map is encoded exactly as it appears in the record body
// (registry-identifier keys → digest byte strings, canonical key order). An
// `enc`-bearing item MUST declare at least one content hash — the ciphertext is
// bound to the plaintext only through that digest — so an empty map is rejected
// here, on both the producer and the verifier side.
export function itemHashesHash(hashes: ItemHashes): Uint8Array {
  if (Object.keys(hashes).length === 0) {
    throw new EciesSealedPoeError(
      'ENC_REQUIRES_CONTENT_HASH',
      'hashes MUST carry at least one content-hash entry',
    );
  }
  return labelledSha256(CARDANO_POE_ITEM_HASHES_PREFIX, encodeCanonicalCbor(hashes));
}

// SHA-256("cardano-poe-slots-transcript-v1" || canonicalEncode(SLOTS_TRANSCRIPT)).
// SLOTS_TRANSCRIPT is the closed seven-key map binding the cross-KEM header
// fields (scheme, path, aead, kem, nonce) and the item's hash claim
// (hashes_hash) to the on-wire slot set, so a relay that flips any header field
// — or splices the envelope onto a different item — yields a different
// `slots_hash` and the MAC fails. Computed ONCE per envelope and held constant
// across the recipient trial-decrypt loop. The map keys are a SET — their wire
// order is fixed by the canonical-encode sort, never hand-arranged here.
export function computeSlotsHash(args: {
  aead: string;
  kem: SealedKem;
  nonce: Uint8Array;
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>;
  hashesHash: Uint8Array;
}): Uint8Array {
  // The slot array is re-stated as explicit closed two-key maps (never the raw
  // caller objects), so an extra property on a caller's slot value can never
  // leak into the committed bytes.
  const slots: CanonicalCborValue =
    args.kem === 'x25519'
      ? (args.slots as ReadonlyArray<X25519Slot>).map((s) => ({ epk: s.epk, wrap: s.wrap }))
      : (args.slots as ReadonlyArray<Mlkem768X25519Slot>).map((s) => ({
          kem_ct: s.kem_ct,
          wrap: s.wrap,
        }));
  const transcript: CanonicalCborValue = {
    scheme: 1,
    path: 'slots',
    aead: args.aead,
    kem: args.kem,
    nonce: args.nonce,
    slots,
    hashes_hash: args.hashesHash,
  };
  return labelledSha256(CARDANO_POE_SLOTS_TRANSCRIPT_PREFIX, encodeCanonicalCbor(transcript));
}

// SHA-256("cardano-poe-passphrase-transcript-v1" || canonicalEncode(PASSPHRASE_TRANSCRIPT)).
// PASSPHRASE_TRANSCRIPT is the closed six-key map (with `passphrase` itself a
// closed sub-map) binding the header fields, the Argon2id parameters, the
// normalization profile, and the item's hash claim into the in-ciphertext
// commitment. There is NO `kem` key on this path. The `normalization` value is
// the scheme-fixed profile constant, pinned into the transcript and never
// serialised on the wire.
export function computePassphraseHash(args: {
  aead: string;
  nonce: Uint8Array;
  hashesHash: Uint8Array;
  salt: Uint8Array;
  params: { m: number; t: number; p: number };
}): Uint8Array {
  const transcript: CanonicalCborValue = {
    scheme: 1,
    path: 'passphrase',
    aead: args.aead,
    nonce: args.nonce,
    hashes_hash: args.hashesHash,
    passphrase: {
      alg: 'argon2id',
      salt: args.salt,
      params: { m: args.params.m, t: args.params.t, p: args.params.p },
      normalization: CARDANO_POE_PW_NORM_PROFILE,
    },
  };
  return labelledSha256(CARDANO_POE_PASSPHRASE_TRANSCRIPT_PREFIX, encodeCanonicalCbor(transcript));
}

// Slot-set MAC: HMAC-SHA-256 keyed by an HKDF leaf of the CEK over the 32-byte
// `slots_hash`. Pre-hashing the transcript only changes the HMAC message from
// the full transcript to its SHA-256, leaving the CEK-keyed commitment intact.
// The fixed 32-byte HKDF key structurally excludes the HMAC over-block-length
// key ambiguity.
export function computeSlotsMac(args: { cek: Uint8Array; slotsHash: Uint8Array }): Uint8Array {
  const macKey = hkdfSha256({
    ikm: args.cek,
    salt: EMPTY_SALT,
    info: CARDANO_POE_HKDF_INFO_SLOTS_MAC,
    length: 32,
  });
  return hmac(sha256, macKey, args.slotsHash);
}

// Passphrase-path key commitment: HMAC-SHA-256 keyed by an HKDF leaf of the CEK
// over the 32-byte `pw_hash`. Prepended inside the ciphertext blob (never an
// on-chain field), so testing a passphrase guess requires possession of the
// blob itself.
export function computePassphraseCommitment(args: {
  cek: Uint8Array;
  pwHash: Uint8Array;
}): Uint8Array {
  const macKey = hkdfSha256({
    ikm: args.cek,
    salt: EMPTY_SALT,
    info: CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC,
    length: 32,
  });
  return hmac(sha256, macKey, args.pwHash);
}

// Slots-path content key: HKDF-SHA-256(ikm=CEK, salt=enc.nonce, info=payload-v1).
// The content is encrypted under this leaf of the CEK, never under the CEK
// directly, so the wrap layer and the content layer never key the same primitive
// on the same bytes. The envelope-unique nonce salt makes the key single-use,
// which is what keeps the STREAM counter nonces collision-free.
export function slotsPayloadKey(args: { cek: Uint8Array; nonce: Uint8Array }): Uint8Array {
  return hkdfSha256({
    ikm: args.cek,
    salt: args.nonce,
    info: CARDANO_POE_HKDF_INFO_PAYLOAD,
    length: 32,
  });
}

// Passphrase-path content key: HKDF-SHA-256(ikm=CEK, salt=enc.nonce,
// info=payload-passphrase-v1).
export function passphrasePayloadKey(args: { cek: Uint8Array; nonce: Uint8Array }): Uint8Array {
  return hkdfSha256({
    ikm: args.cek,
    salt: args.nonce,
    info: CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE,
    length: 32,
  });
}

// Classical (x25519) per-slot KEK salt:
// SHA-256("cardano-poe-x25519-kek-salt-v1" || enc.nonce || epk || pub_R).
// The slot's own ephemeral anchors the KEK to a slot-unique value, `pub_R`
// binds it to the specific recipient (defeating confused-deputy relay of the
// ephemeral against a different recipient), and the envelope-unique `enc.nonce`
// anchors it to one envelope — a CSPRNG failure that repeats KEM randomness
// across records degrades to mere linkability instead of reproducing a
// (KEK, zero-nonce) wrap pair.
export function x25519KekSalt(args: {
  nonce: Uint8Array;
  epk: Uint8Array;
  pubR: Uint8Array;
}): Uint8Array {
  return labelledSha256(CARDANO_POE_X25519_KEK_SALT_PREFIX, args.nonce, args.epk, args.pubR);
}

// Hybrid (mlkem768x25519) per-slot KEK salt:
// SHA-256("cardano-poe-xwing-kek-salt-v1" || enc.nonce || kem_ct || pub_R).
// `kem_ct` is the slot's 1120-byte X-Wing ciphertext exactly as carried on the
// wire and `pub_R` the 1216-byte X-Wing recipient public key — the same three
// bindings as the classical salt, computed outside the KEM over the slot's own
// wire bytes so it holds X-Wing as a black box.
export function xwingKekSalt(args: {
  nonce: Uint8Array;
  kemCt: Uint8Array;
  pubR: Uint8Array;
}): Uint8Array {
  return labelledSha256(CARDANO_POE_XWING_KEK_SALT_PREFIX, args.nonce, args.kemCt, args.pubR);
}
