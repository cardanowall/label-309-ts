// Multi-recipient sealed-PoE unwrap (age-style trial-decrypt
// + constant-time slots_mac binding + partitioning-oracle length pre-checks).
//
// Two forms (mutually exclusive — exactly one MUST be supplied):
//
//   • Single-priv form: `recipientSecretKey: Uint8Array` — the standalone-verifier
//     path. Runs the trial-decrypt loop over `envelope.slots` once.
//
//   • Multi-priv form: `recipientSecretKeys: ReadonlyArray<Uint8Array>` — for the
//     trial-decrypt scan of a rotated identity holding `[currentPriv, ...archivedPrivs]`.
//     Caller supplies the order; the iterator runs outer-loop = privkey ×
//     inner-loop = slot, short-circuiting on the first cross-priv match that
//     passes slots_mac verification. The recommended caller order
//     is `[currentPriv, ...previousPrivsReversed]` (newest archive first).
//
// Constant-time-N (default `true`) applies PER PRIV (the inner loop): all slots
// are entered regardless of match position. The outer loop short-circuits on
// first cross-priv match — the cross-priv channel is intrinsic to trial-decrypt
//
// Both KEM branches share this control flow. The per-slot recovery body differs:
//   • x25519:         X25519 ECDH → HKDF → AEAD-unwrap; may throw on a low-order
//                     epk (RFC 7748 §6.1 contributory-check rejection), handled
//                     as a non-match.
//   • mlkem768x25519: X-Wing decapsulate → HKDF → AEAD-unwrap; NEVER throws on
//                     attacker wire data (ML-KEM implicit rejection yields a
//                     pseudorandom shared secret), so no try/catch around it.

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { chacha20Poly1305Decrypt } from '../aead/chacha20-poly1305';
import { AeadVerificationError } from '../aead/errors';
import { xchacha20Poly1305Decrypt } from '../aead/xchacha20-poly1305';
import { hkdfSha256 } from '../kdf/hkdf';
import { mlkem768x25519Decapsulate, MLKEM768X25519_ENC_LENGTH } from '../kem/mlkem768x25519';
import { x25519Ecdh, X25519LowOrderPointError, x25519PublicKey } from '../kem/x25519';
import { compareCt } from '../util/compare-ct';

import { EciesSealedPoeError } from './errors';
import { joinKemCt, slotsToMacCbor } from './slots-codec';
import {
  CARDANO_POE_HKDF_INFO_KEK,
  CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
  CARDANO_POE_HKDF_INFO_SLOTS_MAC,
  type Mlkem768X25519Slot,
  type SealedEnvelope,
  type X25519Slot,
} from './wrap';

export type UnwrapFailureReason = 'WRONG_RECIPIENT_KEY' | 'TAMPERED_HEADER' | 'TAMPERED_CIPHERTEXT';

export type UnwrapResult =
  | { readonly matched: true; readonly plaintext: Uint8Array }
  | { readonly matched: false; readonly reason: UnwrapFailureReason };

// Unified recipient key bundle. Callers hold BOTH the X25519
// private-key chain (current + archived, for classical and rotation history)
// AND the X-Wing secret seed(s) (for the hybrid KEM), without knowing which a
// given record was sealed under. They pass the whole bundle; the unwrap /
// trial-decrypt dispatch selects the correct secret list from `envelope.kem`:
//
//   • kem === 'x25519'         → bundle.x25519PrivateKeys
//   • kem === 'mlkem768x25519' → bundle.mlkem768x25519SecretSeeds
//
// Both lists are ordered newest-first (caller's responsibility — the outer
// trial-decrypt loop scans them in order). A list MAY be empty when the
// recipient holds no key for that KEM (e.g. archived-only X25519 identities
// predate the hybrid KEM, so their hybrid seed list is empty); a bundle whose
// selected list is empty unwraps to a clean WRONG_RECIPIENT_KEY / no_aead_pass
// without touching any KEM primitive.
export interface RecipientKeyBundle {
  readonly x25519PrivateKeys: ReadonlyArray<Uint8Array>;
  readonly mlkem768x25519SecretSeeds: ReadonlyArray<Uint8Array>;
}

// Select the secret-key list a bundle contributes for the given envelope KEM.
// The single dispatch seam — wrap and trial-decrypt both route through here so
// the per-KEM selection lives in exactly one place.
function selectBundleSecrets(
  envelope: SealedEnvelope,
  bundle: RecipientKeyBundle,
): ReadonlyArray<Uint8Array> {
  return envelope.kem === 'x25519' ? bundle.x25519PrivateKeys : bundle.mlkem768x25519SecretSeeds;
}

interface UnwrapArgsCommon {
  readonly envelope: SealedEnvelope;
  readonly ciphertext: Uint8Array;
  readonly constantTimeN?: boolean;
  // Test-only instrumentation for constant-time-N verification.
  // The unwrap fn bumps `count` once per inner-loop iteration entered. In the
  // multi-priv path, `count` is reset at the start of each outer iteration and
  // — when `perPrivCounts` is provided — the final per-priv inner count is
  // appended after that priv's inner loop completes. Production callers never
  // pass this.
  readonly _slotsAttemptedOut?: { count: number; perPrivCounts?: number[] };
  // Test-only multi-priv outer-loop iteration counter. Bumped to `k + 1` at
  // the start of each outer-loop iteration. Production callers never pass this.
  readonly _privsAttemptedOut?: { count: number };
}

export interface UnwrapArgsSinglePriv extends UnwrapArgsCommon {
  readonly recipientSecretKey: Uint8Array;
}

export interface UnwrapArgsMultiPriv extends UnwrapArgsCommon {
  readonly recipientSecretKeys: ReadonlyArray<Uint8Array>;
}

// Bundle form of the multi-priv path: the caller passes both KEMs' secret
// lists and the dispatch picks the right one from `envelope.kem`. This is the
// surface every read-path consumer (inbox decrypt, CLI decrypt, standalone
// recipient verifier) should use — they hold the whole identity key bundle and
// must NOT pre-select a list or rebuild slots themselves.
export interface UnwrapArgsBundle extends UnwrapArgsCommon {
  readonly recipientKeyBundle: RecipientKeyBundle;
}

export type UnwrapArgs = UnwrapArgsSinglePriv | UnwrapArgsMultiPriv | UnwrapArgsBundle;

// Trial-decrypt-only sibling of eciesSealedPoeUnwrap. Runs the
// per-slot AEAD + slots_mac check but NEVER calls the content AEAD (which
// requires the off-chain `ciphertext` blob, not available at trial-decrypt
// time). Used by an inbox-scan agent to discover readable records before
// fetching their ciphertext.
interface TrialDecryptOnlyArgsCommon {
  readonly envelope: SealedEnvelope;
  readonly constantTimeN?: boolean;
  readonly _slotsAttemptedOut?: { count: number; perPrivCounts?: number[] };
  readonly _privsAttemptedOut?: { count: number };
}

// Exactly one of `recipientSecretKeys` (flat, KEM-pre-selected) or
// `recipientKeyBundle` (whole bundle, KEM dispatched from `envelope.kem`).
// Inbox-scan consumers pass the bundle; the low-level / parity tests pass the
// flat list directly.
export type TrialDecryptOnlyArgs = TrialDecryptOnlyArgsCommon &
  (
    | { readonly recipientSecretKeys: ReadonlyArray<Uint8Array> }
    | { readonly recipientKeyBundle: RecipientKeyBundle }
  );

export type TrialDecryptOnlyResult =
  | { readonly kind: 'match'; readonly slotIdx: number; readonly cek: Uint8Array }
  | { readonly kind: 'no_aead_pass' }
  | { readonly kind: 'aead_pass_no_mac_match' };

const ZERO_NONCE_12: Uint8Array = new Uint8Array(12);
const EMPTY_SALT: Uint8Array = new Uint8Array(0);
const X25519_SECRET_KEY_LENGTH = 32 as const;
const X25519_PUBLIC_KEY_LENGTH = 32 as const;
const NONCE_LENGTH = 24 as const;
const WRAP_LENGTH = 48 as const;
const SLOTS_MAC_LENGTH = 32 as const;

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// Partitioning-oracle defence: every wire
// length MUST be validated before any KEM/AEAD primitive is invoked, so malformed
// records cannot probe per-slot failure ordering. Shared between
// `eciesSealedPoeUnwrap` (single- and multi-priv) and `eciesSealedPoeTrialDecrypt`
// to guarantee byte-identical pre-trial behaviour and to keep the dispatch
// invariant in one place. For the hybrid branch this includes reassembling each
// slot's `kem_ct` and asserting the flat enc length BEFORE any decapsulation.
function assertEnvelopeStructure(
  envelope: SealedEnvelope,
  multiPrivKeys?: ReadonlyArray<Uint8Array>,
  singlePrivKey?: Uint8Array,
): void {
  if (envelope.scheme !== 1) {
    throw new EciesSealedPoeError(
      'UNSUPPORTED_ENC_VERSION',
      `envelope.scheme=${String(envelope.scheme)} unsupported (expected 1)`,
    );
  }
  if (envelope.aead !== 'xchacha20-poly1305') {
    throw new EciesSealedPoeError(
      'UNSUPPORTED_AEAD_ALG',
      `envelope.aead=${String(envelope.aead)} unsupported (expected 'xchacha20-poly1305')`,
    );
  }
  if (envelope.kem !== 'x25519' && envelope.kem !== 'mlkem768x25519') {
    throw new EciesSealedPoeError(
      'UNSUPPORTED_KEM_ALG',
      `envelope.kem=${String((envelope as { kem: string }).kem)} unsupported (expected 'x25519' or 'mlkem768x25519')`,
    );
  }

  // Envelope-level length pre-checks in this exact order.
  const n = envelope.slots.length;
  if (n < 1) {
    throw new EciesSealedPoeError('ENC_SLOTS_EMPTY', `envelope.slots.length=${n} must be >= 1`);
  }
  if (envelope.nonce.length !== NONCE_LENGTH) {
    throw new EciesSealedPoeError(
      'NONCE_LENGTH_MISMATCH',
      `envelope.nonce MUST be exactly ${NONCE_LENGTH} bytes, got ${envelope.nonce.length}`,
    );
  }
  if (envelope.slots_mac.length !== SLOTS_MAC_LENGTH) {
    throw new EciesSealedPoeError(
      'ENC_SLOTS_MAC_INVALID_LENGTH',
      `envelope.slots_mac MUST be exactly ${SLOTS_MAC_LENGTH} bytes, got ${envelope.slots_mac.length}`,
    );
  }

  // Per-slot length pre-checks — KEM-driven. ALL slots are validated here,
  // before any decapsulation, so the trial-decrypt loop never observes a
  // malformed slot (partitioning-oracle-safe ordering).
  if (envelope.kem === 'x25519') {
    for (let i = 0; i < n; i++) {
      const slot = envelope.slots[i]!;
      if (slot.epk.length !== X25519_PUBLIC_KEY_LENGTH) {
        throw new EciesSealedPoeError(
          'KEM_EPK_LENGTH_MISMATCH',
          `envelope.slots[${i}].epk MUST be exactly ${X25519_PUBLIC_KEY_LENGTH} bytes, got ${slot.epk.length}`,
        );
      }
      if (slot.wrap.length !== WRAP_LENGTH) {
        throw new EciesSealedPoeError(
          'WRAP_LENGTH_MISMATCH',
          `envelope.slots[${i}].wrap MUST be exactly ${WRAP_LENGTH} bytes, got ${slot.wrap.length}`,
        );
      }
    }
  } else {
    for (let i = 0; i < n; i++) {
      const slot = envelope.slots[i]!;
      const enc = joinKemCt(slot.kem_ct);
      if (enc.length !== MLKEM768X25519_ENC_LENGTH) {
        throw new EciesSealedPoeError(
          'KEM_CT_LENGTH_MISMATCH',
          `envelope.slots[${i}].kem_ct MUST reassemble to exactly ${MLKEM768X25519_ENC_LENGTH} bytes, got ${enc.length}`,
        );
      }
      if (slot.wrap.length !== WRAP_LENGTH) {
        throw new EciesSealedPoeError(
          'WRAP_LENGTH_MISMATCH',
          `envelope.slots[${i}].wrap MUST be exactly ${WRAP_LENGTH} bytes, got ${slot.wrap.length}`,
        );
      }
    }
  }

  if (multiPrivKeys !== undefined) {
    for (let i = 0; i < multiPrivKeys.length; i++) {
      if (multiPrivKeys[i]!.length !== X25519_SECRET_KEY_LENGTH) {
        throw new EciesSealedPoeError(
          'INVALID_RECIPIENT_KEY',
          `recipientSecretKeys[${i}] MUST be exactly ${X25519_SECRET_KEY_LENGTH} bytes, got ${multiPrivKeys[i]!.length}`,
        );
      }
    }
  } else if (singlePrivKey !== undefined) {
    if (singlePrivKey.length !== X25519_SECRET_KEY_LENGTH) {
      throw new EciesSealedPoeError(
        'INVALID_RECIPIENT_KEY',
        `recipientSecretKey MUST be exactly ${X25519_SECRET_KEY_LENGTH} bytes, got ${singlePrivKey.length}`,
      );
    }
  }
}

// Classical (x25519) per-slot recovery body. Returns the CEK on the first
// AEAD-tag success; null otherwise. `liveSlot` distinguishes the real-work path
// (attempt the AEAD unwrap) from the constant-time-N dummy path (do the ECDH +
// HKDF but skip the AEAD, since a CEK is already in hand).
function tryX25519Slot(args: {
  slot: X25519Slot;
  recipientSecretKey: Uint8Array;
  pubRLocal: Uint8Array;
  liveSlot: boolean;
}): Uint8Array | null {
  // A slot's `epk` is attacker-influenceable wire data. A small-order
  // Montgomery point makes the X25519 shared secret all-zero, which the KEM
  // rejects per RFC 7748 §6.1. Such a slot can never have been produced by a
  // conformant wrap for THIS recipient, so it is a non-match — handled here
  // identically to an AEAD-tag failure (skip the slot, keep iterating so the
  // constant-time-N loop shape is preserved). Only the contributory-check
  // rejection is swallowed; any other error propagates.
  if (args.liveSlot) {
    try {
      const shared = x25519Ecdh({
        secretKey: args.recipientSecretKey,
        theirPublicKey: args.slot.epk,
      });
      const kek = hkdfSha256({
        ikm: shared,
        salt: concat(args.slot.epk, args.pubRLocal),
        info: CARDANO_POE_HKDF_INFO_KEK,
        length: 32,
      });
      return chacha20Poly1305Decrypt({
        key: kek,
        nonce: ZERO_NONCE_12,
        aad: CARDANO_POE_HKDF_INFO_KEK,
        ciphertext: args.slot.wrap,
      });
    } catch (e) {
      if (!(e instanceof AeadVerificationError) && !(e instanceof X25519LowOrderPointError)) {
        throw e;
      }
      return null;
    }
  }
  // Constant-time-N dummy path: mirror the real-work ECDH + HKDF, still
  // tolerating a low-order epk in a later slot so it cannot turn a successful
  // unwrap into a throw.
  try {
    const shared = x25519Ecdh({
      secretKey: args.recipientSecretKey,
      theirPublicKey: args.slot.epk,
    });
    hkdfSha256({
      ikm: shared,
      salt: concat(args.slot.epk, args.pubRLocal),
      info: CARDANO_POE_HKDF_INFO_KEK,
      length: 32,
    });
  } catch (e) {
    if (!(e instanceof X25519LowOrderPointError)) throw e;
  }
  return null;
}

// Hybrid (mlkem768x25519) per-slot recovery body. X-Wing decapsulate NEVER
// throws on attacker wire data (ML-KEM implicit rejection), so there is no
// try/catch: a wrong shared secret simply yields a KEK that fails the AEAD tag.
// The dummy (constant-time-N) path runs a FULL decapsulate + HKDF so matching
// and non-matching slots cost the same X-Wing work.
function tryMlkem768X25519Slot(args: {
  slot: Mlkem768X25519Slot;
  recipientSecretKey: Uint8Array;
  liveSlot: boolean;
}): Uint8Array | null {
  // kem_ct length was validated to reassemble to MLKEM768X25519_ENC_LENGTH in
  // assertEnvelopeStructure, so this join + decapsulate is constant-work.
  const enc = joinKemCt(args.slot.kem_ct);
  const ss = mlkem768x25519Decapsulate({ secretSeed: args.recipientSecretKey, enc });
  const kek = hkdfSha256({
    ikm: ss,
    salt: EMPTY_SALT,
    info: CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
    length: 32,
  });
  if (!args.liveSlot) {
    // Dummy path: full decapsulate + HKDF already done above; skip only the
    // AEAD attempt (a CEK is already in hand).
    return null;
  }
  try {
    return chacha20Poly1305Decrypt({
      key: kek,
      nonce: ZERO_NONCE_12,
      aad: CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
      ciphertext: args.slot.wrap,
    });
  } catch (e) {
    if (!(e instanceof AeadVerificationError)) throw e;
    return null;
  }
}

// Per-priv inner trial-decrypt loop with slot-index reporting, KEM-driven.
// Enters every slot when constantTimeN; the dummy path keeps per-iteration cost
// uniform regardless of which slot matched.
function tryRecipientUnwrapWithIdx(
  envelope: SealedEnvelope,
  recipientSecretKey: Uint8Array,
  constantTimeN: boolean,
  slotsAttemptedOut: { count: number; perPrivCounts?: number[] } | undefined,
): { cek: Uint8Array; slotIdx: number } | null {
  const n = envelope.slots.length;
  let cek: Uint8Array | null = null;
  let matchedSlotIdx = -1;

  if (envelope.kem === 'x25519') {
    const pubRLocal = x25519PublicKey({ secretKey: recipientSecretKey });
    for (let i = 0; i < n; i++) {
      if (slotsAttemptedOut !== undefined) {
        slotsAttemptedOut.count = i + 1;
      }
      const candidate = tryX25519Slot({
        slot: envelope.slots[i]!,
        recipientSecretKey,
        pubRLocal,
        liveSlot: cek === null,
      });
      if (cek === null && candidate !== null) {
        cek = candidate;
        matchedSlotIdx = i;
      }
      if (cek !== null && !constantTimeN) break;
    }
  } else {
    for (let i = 0; i < n; i++) {
      if (slotsAttemptedOut !== undefined) {
        slotsAttemptedOut.count = i + 1;
      }
      const candidate = tryMlkem768X25519Slot({
        slot: envelope.slots[i]!,
        recipientSecretKey,
        liveSlot: cek === null,
      });
      if (cek === null && candidate !== null) {
        cek = candidate;
        matchedSlotIdx = i;
      }
      if (cek !== null && !constantTimeN) break;
    }
  }
  return cek === null ? null : { cek, slotIdx: matchedSlotIdx };
}

// Back-compat wrapper preserved for callers that only care about the CEK
// (single-priv path inside `eciesSealedPoeUnwrap`).
function tryRecipientUnwrap(
  envelope: SealedEnvelope,
  recipientSecretKey: Uint8Array,
  constantTimeN: boolean,
  slotsAttemptedOut: { count: number; perPrivCounts?: number[] } | undefined,
): Uint8Array | null {
  return (
    tryRecipientUnwrapWithIdx(envelope, recipientSecretKey, constantTimeN, slotsAttemptedOut)
      ?.cek ?? null
  );
}

// Slot-set MAC bytes, KEM-driven so the hybrid kem_ct is
// committed exactly as it appears on-wire. Constant across the multi-priv outer
// loop (depends only on envelope.slots), so callers compute it once.
function slotsMacCborBytes(envelope: SealedEnvelope): Uint8Array {
  return slotsToMacCbor(
    envelope.slots as ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
    envelope.kem,
  );
}

export function eciesSealedPoeUnwrap(args: UnwrapArgs): UnwrapResult {
  const { envelope, ciphertext } = args;
  const constantTimeN = args.constantTimeN ?? true;

  // Exactly-one-of validation across the three UnwrapArgs forms (single-priv,
  // flat multi-priv, bundle). Runs before any AEAD / wire-shape work so a
  // malformed call cannot probe per-slot AEAD timing. The bundle form resolves
  // to a flat multi-priv list here by dispatching on `envelope.kem` — from this
  // point the loop is identical regardless of how the caller supplied keys.
  const hasSingle = 'recipientSecretKey' in args;
  const hasBundle = 'recipientKeyBundle' in args;
  const multiPrivKeys: ReadonlyArray<Uint8Array> | undefined = hasBundle
    ? selectBundleSecrets(envelope, (args as UnwrapArgsBundle).recipientKeyBundle)
    : 'recipientSecretKeys' in args
      ? (args as UnwrapArgsMultiPriv).recipientSecretKeys
      : undefined;
  const hasMulti = multiPrivKeys !== undefined;
  if (hasSingle === hasMulti) {
    throw new EciesSealedPoeError(
      'INVALID_RECIPIENT_KEY',
      'exactly one of recipientSecretKey / recipientSecretKeys / recipientKeyBundle MUST be supplied',
    );
  }
  // A bundle selecting an empty list for this KEM means the recipient holds no
  // key of the matching kind (e.g. an archived-only identity facing a hybrid
  // record). That is a legitimate non-match, NOT a malformed call — return a
  // clean WRONG_RECIPIENT_KEY without invoking any KEM primitive. The flat
  // multi-priv form keeps the original "empty array is a programmer error"
  // contract its callers (and step-3 tests) rely on.
  if (hasMulti && multiPrivKeys!.length === 0) {
    if (hasBundle) {
      return { matched: false, reason: 'WRONG_RECIPIENT_KEY' };
    }
    throw new EciesSealedPoeError(
      'INVALID_RECIPIENT_KEY',
      'recipientSecretKeys MUST be a non-empty array, got length=0',
    );
  }

  // Partitioning-oracle pre-checks; per-priv length validation happens
  // inside `assertEnvelopeStructure`.
  if (hasMulti) {
    assertEnvelopeStructure(envelope, multiPrivKeys, undefined);
  } else {
    assertEnvelopeStructure(envelope, undefined, (args as UnwrapArgsSinglePriv).recipientSecretKey);
  }

  // Trial-decrypt loop. With constantTimeN=true the loop
  // entries are uniform regardless of match position; the per-iteration body
  // does the same KEM + HKDF work in both branches.

  let matchedCek: Uint8Array | null = null;
  let anyCandidateRecovered = false;

  if (hasSingle) {
    const recipientSecretKey = (args as UnwrapArgsSinglePriv).recipientSecretKey;
    const cek = tryRecipientUnwrap(
      envelope,
      recipientSecretKey,
      constantTimeN,
      args._slotsAttemptedOut,
    );
    if (cek === null) {
      return { matched: false, reason: 'WRONG_RECIPIENT_KEY' };
    }
    // Slot-set MAC verification. Use compareCt to
    // avoid leaking byte-position via early-exit on first mismatching byte.
    const slotsCbor = slotsMacCborBytes(envelope);
    const hmacKey = hkdfSha256({
      ikm: cek,
      salt: EMPTY_SALT,
      info: CARDANO_POE_HKDF_INFO_SLOTS_MAC,
      length: 32,
    });
    const slotsMacCalc = hmac(sha256, hmacKey, slotsCbor);
    if (!compareCt(slotsMacCalc, envelope.slots_mac)) {
      return { matched: false, reason: 'TAMPERED_HEADER' };
    }
    matchedCek = cek;
  } else {
    // The slots-CBOR is constant across the outer loop (depends only on
    // envelope.slots) — compute once before the loop to keep per-priv cost
    // identical to the single-priv path.
    const slotsCbor = slotsMacCborBytes(envelope);
    const recipientSecretKeys = multiPrivKeys!;
    for (let k = 0; k < recipientSecretKeys.length; k++) {
      if (args._privsAttemptedOut !== undefined) {
        args._privsAttemptedOut.count = k + 1;
      }
      if (args._slotsAttemptedOut !== undefined) {
        args._slotsAttemptedOut.count = 0;
      }
      const cek = tryRecipientUnwrap(
        envelope,
        recipientSecretKeys[k]!,
        constantTimeN,
        args._slotsAttemptedOut,
      );
      if (args._slotsAttemptedOut?.perPrivCounts !== undefined) {
        args._slotsAttemptedOut.perPrivCounts.push(args._slotsAttemptedOut.count);
      }
      if (cek === null) continue;
      // Slot-set MAC verification per priv that recovered a candidate CEK.
      const hmacKey = hkdfSha256({
        ikm: cek,
        salt: EMPTY_SALT,
        info: CARDANO_POE_HKDF_INFO_SLOTS_MAC,
        length: 32,
      });
      const slotsMacCalc = hmac(sha256, hmacKey, slotsCbor);
      // The outer cross-priv loop short-circuits on the first priv whose
      // recovered CEK also passes slots_mac. This intentionally leaks "which
      // priv matched" → "how many key rotations the recipient has performed".
      // We accept it: trial-decrypt runs client-side, so this timing is only
      // locally observable, and the leak is a weak ordering signal, not a
      // key/plaintext oracle. Making the outer loop constant-work would cost a
      // FULL KEM decapsulation (an X25519 ECDH, or — for the hybrid branch — a
      // full X-Wing ML-KEM-768 + X25519 decapsulation) for EVERY archived priv
      // on EVERY record, which for the hybrid case is the dominant cost; the
      // benefit (hiding a count the user already knows) does not justify it.
      // The inner per-slot loop IS held constant-work (constant-time-N).
      if (compareCt(slotsMacCalc, envelope.slots_mac)) {
        matchedCek = cek;
        break;
      }
      anyCandidateRecovered = true;
    }
    if (matchedCek === null) {
      return {
        matched: false,
        reason: anyCandidateRecovered ? 'TAMPERED_HEADER' : 'WRONG_RECIPIENT_KEY',
      };
    }
  }

  // Content AEAD AAD is `nonce || slots_mac`.
  const adContent = concat(envelope.nonce, envelope.slots_mac);
  try {
    const plaintext = xchacha20Poly1305Decrypt({
      key: matchedCek,
      nonce: envelope.nonce,
      aad: adContent,
      ciphertext,
    });
    return { matched: true, plaintext };
  } catch (e) {
    if (!(e instanceof AeadVerificationError)) throw e;
    return { matched: false, reason: 'TAMPERED_CIPHERTEXT' };
  }
}

// Trial-decrypt half of the sealed-PoE unwrap algorithm:
// recovers the CEK + slot index without touching the content AEAD. Used by an
// inbox-scan agent where the on-chain `metadata_cbor` envelope is available but
// the off-chain ciphertext blob is fetched lazily only when the user invokes
// Decrypt.
//
// Mirrors the multi-priv branch of `eciesSealedPoeUnwrap`: same
// partitioning-oracle pre-checks, same per-priv inner loop, same
// constant-time-N invariant (default `true` — MANDATORY for untrusted scan
// agents), same `compareCt` slots_mac check. Differs only
// in the return shape: `{kind: 'match', slotIdx, cek}` instead of plaintext;
// `{kind: 'aead_pass_no_mac_match'}`
// instead of `TAMPERED_HEADER`; `{kind: 'no_aead_pass'}` instead of
// `WRONG_RECIPIENT_KEY`. Cross-priv variable-time short-circuit is preserved
// (leaks "which priv matched" → "how many rotations",
// a documented weak ordering signal).
export function eciesSealedPoeTrialDecrypt(args: TrialDecryptOnlyArgs): TrialDecryptOnlyResult {
  const { envelope } = args;
  const constantTimeN = args.constantTimeN ?? true;

  // Bundle form selects the per-KEM list from `envelope.kem`; flat form is
  // already KEM-pre-selected. An empty bundle list for this KEM is a clean
  // no_aead_pass (the recipient holds no key of the matching kind), whereas an
  // empty flat list stays a programmer error (its callers / step-3 tests rely
  // on the throw).
  const hasBundle = 'recipientKeyBundle' in args;
  const recipientSecretKeys: ReadonlyArray<Uint8Array> = hasBundle
    ? selectBundleSecrets(envelope, args.recipientKeyBundle)
    : args.recipientSecretKeys;

  if (recipientSecretKeys.length === 0) {
    if (hasBundle) {
      return { kind: 'no_aead_pass' };
    }
    throw new EciesSealedPoeError(
      'INVALID_RECIPIENT_KEY',
      'recipientSecretKeys MUST be a non-empty array, got length=0',
    );
  }
  assertEnvelopeStructure(envelope, recipientSecretKeys, undefined);

  const slotsCbor = slotsMacCborBytes(envelope);

  let anyCandidateRecovered = false;
  for (let k = 0; k < recipientSecretKeys.length; k++) {
    if (args._privsAttemptedOut !== undefined) {
      args._privsAttemptedOut.count = k + 1;
    }
    if (args._slotsAttemptedOut !== undefined) {
      args._slotsAttemptedOut.count = 0;
    }
    const candidate = tryRecipientUnwrapWithIdx(
      envelope,
      recipientSecretKeys[k]!,
      constantTimeN,
      args._slotsAttemptedOut,
    );
    if (args._slotsAttemptedOut?.perPrivCounts !== undefined) {
      args._slotsAttemptedOut.perPrivCounts.push(args._slotsAttemptedOut.count);
    }
    if (candidate === null) continue;
    const hmacKey = hkdfSha256({
      ikm: candidate.cek,
      salt: EMPTY_SALT,
      info: CARDANO_POE_HKDF_INFO_SLOTS_MAC,
      length: 32,
    });
    const slotsMacCalc = hmac(sha256, hmacKey, slotsCbor);
    if (compareCt(slotsMacCalc, envelope.slots_mac)) {
      return { kind: 'match', slotIdx: candidate.slotIdx, cek: candidate.cek };
    }
    anyCandidateRecovered = true;
  }
  return anyCandidateRecovered ? { kind: 'aead_pass_no_mac_match' } : { kind: 'no_aead_pass' };
}
