// Multi-recipient sealed-PoE unwrap (age-style trial-decrypt with the slot-set
// MAC folded into per-slot acceptance + partitioning-oracle length pre-checks).
//
// Three key forms (mutually exclusive — exactly one MUST be supplied):
//
//   • Single-priv form: `recipientSecretKey: Uint8Array` — the standalone-verifier
//     path. Runs the trial-decrypt loop over `envelope.slots` once.
//
//   • Multi-priv form: `recipientSecretKeys: ReadonlyArray<Uint8Array>` — for the
//     trial-decrypt scan of a rotated identity holding `[currentPriv, ...archivedPrivs]`.
//     Caller supplies the order; the iterator runs outer-loop = privkey ×
//     inner-loop = slot, short-circuiting on the first priv that accepts a
//     slot. The recommended caller order is `[currentPriv,
//     ...previousPrivsReversed]` (newest archive first).
//
//   • Bundle form: `recipientKeyBundle` — both KEMs' secret lists; the dispatch
//     picks the right one from `envelope.kem`.
//
// The inner per-slot loop is constant-time across slots: every slot of a key's
// pass is entered regardless of match position, and every slot pays the same
// KEM + HKDF + wrap-open + MAC work, so an observer cannot infer which slot
// index matched. The outer loop short-circuits on the first cross-priv match —
// that channel leaks only the weak "which key matched" ordering signal,
// intrinsic to multi-key trial-decrypt.
//
// Per-slot acceptance folds three bits: `ok = kem_ok AND open_ok AND mac_ok`.
// The MAC fold is load-bearing: a malicious sender can craft a slot that
// wrap-opens under a recipient's key with an attacker-chosen CEK, but that CEK
// does not reproduce `slots_mac`, so the forged slot is skipped exactly like a
// non-matching one and an honest slot later in the array still wins.
//
// The per-slot recovery body differs by KEM, but both take the same work
// shape — KEK derivation, then a wrap-open attempt on EVERY slot:
//   • x25519:         X25519 ECDH → HKDF → AEAD-unwrap; a low-order epk
//                     (RFC 7748 §6.1 contributory-check rejection) sets
//                     kem_ok=false, derives a dummy KEK instead, and STILL
//                     attempts the wrap-open under it, so an invalid-ECDH slot
//                     pays the identical per-slot cost and can never be
//                     accepted (the kem bit is folded into acceptance).
//   • mlkem768x25519: X-Wing decapsulate → HKDF → AEAD-unwrap; NEVER throws on
//                     attacker wire data (ML-KEM implicit rejection yields a
//                     pseudorandom shared secret), so no try/catch around it.

import { chacha20Poly1305Decrypt } from '../aead/chacha20-poly1305';
import { AeadVerificationError } from '../aead/errors';
import { hkdfSha256 } from '../kdf/hkdf';
import {
  mlkem768x25519Decapsulate,
  mlkem768x25519Keygen,
  MLKEM768X25519_ENC_LENGTH,
} from '../kem/mlkem768x25519';
import { x25519Ecdh, X25519LowOrderPointError, x25519PublicKey } from '../kem/x25519';
import { compareCt } from '../util/compare-ct';

import { EciesSealedPoeError } from './errors';
import {
  finishSlotAcceptance,
  foldSlotAcceptance,
  newSlotAcceptanceState,
} from './slot-acceptance';
import { streamOpen, StreamTamperedError } from './stream';
import {
  computeSlotsHash,
  computeSlotsMac,
  itemHashesHash,
  MAX_DECODED_ENVELOPE_BYTES,
  MAX_SLOTS,
  slotsPayloadKey,
  x25519KekSalt,
  xwingKekSalt,
  type ItemHashes,
} from './transcript';
import {
  CARDANO_POE_HKDF_INFO_KEK,
  CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
  SEALED_POE_AEAD,
  type Mlkem768X25519Slot,
  type SealedEnvelope,
  type X25519Slot,
} from './wrap';

// Typed decryption outcomes — internal diagnostics for a trusted local caller.
// An untrusted external caller MUST receive one indistinguishable generic
// failure regardless of which of these fired.
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
// selected list is empty unwraps to a clean no-match without touching any KEM
// primitive.
export interface RecipientKeyBundle {
  readonly x25519PrivateKeys: ReadonlyArray<Uint8Array>;
  readonly mlkem768x25519SecretSeeds: ReadonlyArray<Uint8Array>;
}

// Select the secret-key list a bundle contributes for the given envelope KEM.
// The single dispatch seam — unwrap and trial-decrypt both route through here so
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
  // The item's plaintext-hash claim, as carried in the record body. Bound into
  // the slots transcript: an envelope spliced onto an item with a different
  // hashes map fails the per-slot MAC, before any content work.
  readonly hashes: ItemHashes;
  // Test-only instrumentation for the constant-time-across-slots invariant.
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

// Trial-decrypt-only sibling of eciesSealedPoeUnwrap. Runs the per-slot
// acceptance (KEM + wrap-open + slots_mac) but NEVER opens the content stream
// (which requires the off-chain ciphertext blob, not available at trial-decrypt
// time). Used by an inbox-scan agent to discover readable records before
// fetching their ciphertext.
interface TrialDecryptOnlyArgsCommon {
  readonly envelope: SealedEnvelope;
  readonly hashes: ItemHashes;
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

// Binary by design: with the MAC folded into per-slot acceptance there is no
// observable middle state — a slot either fully matches (KEM + wrap + MAC) or
// it does not. A CEK conflict among accepted slots fails closed to no_match.
export type TrialDecryptOnlyResult =
  | { readonly kind: 'match'; readonly slotIdx: number; readonly cek: Uint8Array }
  | { readonly kind: 'no_match' };

const ZERO_NONCE_12: Uint8Array = new Uint8Array(12);
const CEK_LENGTH = 32 as const;
const X25519_SECRET_KEY_LENGTH = 32 as const;
const X25519_PUBLIC_KEY_LENGTH = 32 as const;
const NONCE_LENGTH = 24 as const;
const WRAP_LENGTH = 48 as const;
const SLOTS_MAC_LENGTH = 32 as const;

// Stable string key for a byte string, used only for the per-slot KEM-material
// duplicate check (a structural pre-trial gate, not a constant-time comparison).
function bytesKey(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]!);
  }
  return s;
}

// Partitioning-oracle defence: every wire
// length MUST be validated before any KEM/AEAD primitive is invoked, so malformed
// records cannot probe per-slot failure ordering. Shared between
// `eciesSealedPoeUnwrap` (single- and multi-priv) and `eciesSealedPoeTrialDecrypt`
// to guarantee byte-identical pre-trial behaviour and to keep the dispatch
// invariant in one place.
function assertEnvelopeStructure(
  envelope: SealedEnvelope,
  multiPrivKeys?: ReadonlyArray<Uint8Array>,
  singlePrivKey?: Uint8Array,
): void {
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
  // Resource bound: reject an envelope with more than MAX_SLOTS slots before any
  // KEM/AEAD primitive runs, so a malformed record cannot drive unbounded
  // per-slot work. Checked before the per-slot length loop below.
  if (n > MAX_SLOTS) {
    throw new EciesSealedPoeError(
      'ENC_SLOTS_TOO_MANY',
      `envelope.slots.length=${n} exceeds MAX_SLOTS=${MAX_SLOTS}`,
    );
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
  //
  // Per-slot KEK uniqueness is also enforced here. The zero-nonce per-slot wrap
  // is safe only because each slot draws fresh KEM randomness, so its KEK is
  // unique; two slots sharing the same KEM material derive the same KEK and
  // repeat a (KEK, zero-nonce) pair. The KEM material that fixes the KEK is the
  // `epk` (x25519) or the `kem_ct` (hybrid) — both bound into the KEK salt — so
  // a repeat of either across slots is rejected outright.
  const seenKemMaterial = new Set<string>();
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
      const key = bytesKey(slot.epk);
      if (seenKemMaterial.has(key)) {
        throw new EciesSealedPoeError(
          'ENC_SLOTS_DUPLICATE_KEM_MATERIAL',
          `envelope.slots[${i}].epk duplicates an earlier slot — per-slot KEK uniqueness is violated`,
        );
      }
      seenKemMaterial.add(key);
    }
  } else {
    for (let i = 0; i < n; i++) {
      const slot = envelope.slots[i]!;
      if (slot.kem_ct.length !== MLKEM768X25519_ENC_LENGTH) {
        throw new EciesSealedPoeError(
          'KEM_CT_LENGTH_MISMATCH',
          `envelope.slots[${i}].kem_ct MUST be exactly ${MLKEM768X25519_ENC_LENGTH} bytes, got ${slot.kem_ct.length}`,
        );
      }
      if (slot.wrap.length !== WRAP_LENGTH) {
        throw new EciesSealedPoeError(
          'WRAP_LENGTH_MISMATCH',
          `envelope.slots[${i}].wrap MUST be exactly ${WRAP_LENGTH} bytes, got ${slot.wrap.length}`,
        );
      }
      const key = bytesKey(slot.kem_ct);
      if (seenKemMaterial.has(key)) {
        throw new EciesSealedPoeError(
          'ENC_SLOTS_DUPLICATE_KEM_MATERIAL',
          `envelope.slots[${i}].kem_ct duplicates an earlier slot — per-slot KEK uniqueness is violated`,
        );
      }
      seenKemMaterial.add(key);
    }
  }

  // Decoded-envelope byte backstop. Every per-slot field above is validated to a
  // fixed length, so the decoded envelope's aggregate size is determined here:
  // nonce + slots_mac + per-slot (epk|kem_ct + wrap). Reject before any KEM/AEAD
  // primitive when it exceeds the bound — a tighter resource cap than MAX_SLOTS
  // for honest records, and the bound a parser that can see the decoded size
  // enforces. (The slot-count cap above already bounds work; this is the byte
  // backstop the verifier also pins.)
  const perSlotBytes =
    envelope.kem === 'x25519'
      ? X25519_PUBLIC_KEY_LENGTH + WRAP_LENGTH
      : MLKEM768X25519_ENC_LENGTH + WRAP_LENGTH;
  const decodedEnvelopeBytes = NONCE_LENGTH + SLOTS_MAC_LENGTH + n * perSlotBytes;
  if (decodedEnvelopeBytes > MAX_DECODED_ENVELOPE_BYTES) {
    throw new EciesSealedPoeError(
      'ENC_ENVELOPE_TOO_LARGE',
      `decoded envelope size ${decodedEnvelopeBytes} exceeds MAX_DECODED_ENVELOPE_BYTES=${MAX_DECODED_ENVELOPE_BYTES}`,
    );
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

// All-zero IKM for the dummy KEK an invalid-ECDH slot derives so it pays the
// same HKDF work as a live slot (see `tryX25519Slot`).
const ZERO_IKM_32: Uint8Array = new Uint8Array(32);
// Fixed dummy candidate CEK for a slot whose wrap-open failed, so the per-slot
// MAC step runs uniformly on every slot. The dummy is independent of the failed
// ciphertext, and its MAC outcome can never accept a slot — acceptance also
// requires the slot's `ok` bit.
const DUMMY_CEK_32: Uint8Array = new Uint8Array(32);

// One slot's recovery outcome: the folded `kem_ok AND open_ok` acceptance
// contribution as a 0|1 integer, plus the candidate CEK — the recovered
// 32-byte wrap plaintext, or the fixed dummy when the bit is 0 — so the
// caller's MAC step folds the same-shaped input for every slot.
interface SlotCandidate {
  readonly ok: number;
  readonly candidate: Uint8Array;
}

// Attempt the per-slot wrap AEAD, or yield the dummy candidate. Atomic: on a
// tag failure no plaintext escapes and the candidate is the fixed all-zero
// dummy, independent of the failed ciphertext.
function wrapOpenOrDummy(kek: Uint8Array, aad: Uint8Array, wrap: Uint8Array): SlotCandidate {
  try {
    const plaintext = chacha20Poly1305Decrypt({
      key: kek,
      nonce: ZERO_NONCE_12,
      aad,
      ciphertext: wrap,
    });
    // The wrap is pre-validated to 48 bytes, so the recovered CEK is exactly
    // 32; anything else is treated as a failed open.
    if (plaintext.length === CEK_LENGTH) {
      return { ok: 1, candidate: plaintext };
    }
    return { ok: 0, candidate: DUMMY_CEK_32 };
  } catch (e) {
    if (!(e instanceof AeadVerificationError)) throw e;
    return { ok: 0, candidate: DUMMY_CEK_32 };
  }
}

// Classical (x25519) per-slot recovery body. The wrap AEAD is attempted on
// EVERY slot (no match-position-dependent skip), so a per-priv scan recovers a
// candidate CEK from each slot the recipient is addressed in — which is what
// the CEK-conflict detection needs — and every slot pays the identical
// ECDH + HKDF + AEAD-open cost regardless of where the match lands.
//
// `kem_ok` is the X25519 validity bit: a small-order `epk` drives the shared
// secret to all-zero, which RFC 7748 §6.1 rejects. @noble/curves signals this
// by THROWING from `getSharedSecret`, so a fully branchless ct-select over the
// shared secret is not expressible against this library API. The next-best,
// equivalent form is taken instead: on the all-zero rejection the slot derives
// a DUMMY KEK from `ikm=0^32` (same salt/info — same HKDF work) and STILL
// attempts the wrap-open under it, so the invalid-ECDH slot takes the same
// per-slot work shape as a live one, while `kem_ok=0` folded into the returned
// bit means it can never be accepted regardless of the AEAD outcome.
function tryX25519Slot(args: {
  slot: X25519Slot;
  nonce: Uint8Array;
  recipientSecretKey: Uint8Array;
  pubRLocal: Uint8Array;
}): SlotCandidate {
  const salt = x25519KekSalt({ nonce: args.nonce, epk: args.slot.epk, pubR: args.pubRLocal });
  let kemOk = 1;
  let kek: Uint8Array;
  try {
    const shared = x25519Ecdh({
      secretKey: args.recipientSecretKey,
      theirPublicKey: args.slot.epk,
    });
    kek = hkdfSha256({ ikm: shared, salt, info: CARDANO_POE_HKDF_INFO_KEK, length: 32 });
  } catch (e) {
    if (!(e instanceof X25519LowOrderPointError)) throw e;
    kemOk = 0;
    kek = hkdfSha256({ ikm: ZERO_IKM_32, salt, info: CARDANO_POE_HKDF_INFO_KEK, length: 32 });
  }
  const opened = wrapOpenOrDummy(kek, CARDANO_POE_HKDF_INFO_KEK, args.slot.wrap);
  return { ok: kemOk & opened.ok, candidate: opened.candidate };
}

// Hybrid (mlkem768x25519) per-slot recovery body. X-Wing decapsulate NEVER
// throws on attacker wire data (ML-KEM implicit rejection), so there is no
// try/catch and the KEM validity bit is constant 1: a wrong shared secret
// simply yields a KEK that fails the AEAD tag. As in the classical body, the
// AEAD is attempted on EVERY slot (full decapsulate + HKDF + AEAD-open) so
// matching and non-matching slots cost the same X-Wing work.
function tryMlkem768X25519Slot(args: {
  slot: Mlkem768X25519Slot;
  nonce: Uint8Array;
  recipientSecretKey: Uint8Array;
  pubR: Uint8Array;
}): SlotCandidate {
  // kem_ct length was validated against MLKEM768X25519_ENC_LENGTH in
  // assertEnvelopeStructure, so this decapsulate is constant-work.
  const ss = mlkem768x25519Decapsulate({
    secretSeed: args.recipientSecretKey,
    enc: args.slot.kem_ct,
  });
  // The KEK salt binds the envelope nonce, the slot's own ciphertext, and the
  // recipient's own X-Wing public key (recomputed from the held seed), exactly
  // as the producer bound them — see the wrap path.
  const kek = hkdfSha256({
    ikm: ss,
    salt: xwingKekSalt({ nonce: args.nonce, kemCt: args.slot.kem_ct, pubR: args.pubR }),
    info: CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
    length: 32,
  });
  return wrapOpenOrDummy(kek, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, args.slot.wrap);
}

// Outcome of one private key's full pass over the slot array.
//
//   • found        — some slot fully matched (kem_ok AND open_ok AND mac_ok).
//   • selectedCek  — the FIRST matching slot's CEK (null when !found).
//   • cekConflict  — two matching slots recovered different CEKs (the
//                    commitment collision the construction fails closed on).
//   • anyOpened    — some slot wrap-opened under a valid KEM (`kem_ok AND
//                    open_ok`), regardless of its MAC outcome. Distinguishes
//                    the tampered-header diagnostic from a plain non-recipient.
interface PrivPassResult {
  readonly found: boolean;
  readonly selectedCek: Uint8Array | null;
  readonly selectedSlotIdx: number;
  readonly cekConflict: boolean;
  readonly anyOpened: boolean;
}

// Per-priv inner trial-decrypt loop, KEM-driven, with the slot-set MAC folded
// into per-slot acceptance. Every slot is entered and every slot pays the same
// work: KEM recovery, wrap-open, then the MAC check over the loop-constant
// `slots_hash` — keyed from the recovered candidate CEK, or from a fixed dummy
// when the wrap-open failed, so the MAC step is uniform too. This follows the
// spec loop shape:
//
//   ok           = kem_ok AND open_ok AND mac_ok
//   first        = ok AND NOT found
//   cek_conflict = cek_conflict OR (ok AND found AND NOT ctEq(cand, selected))
//   selected_CEK = select(first, cand, selected)
//   found        = found OR ok
//
// No early break is taken, the bits combine with integer `&`/`|` (never a
// short-circuit), and the running selection state is folded with mask-based
// updates, so the scan takes the same source-level path across the whole slot
// set regardless of where (or whether) a match lands.
function runPrivPass(
  envelope: SealedEnvelope,
  recipientSecretKey: Uint8Array,
  slotsHash: Uint8Array,
  slotsAttemptedOut: { count: number; perPrivCounts?: number[] } | undefined,
): PrivPassResult {
  const n = envelope.slots.length;
  const state = newSlotAcceptanceState();
  let anyOpenedBit = 0;

  const acceptSlot = (slot: SlotCandidate, i: number): void => {
    anyOpenedBit |= slot.ok;
    const macOk =
      Number(compareCt(computeSlotsMac({ cek: slot.candidate, slotsHash }), envelope.slots_mac)) &
      1;
    foldSlotAcceptance(state, slot.ok & macOk, slot.candidate, i);
  };

  if (envelope.kem === 'x25519') {
    const pubRLocal = x25519PublicKey({ secretKey: recipientSecretKey });
    for (let i = 0; i < n; i++) {
      if (slotsAttemptedOut !== undefined) {
        slotsAttemptedOut.count = i + 1;
      }
      acceptSlot(
        tryX25519Slot({
          slot: envelope.slots[i]!,
          nonce: envelope.nonce,
          recipientSecretKey,
          pubRLocal,
        }),
        i,
      );
    }
  } else {
    // Recompute the recipient's own X-Wing public key from the held seed: the
    // hybrid KEK salt binds `pub_R`, so each private key in a multi-key scan
    // MUST re-derive it (a single shared pub_R would compute the wrong KEK for
    // every key but one).
    const pubR = mlkem768x25519Keygen(recipientSecretKey).publicKey;
    for (let i = 0; i < n; i++) {
      if (slotsAttemptedOut !== undefined) {
        slotsAttemptedOut.count = i + 1;
      }
      acceptSlot(
        tryMlkem768X25519Slot({
          slot: envelope.slots[i]!,
          nonce: envelope.nonce,
          recipientSecretKey,
          pubR,
        }),
        i,
      );
    }
  }
  const outcome = finishSlotAcceptance(state);
  return {
    found: outcome.found,
    selectedCek: outcome.selectedCek,
    selectedSlotIdx: outcome.selectedSlotIdx,
    cekConflict: outcome.cekConflict,
    anyOpened: anyOpenedBit === 1,
  };
}

// 32-byte slots-transcript hash. It depends only on the header, the slots, and
// the item's hash claim, so it is constant across the multi-priv outer loop and
// the per-slot trial-decrypt loop — callers compute it ONCE and re-key the HMAC
// from each candidate CEK over this same 32-byte message.
function slotsHashBytes(envelope: SealedEnvelope, hashes: ItemHashes): Uint8Array {
  return computeSlotsHash({
    aead: envelope.aead,
    kem: envelope.kem,
    nonce: envelope.nonce,
    slots: envelope.slots as ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
    hashesHash: itemHashesHash(hashes),
  });
}

export function eciesSealedPoeUnwrap(args: UnwrapArgs): UnwrapResult {
  const { envelope, ciphertext } = args;

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
  // multi-priv form keeps the "empty array is a programmer error" contract.
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

  // The slots-transcript hash (which also digests the item's hash claim) is
  // constant across the whole scan — compute it ONCE, then re-key the HMAC from
  // each candidate CEK over this same 32-byte message.
  const slotsHash = slotsHashBytes(envelope, args.hashes);

  let matchedCek: Uint8Array | null = null;
  let anyOpenedAcrossPrivs = false;

  const privKeys: ReadonlyArray<Uint8Array> = hasMulti
    ? multiPrivKeys!
    : [(args as UnwrapArgsSinglePriv).recipientSecretKey];

  for (let k = 0; k < privKeys.length; k++) {
    if (args._privsAttemptedOut !== undefined) {
      args._privsAttemptedOut.count = k + 1;
    }
    if (args._slotsAttemptedOut !== undefined) {
      args._slotsAttemptedOut.count = 0;
    }
    const pass = runPrivPass(envelope, privKeys[k]!, slotsHash, args._slotsAttemptedOut);
    if (args._slotsAttemptedOut?.perPrivCounts !== undefined) {
      args._slotsAttemptedOut.perPrivCounts.push(args._slotsAttemptedOut.count);
    }
    anyOpenedAcrossPrivs = anyOpenedAcrossPrivs || pass.anyOpened;
    if (!pass.found) continue;
    // Two accepted slots recovering different CEKs is the commitment collision
    // the construction fails closed on — an anomalous slot set, surfaced as the
    // generic tampered-header diagnostic.
    if (pass.cekConflict) {
      return { matched: false, reason: 'TAMPERED_HEADER' };
    }
    matchedCek = pass.selectedCek;
    // The outer cross-priv loop short-circuits on the first priv that accepted
    // a slot. This intentionally leaks "which priv matched" → "how many key
    // rotations the recipient has performed". We accept it: trial-decrypt runs
    // client-side, so this timing is only locally observable, and the leak is a
    // weak ordering signal, not a key/plaintext oracle. Making the outer loop
    // constant-work would cost a FULL KEM pass (for the hybrid branch a full
    // X-Wing decapsulation per slot) for EVERY archived priv on EVERY record;
    // the benefit (hiding a count the user already knows) does not justify it.
    // The inner per-slot loop IS constant across slots.
    break;
  }

  if (matchedCek === null) {
    // A slot wrap-opened somewhere but nothing passed the folded acceptance:
    // some slot, header field, the hashes claim, or slots_mac itself was
    // tampered. No wrap-open at all is a plain non-recipient.
    return {
      matched: false,
      reason: anyOpenedAcrossPrivs ? 'TAMPERED_HEADER' : 'WRONG_RECIPIENT_KEY',
    };
  }

  // Content opens under the derived `payload_key` in the segmented STREAM
  // format; each chunk's tag is verified before its plaintext is released.
  try {
    const plaintext = streamOpen({
      payloadKey: slotsPayloadKey({ cek: matchedCek, nonce: envelope.nonce }),
      ciphertext,
    });
    return { matched: true, plaintext };
  } catch (e) {
    if (!(e instanceof StreamTamperedError)) throw e;
    return { matched: false, reason: 'TAMPERED_CIPHERTEXT' };
  }
}

// Trial-decrypt half of the sealed-PoE unwrap algorithm:
// recovers the CEK + slot index without touching the content stream. Used by an
// inbox-scan agent where the on-chain envelope is available but the off-chain
// ciphertext blob is fetched lazily only when the user invokes Decrypt.
//
// Mirrors the multi-priv branch of `eciesSealedPoeUnwrap`: same
// partitioning-oracle pre-checks, same per-priv inner loop with the MAC folded
// into per-slot acceptance, same constant-across-slots invariant. Differs only
// in the return shape: `{kind: 'match', slotIdx, cek}` instead of plaintext;
// `{kind: 'no_match'}` for everything else (per-slot acceptance is binary, so
// there is no distinguishable middle outcome). Cross-priv variable-time
// short-circuit is preserved (leaks "which priv matched" → "how many
// rotations", a documented weak ordering signal).
export function eciesSealedPoeTrialDecrypt(args: TrialDecryptOnlyArgs): TrialDecryptOnlyResult {
  const { envelope } = args;

  // Bundle form selects the per-KEM list from `envelope.kem`; flat form is
  // already KEM-pre-selected. An empty bundle list for this KEM is a clean
  // no_match (the recipient holds no key of the matching kind), whereas an
  // empty flat list stays a programmer error.
  const hasBundle = 'recipientKeyBundle' in args;
  const recipientSecretKeys: ReadonlyArray<Uint8Array> = hasBundle
    ? selectBundleSecrets(envelope, args.recipientKeyBundle)
    : args.recipientSecretKeys;

  if (recipientSecretKeys.length === 0) {
    if (hasBundle) {
      return { kind: 'no_match' };
    }
    throw new EciesSealedPoeError(
      'INVALID_RECIPIENT_KEY',
      'recipientSecretKeys MUST be a non-empty array, got length=0',
    );
  }
  assertEnvelopeStructure(envelope, recipientSecretKeys, undefined);

  const slotsHash = slotsHashBytes(envelope, args.hashes);

  for (let k = 0; k < recipientSecretKeys.length; k++) {
    if (args._privsAttemptedOut !== undefined) {
      args._privsAttemptedOut.count = k + 1;
    }
    if (args._slotsAttemptedOut !== undefined) {
      args._slotsAttemptedOut.count = 0;
    }
    const pass = runPrivPass(envelope, recipientSecretKeys[k]!, slotsHash, args._slotsAttemptedOut);
    if (args._slotsAttemptedOut?.perPrivCounts !== undefined) {
      args._slotsAttemptedOut.perPrivCounts.push(args._slotsAttemptedOut.count);
    }
    if (!pass.found) continue;
    // A CEK conflict is never a clean match — fail closed.
    if (pass.cekConflict) {
      return { kind: 'no_match' };
    }
    return {
      kind: 'match',
      slotIdx: pass.selectedSlotIdx,
      cek: pass.selectedCek as Uint8Array,
    };
  }
  return { kind: 'no_match' };
}
