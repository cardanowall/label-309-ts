// A tight upper-bound estimator for the canonical-CBOR record size.
//
// A publish quote precedes the upload, so the `record_bytes` figure handed to
// `POST /poe/quote` must be computed **before** the final record exists. The
// gateway enforces `actual <= quoted` when the quote is consumed, so the
// estimate must never undershoot: a quote priced for fewer bytes than the
// record turns out to be would be rejected at publish. This module computes an
// **upper bound** on the encoded size of a record from its shape — its content
// items (each with a hash-algorithm list, an optional URI list, and an optional
// sealed envelope) and an optional Merkle commitment — and is unit-tested to be
// `>=` the real canonical-CBOR encoding across every shape the publish helpers
// can build.
//
// `items` and `merkle` are independent top-level peers: a record can carry one,
// the other, or both (the floor is that it carries at least one of them). The
// estimate charges each present component and the exact top-level key count.
//
// Each CBOR header is charged its **exact** canonical width for the count or
// length being encoded (`cborHeaderLen`) rather than a worst-case width, so the
// bound stays tight even near a gateway's record ceiling — a record whose real
// CBOR sits just under `MAX_RECORD_BYTES` must not be falsely rejected by a
// slack estimate. The only deliberate slack is a small fixed `SAFETY_MARGIN`
// and the use of fixed maxima for the AEAD/KEM identifier strings and the
// path-1 COSE_Sign1 (all of which are fixed-shape, so their maxima are exact
// upper bounds).

// The Argon2id registry floors and the salt-length floor are the crypto
// layer's authoritative constants; charging the passphrase envelope from them
// keeps this estimator in lockstep if they are ever retuned.
import {
  PASSPHRASE_ARGON2_M_MIN,
  PASSPHRASE_ARGON2_P_MIN,
  PASSPHRASE_ARGON2_T_MIN,
  PASSPHRASE_SALT_MIN_LENGTH,
} from '@cardanowall/crypto-core';

/**
 * A pre-quote ceiling on the canonical record size, set just under the
 * gateway's ~14,500-byte record ceiling. A record (by its shape) estimated
 * above this can be rejected before a quote is requested with a clear "record
 * too large / too many recipients" error, rather than discovering the
 * rejection at the gateway after a paid upload.
 */
export const MAX_RECORD_BYTES = 14_000;

/** The 24-byte sealed-envelope content nonce. */
const ENVELOPE_NONCE_BYTES = 24;
/** The 32-byte slots MAC. */
const SLOTS_MAC_BYTES = 32;
/** The 48-byte per-slot wrapped CEK (`wrap`). */
const SLOT_WRAP_BYTES = 48;
/** The classical per-slot ephemeral public key (`epk`), 32 bytes. */
const SLOT_EPK_BYTES = 32;
/** The X-Wing per-slot ciphertext (`kem_ct`), 1120 bytes. */
const SLOT_KEM_CT_BYTES = 1120;
/** The 32-byte transaction hash a `supersedes` carries. */
const SUPERSEDES_BYTES = 32;

/**
 * A small fixed slack added once to the whole estimate, absorbing any rounding
 * the per-component sums do not already cover. Kept deliberately small (the
 * component widths are exact) so the bound stays close to the real size near
 * the `MAX_RECORD_BYTES` ceiling rather than rejecting valid records.
 */
const SAFETY_MARGIN = 16;

/**
 * The exact width, in bytes, of a canonical-CBOR argument header for a
 * major-type item whose count/length/value is `n`.
 *
 * Canonical CBOR encodes the argument in the shortest form: inline in the
 * initial byte for `n <= 23`, then a 1-, 2-, 4-, or 8-byte big-endian
 * extension. The returned width includes the initial byte. This is the exact
 * header width for an unsigned integer, a map/array element count, or a
 * text/byte-string length — so the estimate charges precisely what the
 * encoder will emit, never a worst-case width.
 */
function cborHeaderLen(n: number): number {
  if (n <= 23) return 1;
  if (n <= 0xff) return 2;
  if (n <= 0xffff) return 3;
  if (n <= 0xffff_ffff) return 5;
  return 9;
}

/**
 * The exact encoded width of a CBOR map or array header for `entries`
 * elements: its argument header (the element count is the argument).
 */
function containerHeader(entries: number): number {
  return cborHeaderLen(entries);
}

/** The exact encoded width of a CBOR unsigned integer holding `value`. */
function uintBytes(value: number): number {
  return cborHeaderLen(value);
}

/**
 * The exact encoded width of a CBOR text/byte string of `len` bytes: its
 * length-prefix header plus the payload.
 */
function strBytes(len: number): number {
  return cborHeaderLen(len) + len;
}

const utf8Encoder = new TextEncoder();

/**
 * The UTF-8 byte length of a caller-supplied string. CBOR text strings are
 * length-prefixed by their encoded BYTE count, so a non-ASCII URI or
 * algorithm id must be charged its UTF-8 width, not its UTF-16 code-unit
 * count — undercounting would break the upper-bound guarantee.
 */
function utf8ByteLength(s: string): number {
  return utf8Encoder.encode(s).length;
}

/**
 * The `enc` envelope shape of a sealed item: which key-delivery path the
 * scheme-1 envelope uses, since the two encode to very different widths.
 */
export type EncShape =
  | {
      readonly kind: 'kem';
      /**
       * The KEM every slot is sealed under. Classical `x25519` slots carry a
       * 32-byte `epk` + 48-byte `wrap`; hybrid `mlkem768x25519` (X-Wing)
       * slots carry a 1120-byte `kem_ct` + 48-byte `wrap`; the envelope also
       * carries the KEM id and the 32-byte `slots_mac`.
       */
      readonly kem: 'x25519' | 'mlkem768x25519';
      /** The number of recipient slots. */
      readonly recipientCount: number;
    }
  | {
      /**
       * An Argon2id passphrase envelope
       * (`{scheme, aead, nonce, passphrase: {alg, salt, params}}` — no
       * slots). Charged at the canonical producer shape: the fixed
       * `argon2id` identifier, a 16-byte salt, and integer widths that cover
       * the whole `m` wire range plus `t` / `p` up to CBOR's one-byte
       * immediate range (23) — every parameter set the reference producers
       * emit. A producer choosing a longer salt or larger `t` / `p` must
       * size its envelope by building and measuring it.
       */
      readonly kind: 'passphrase';
    };

/**
 * The shape of one content item to size. Every field maps to a CBOR component
 * whose maximum encoded width the estimator sums.
 */
export interface ItemShape {
  /**
   * The content-hash algorithm ids this item will carry (e.g.
   * `['sha2-256', 'blake2b-256']`). Each contributes a key string + a 32-byte
   * digest value. Non-empty for a real item.
   */
  readonly hashAlgs: readonly string[];
  /**
   * The off-chain URIs this item will carry. Each is charged its full string
   * width. Omitted/empty for a hash-only item.
   */
  readonly uris?: readonly string[];
  /**
   * The sealed envelope's shape, when sealed. Omit for an unsealed item (no
   * `enc` block).
   */
  readonly enc?: EncShape;
}

/** The shape of a Merkle commitment for the estimate. */
export interface MerkleShape {
  /** The list-commitment algorithm id (e.g. `rfc9162-sha256`). */
  readonly alg: string;
  /**
   * The off-chain URIs the commitment will carry (e.g. the leaves-list
   * `ar://` pointer). Omitted/empty when the manifest is kept private.
   */
  readonly uris?: readonly string[];
}

/**
 * The shape of the record to size: its content items plus an optional Merkle
 * commitment (independent top-level peers), and the record-level signature /
 * supersedes flags.
 */
export interface RecordShape {
  /**
   * The content items the record carries (its `items[]`). Omitted/empty when
   * the record carries only a Merkle commitment.
   */
  readonly items?: readonly ItemShape[];
  /** Whether the record will carry a record-level COSE_Sign1 signature. */
  readonly signed?: boolean;
  /** Whether the record carries a `supersedes` link. */
  readonly supersedes?: boolean;
  /**
   * A Merkle commitment to size, when the record carries a Merkle batch.
   * Additive to `items` — both may be present.
   */
  readonly merkle?: MerkleShape;
}

// --- field name byte lengths (the canonical encoder keys records by text) ---
const V_KEY = 1; // "v"
const ITEMS_KEY = 5; // "items"
const MERKLE_KEY = 6; // "merkle"
const SUPERSEDES_KEY = 10; // "supersedes"
const SIGS_KEY = 4; // "sigs"
const HASHES_KEY = 6; // "hashes"
const URIS_KEY = 4; // "uris"
const ENC_KEY = 3; // "enc"
const ALG_KEY = 3; // "alg"
const ROOT_KEY = 4; // "root"
const LEAF_COUNT_KEY = 10; // "leaf_count"
const SCHEME_KEY = 6; // "scheme"
const AEAD_KEY = 4; // "aead"
const NONCE_KEY = 5; // "nonce"
const KEM_KEY = 3; // "kem"
const SLOTS_KEY = 5; // "slots"
const SLOTS_MAC_KEY = 9; // "slots_mac"
const EPK_KEY = 3; // "epk"
const KEM_CT_KEY = 6; // "kem_ct"
const WRAP_KEY = 4; // "wrap"
const COSE_SIGN1_KEY = 10; // "cose_sign1"
const PASSPHRASE_KEY = 10; // "passphrase"
const SALT_KEY = 4; // "salt"
const PARAMS_KEY = 6; // "params"
const PARAM_NAME_KEY = 1; // "m" / "t" / "p"

/**
 * A content-hash digest is 32 bytes for every algorithm the publish helpers
 * use (`sha2-256`, `blake2b-256`).
 */
const DIGEST_BYTES = 32;
/**
 * The longest AEAD identifier (`chacha20-poly1305-stream64k`, 27 bytes);
 * charged for any envelope so the bound holds regardless of the exact id.
 */
const AEAD_ID_BYTES = 27;
/** The longest KEM identifier (`mlkem768x25519`, 14 bytes). */
const KEM_ID_BYTES = 14;
/** The sole passphrase-KDF identifier (`argon2id`, 8 bytes). */
const PASSPHRASE_ALG_ID_BYTES = 8;
/**
 * The exact byte length of a detached **path-1** COSE_Sign1, which is fully
 * fixed-shape: a 4-element array (`0x84`) of the 38-byte protected header
 * (`{1: -8, 4: <32-byte kid>}`, encoded as a 40-byte byte string), an empty
 * unprotected header (`0xa0`), a null detached payload (`0xf6`), and the
 * 64-byte Ed25519 signature (encoded as a 66-byte byte string):
 * `1 + 40 + 1 + 1 + 66`.
 */
export const COSE_SIGN1_PATH1_BYTES = 109;
/**
 * The `leaf_count` is unknown at estimate time; the leaf count fits an
 * unsigned 64-bit integer, so the estimate charges the maximum uint header
 * width (9 bytes) — an exact upper bound for any realisable batch.
 */
const MAX_UINT64_BYTES = 9;

/**
 * The `uris` component shared by an item and a merkle commitment: an array of
 * URI strings, or nothing when empty (the field is omitted).
 */
function urisBytes(uris: readonly string[] | undefined): number {
  if (uris === undefined || uris.length === 0) return 0;
  let out = strBytes(URIS_KEY) + containerHeader(uris.length);
  for (const uri of uris) out += strBytes(utf8ByteLength(uri));
  return out;
}

/**
 * The `enc` scheme-1 envelope, by key-delivery path: the slots shape
 * `{scheme, aead, nonce, kem, slots, slots_mac}` (6 keys) plus one slot per
 * recipient, or the passphrase shape
 * `{scheme, aead, nonce, passphrase: {alg, salt, params}}` (4 keys) at the
 * canonical producer widths (see {@link EncShape}).
 */
function envelopeBytes(enc: EncShape): number {
  if (enc.kind === 'kem') {
    const { kem, recipientCount } = enc;
    let env = containerHeader(6); // the 6-key envelope map header
    env += strBytes(SCHEME_KEY) + uintBytes(1); // scheme is the value `1`
    env += strBytes(AEAD_KEY) + strBytes(AEAD_ID_BYTES);
    env += strBytes(NONCE_KEY) + strBytes(ENVELOPE_NONCE_BYTES);
    env += strBytes(KEM_KEY) + strBytes(KEM_ID_BYTES);
    env += strBytes(SLOTS_MAC_KEY) + strBytes(SLOTS_MAC_BYTES);
    // slots: an array of per-recipient 2-key slot maps.
    env += strBytes(SLOTS_KEY) + containerHeader(recipientCount);
    const perSlot =
      kem === 'x25519'
        ? // `{epk: 32, wrap: 48}`
          containerHeader(2) +
          strBytes(EPK_KEY) +
          strBytes(SLOT_EPK_BYTES) +
          strBytes(WRAP_KEY) +
          strBytes(SLOT_WRAP_BYTES)
        : // `{kem_ct: 1120, wrap: 48}`
          containerHeader(2) +
          strBytes(KEM_CT_KEY) +
          strBytes(SLOT_KEM_CT_BYTES) +
          strBytes(WRAP_KEY) +
          strBytes(SLOT_WRAP_BYTES);
    return env + slotsBytes(perSlot, recipientCount);
  }
  // The 4-key passphrase envelope map: no kem, no slots, no slots_mac — the
  // key commitment lives inside the ciphertext blob, not on chain.
  let env = containerHeader(4);
  env += strBytes(SCHEME_KEY) + uintBytes(1); // scheme is the value `1`
  env += strBytes(AEAD_KEY) + strBytes(AEAD_ID_BYTES);
  env += strBytes(NONCE_KEY) + strBytes(ENVELOPE_NONCE_BYTES);
  // passphrase: `{alg, salt, params: {m, t, p}}` at the canonical producer
  // widths — the fixed `argon2id` id, a salt at the registry-floor length, and
  // the registry-floor parameter integers, all read from the crypto layer's
  // authoritative constants (`m`'s floor already charges the full
  // 4-byte-extension uint width, covering every wire-range `m`; `t`/`p` are
  // covered up to CBOR's 1-byte immediate maximum of 23).
  let params = containerHeader(3);
  params += strBytes(PARAM_NAME_KEY) + uintBytes(PASSPHRASE_ARGON2_M_MIN);
  params += strBytes(PARAM_NAME_KEY) + uintBytes(PASSPHRASE_ARGON2_T_MIN);
  params += strBytes(PARAM_NAME_KEY) + uintBytes(PASSPHRASE_ARGON2_P_MIN);
  let block = containerHeader(3);
  block += strBytes(ALG_KEY) + strBytes(PASSPHRASE_ALG_ID_BYTES);
  block += strBytes(SALT_KEY) + strBytes(PASSPHRASE_SALT_MIN_LENGTH);
  block += strBytes(PARAMS_KEY) + params;
  return env + strBytes(PASSPHRASE_KEY) + block;
}

/**
 * The total width of `recipientCount` slots, saturating at
 * `Number.MAX_SAFE_INTEGER`. The recipient count is the estimator's one
 * unbounded numeric input (every other size derives from an in-memory array
 * or string, which cannot approach 2^53): past `Number.MAX_SAFE_INTEGER` the
 * product loses float precision and could round DOWN, silently breaking the
 * upper-bound guarantee. A non-finite, negative, or fractional count is
 * garbage input and pins to the cap too — never-undershoot beats guessing.
 * Any saturated value sits far above `MAX_RECORD_BYTES`, so the only decision
 * a caller takes from it ("does the shape fit under the ceiling") stays
 * correct. Mirrors the saturating estimate arithmetic of the other SDKs.
 */
function slotsBytes(perSlot: number, recipientCount: number): number {
  if (!Number.isSafeInteger(recipientCount) || recipientCount < 0) {
    return Number.MAX_SAFE_INTEGER;
  }
  const total = perSlot * recipientCount;
  return Number.isSafeInteger(total) ? total : Number.MAX_SAFE_INTEGER;
}

/** The encoded width of one `items[i]` map: a `{hashes, uris?, enc?}` map. */
function itemBytes(item: ItemShape): number {
  // The item map carries `hashes` always, then `uris` (when non-empty) and
  // `enc` (when sealed).
  const hasUris = item.uris !== undefined && item.uris.length > 0;
  let itemKeys = 1; // hashes
  if (hasUris) itemKeys += 1;
  if (item.enc !== undefined) itemKeys += 1;
  let out = containerHeader(itemKeys); // the item map header
  // hashes: a map of (alg-id -> 32-byte digest).
  out += strBytes(HASHES_KEY) + containerHeader(item.hashAlgs.length);
  for (const alg of item.hashAlgs) out += strBytes(utf8ByteLength(alg)) + strBytes(DIGEST_BYTES);
  // uris: an array of URI strings.
  out += urisBytes(item.uris);
  // enc: the sealed envelope, when sealed.
  if (item.enc !== undefined) {
    out += strBytes(ENC_KEY) + envelopeBytes(item.enc);
  }
  return out;
}

/**
 * The `merkle` component: a one-entry array of a single
 * `{alg, root, leaf_count, uris?}` commitment.
 */
function merkleBytes(merkle: MerkleShape): number {
  const hasUris = merkle.uris !== undefined && merkle.uris.length > 0;
  // The commitment map carries `alg`, `root`, `leaf_count` always, plus
  // `uris` when non-empty.
  const commitKeys = hasUris ? 4 : 3;
  let commit = containerHeader(commitKeys); // the commitment map header
  commit += strBytes(ALG_KEY) + strBytes(utf8ByteLength(merkle.alg));
  commit += strBytes(ROOT_KEY) + strBytes(DIGEST_BYTES);
  commit += strBytes(LEAF_COUNT_KEY) + MAX_UINT64_BYTES;
  commit += urisBytes(merkle.uris);
  return strBytes(MERKLE_KEY) + containerHeader(1) + commit;
}

/**
 * The exact size of one `sigs[0]` entry: a 1-key `{cose_sign1: <bstr>}` map
 * whose value is the path-1 COSE_Sign1 (`COSE_SIGN1_PATH1_BYTES`). The record
 * stores `cose_sign1` as a single byte string (the whole-body transport-chunk
 * array is reassembled before the record body is encoded), so there is no
 * chunk-array overhead here.
 */
function sigEntryBytes(): number {
  return containerHeader(1) + strBytes(COSE_SIGN1_KEY) + strBytes(COSE_SIGN1_PATH1_BYTES);
}

/**
 * An upper bound on the canonical-CBOR size of the record `shape` describes —
 * guaranteed `>=` the encoded length of the record actually built from the
 * same shape. Feed the result to `POST /poe/quote` as `record_bytes` (and
 * reject shapes above {@link MAX_RECORD_BYTES} before quoting).
 */
export function estimateRecordBytes(shape: RecordShape): number {
  const items = shape.items ?? [];
  // The top-level record map carries `v` always, then `items` (when the
  // record has any items) and/or `merkle` (when it carries a batch), plus
  // optional `supersedes` and `sigs`. Charge the map header for the exact key
  // count.
  let keyCount = 1; // `v`
  if (items.length > 0) keyCount += 1; // `items`
  if (shape.merkle !== undefined) keyCount += 1; // `merkle`
  if (shape.supersedes === true) keyCount += 1;
  if (shape.signed === true) keyCount += 1;

  // The top-level record map header + the `v` key + its `1` value (a 1-byte
  // immediate uint).
  let total = containerHeader(keyCount) + strBytes(V_KEY) + uintBytes(1);

  if (items.length > 0) {
    // `"items"` key + the array header + every item's encoded width.
    total += strBytes(ITEMS_KEY) + containerHeader(items.length);
    for (const item of items) total += itemBytes(item);
  }
  if (shape.merkle !== undefined) {
    total += merkleBytes(shape.merkle);
  }

  if (shape.supersedes === true) {
    // `"supersedes"` key + a 32-byte byte string.
    total += strBytes(SUPERSEDES_KEY) + strBytes(SUPERSEDES_BYTES);
  }

  if (shape.signed === true) {
    // `"sigs"` key + a one-entry array of one `{cose_sign1}` map.
    total += strBytes(SIGS_KEY) + containerHeader(1) + sigEntryBytes();
  }

  return total + SAFETY_MARGIN;
}
