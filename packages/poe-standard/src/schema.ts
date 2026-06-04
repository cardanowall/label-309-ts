// Label 309 v1 PoE record Zod schemas.
//
// Scope: structural shape gate. The schema enforces per-field types, length
// bounds (chunk size, digest length, supersedes length, nonce length,
// passphrase salt length), closed-map invariants (`sigs[i]`, `slot`,
// `passphrase`, `merkle[i]`), and the `v == 1` literal. Cross-field rules
// (item.hashes content-hash binding when `enc` present, slots/passphrase
// exclusivity, `crit[]` shape, registry membership of algorithm
// identifiers, COSE_Sign1 structural decode, URI per-scheme shape rules)
// fire in `validator.ts` so the validator can emit the precise structural
// codes (`UNSUPPORTED_*_ALG`, `ENC_*`, `SIG_*`, `INVALID_URI`,
// `CRIT_SHAPE_INVALID`, …) rather than a generic schema-mismatch.
//
// Refinements that DO live in the schema (because the validator's domain
// pass lifts these as `SCHEMA_*` / `*_LENGTH_MISMATCH` codes directly):
//   - chunk size `[1, 64]` → `CHUNK_TOO_LARGE`
//   - 32-byte digest / 32-byte root / 32-byte supersedes → `HASH_DIGEST_LENGTH_MISMATCH`
//     / `SUPERSEDES_TX_INVALID_LENGTH`
//   - 24-byte nonce / 32-byte slots_mac →
//     `NONCE_LENGTH_MISMATCH` / `ENC_SLOTS_MAC_INVALID_LENGTH`
//   - passphrase salt 16..64 bytes → `ENC_PASSPHRASE_SALT_TOO_SHORT` /
//     `ENC_PASSPHRASE_SALT_TOO_LONG`
//
// Per-slot recipient lengths (`epk`, `kem_ct`, `wrap`) are NOT enforced here:
// the required slot shape depends on the envelope-level `kem`, which a slot
// cannot see in isolation. The KEM-driven slot descriptor in `validator.ts`
// emits the precise `KEM_EPK_LENGTH_MISMATCH` / `KEM_CT_LENGTH_MISMATCH` /
// `WRAP_LENGTH_MISMATCH` / `ENC_SLOT_INVALID_SHAPE` codes instead.

import { z } from 'zod';

// =============================================================================
// Chunked-bytes / chunked-text arrays
// =============================================================================

// `[1* bstr .size (1..64)]`. A zero-length chunk (0 < 1) is rejected with the
// SAME `CHUNK_TOO_LARGE` code as oversized chunks (any length outside
// `[1, 64]`).
export const ChunkedBytesArraySchema = z
  .array(
    z.instanceof(Uint8Array).refine((b) => b.length >= 1 && b.length <= 64, {
      params: { code: 'CHUNK_TOO_LARGE' },
    }),
  )
  .min(1);
export type ChunkedBytesArray = z.infer<typeof ChunkedBytesArraySchema>;

// `[1* tstr .size (1..64)]` — chunk byte length is the UTF-8-encoded length
// (each `tstr` is wire-encoded as UTF-8). The `tstr .size (1..64)` pin is a
// byte-count constraint, not a code-unit constraint.
const UTF8_ENCODER = new TextEncoder();
export const UriChunkArraySchema = z
  .array(
    z.string().refine(
      (s) => {
        const n = UTF8_ENCODER.encode(s).length;
        return n >= 1 && n <= 64;
      },
      { params: { code: 'CHUNK_TOO_LARGE' } },
    ),
  )
  .min(1);
export type UriChunkArray = z.infer<typeof UriChunkArraySchema>;

// =============================================================================
// Hashes map
// =============================================================================
//
// `hashes` is a non-empty CBOR map keyed by content-hash algorithm identifier
// (a CBOR text string from the content-hash registry) with the 32-byte digest
// as value. cbor2 surfaces a text-keyed CBOR map as a plain JS object — z.record
// admits any string key here. Both the registry-membership check
// (`UNSUPPORTED_HASH_ALG`) and the per-algorithm digest-length check
// (`HASH_DIGEST_LENGTH_MISMATCH`) live in the validator's domain pass so
// each violation emits its precise code; the schema only enforces the
// value is a CBOR byte string.

export const HashDigestSchema = z.instanceof(Uint8Array);

export const HashesMapSchema = z.record(z.string(), HashDigestSchema);
export type HashesMap = z.infer<typeof HashesMapSchema>;

// =============================================================================
// Top-level `merkle[]`
// =============================================================================
//
// Each commit is a closed map `{alg, root, leaf_count, ? uris}`. `alg` is open
// (registry membership is enforced in the validator's domain pass — unknown
// identifiers emit `UNSUPPORTED_MERKLE_COMMIT_ALG`).

export const MerkleCommitSchema = z
  .object({
    alg: z.string(),
    root: z.instanceof(Uint8Array),
    leaf_count: z.number().int().min(1),
    uris: z.array(UriChunkArraySchema).min(1).optional(),
  })
  .strict();
export type MerkleCommit = z.infer<typeof MerkleCommitSchema>;

// =============================================================================
// Encryption envelope
// =============================================================================

// Per-slot recipient entry. The slot shape is KEM-driven:
//
//   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }` — `epk` is the
//     ephemeral X25519 public key, `wrap` is the 32-byte CEK + 16-byte
//     ChaCha20-Poly1305 tag.
//   - mlkem768x25519: `{ kem_ct: [ bstr .size (1..64) ], wrap: bstr(48) }` —
//     `kem_ct` is the 1120-byte X-Wing `enc` carried as a chunked byte-string
//     array (the same `bytes-chunk-array` shape `sigs[i].cose_sign1` uses);
//     there is NO per-slot `epk` on the hybrid path.
//
// The `kem` identifier is hoisted to envelope scope (a per-slot `kem` would
// be wire-bloat). The schema is deliberately PERMISSIVE:
// `epk`, `kem_ct`, and `wrap` are all optional and `.strict()` is NOT applied.
// Both the per-field length checks (`KEM_EPK_LENGTH_MISMATCH`,
// `KEM_CT_LENGTH_MISMATCH`, `WRAP_LENGTH_MISMATCH`) and the KEM-driven
// shape gate (which field MUST/MUST NOT be present for the declared `kem`,
// emitting `ENC_SLOT_INVALID_SHAPE`) live in the validator's domain pass —
// the structural schema cannot know the envelope `kem` from a slot in
// isolation, and we want the precise KEM-aware code rather than a generic
// schema mismatch. Because `.strict()` is dropped, the domain pass MUST
// explicitly reject cross-KEM contamination (an x25519 slot carrying
// `kem_ct`, or a hybrid slot carrying `epk`).
export const SlotSchema = z.object({
  epk: z.instanceof(Uint8Array).optional(),
  kem_ct: ChunkedBytesArraySchema.optional(),
  wrap: z.instanceof(Uint8Array).optional(),
});
export type Slot = z.infer<typeof SlotSchema>;

// Argon2id params `{m, t, p}` are a closed map. Each value MUST be a CBOR
// unsigned integer; the FLOOR check (`m ≥ 65536`,
// `t ≥ 3`, `p ≥ 1`) emits `ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW` in the
// validator's domain pass — keeping it out of the schema lets us emit the
// distinct salt-length code when salt itself is malformed too.
export const Argon2idParamsSchema = z
  .object({
    m: z.number().int(),
    t: z.number().int(),
    p: z.number().int(),
  })
  .strict();
export type Argon2idParams = z.infer<typeof Argon2idParamsSchema>;

// Passphrase block. `alg` is open (registry membership checked in the
// validator's domain pass → `ENC_PASSPHRASE_ALG_UNSUPPORTED`);
// `params` is open here (validator narrows on the registered `alg` value and
// emits `SCHEMA_UNKNOWN_FIELD` for extra keys, `ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW`
// for sub-floor values). `salt` length floor/ceiling are schema-layer
// refinements with the dedicated `ENC_PASSPHRASE_SALT_TOO_SHORT/TOO_LONG`
// codes — they belong at the schema layer because a slot cannot otherwise
// see the salt length.
export const PassphraseBlockSchema = z
  .object({
    alg: z.string(),
    salt: z.instanceof(Uint8Array).superRefine((bytes, ctx) => {
      if (bytes.length < 16) {
        ctx.addIssue({
          code: 'custom',
          path: [],
          message: `passphrase.salt length ${bytes.length} < 16`,
          params: { code: 'ENC_PASSPHRASE_SALT_TOO_SHORT' },
        });
      } else if (bytes.length > 64) {
        ctx.addIssue({
          code: 'custom',
          path: [],
          message: `passphrase.salt length ${bytes.length} > 64`,
          params: { code: 'ENC_PASSPHRASE_SALT_TOO_LONG' },
        });
      }
    }),
    params: z.record(z.string(), z.unknown()),
  })
  .strict();
export type PassphraseBlock = z.infer<typeof PassphraseBlockSchema>;

// Sealed-PoE envelope. The wire format admits any combination of
// `kem` / `slots` / `slots_mac` / `passphrase` keys (permissive superset);
// cross-field invariants (slots ⊕ passphrase, slots ↔ slots_mac, slots
// requires kem, content-hash binding, slots non-empty) are enforced in the
// validator's domain pass so each violation emits its typed code rather
// than a generic shape mismatch.
export const EncryptionEnvelopeSchema = z
  .object({
    scheme: z.unknown(),
    aead: z.string(),
    kem: z.string().optional(),
    nonce: z.instanceof(Uint8Array),
    slots: z.array(SlotSchema).optional(),
    slots_mac: z
      .instanceof(Uint8Array)
      .refine((b) => b.length === 32, {
        params: { code: 'ENC_SLOTS_MAC_INVALID_LENGTH' },
      })
      .optional(),
    passphrase: PassphraseBlockSchema.optional(),
  })
  .strict();
export type EncryptionEnvelope = z.infer<typeof EncryptionEnvelopeSchema>;

// =============================================================================
// Item entry
// =============================================================================

export const ItemEntrySchema = z
  .object({
    hashes: HashesMapSchema,
    uris: z.array(UriChunkArraySchema).min(1).optional(),
    // Captured as `unknown` so the validator can run the
    // `ENC_REQUIRES_CONTENT_HASH` pre-check ahead of any inner-shape errors
    // and surface the most informative code first.
    enc: z.unknown().optional(),
  })
  .strict();
export type ItemEntry = z.infer<typeof ItemEntrySchema>;

// =============================================================================
// Sig entry
// =============================================================================
//
// Closed CBOR map `{cose_sign1, ? cose_key}`. Canonical CBOR map-key sort
// (RFC 8949 §4.2.1, bytewise lex on encoded keys) places `cose_key`
// (length-8 tstr, `0x68`) BEFORE `cose_sign1` (length-10 tstr, `0x6a`); the
// schema property-order is irrelevant — the canonical encoder handles it.
export const SigEntrySchema = z
  .object({
    cose_key: ChunkedBytesArraySchema.optional(),
    cose_sign1: ChunkedBytesArraySchema,
  })
  .strict();
export type SigEntry = z.infer<typeof SigEntrySchema>;

// =============================================================================
// Supersedence
// =============================================================================

export const SupersedesSchema = z.instanceof(Uint8Array).refine((b) => b.length === 32, {
  params: { code: 'SUPERSEDES_TX_INVALID_LENGTH' },
});
export type Supersedes = z.infer<typeof SupersedesSchema>;

// =============================================================================
// Top-level record
// =============================================================================
//
// `v == 1` is a literal — a future major (`v: 2`) MUST be rejected with
// `SCHEMA_INVALID_LITERAL`. `z.literal(1)` preserves the narrow `1` type for
// the inferred `PoeRecord["v"]` (so consumers can dispatch on it) and emits
// Zod's `invalid_value` code which the validator's mapper lifts to
// `SCHEMA_INVALID_LITERAL`.
//
// `looseObject` admits extension keys (matching `^x-.+` or `^[a-z]+-.+`); the
// validator's domain pass rejects unknown keys that match neither pattern with
// `SCHEMA_UNKNOWN_FIELD`.
export const VersionLiteralSchema = z.literal(1);

export const PoeRecordSchema = z.looseObject({
  v: VersionLiteralSchema,
  items: z.array(ItemEntrySchema).optional(),
  merkle: z.array(MerkleCommitSchema).optional(),
  supersedes: SupersedesSchema.optional(),
  sigs: z.array(SigEntrySchema).optional(),
  crit: z.array(z.string()).optional(),
});
export type PoeRecord = z.infer<typeof PoeRecordSchema>;

// =============================================================================
// Closed top-level base-key registry
// =============================================================================
//
// Used by the validator's domain pass to distinguish unknown-typo keys from
// well-formed extension keys (`^x-.+` / `^[a-z]+-.+`).
export const TOP_LEVEL_BASE_KEYS: ReadonlySet<string> = new Set([
  'v',
  'items',
  'merkle',
  'supersedes',
  'sigs',
  'crit',
]);

// Extension-key namespaces. Anchored at both ends so an
// embedded newline cannot smuggle a multi-segment key past the check: `.`
// excludes `\n` in JS, and the `\n?$` tail tolerates exactly ONE trailing
// newline (matching the Python validator's `re.fullmatch(r'^(x-.+|[a-z]+-.+)$')`
// semantics, where `$` likewise admits a single trailing `\n`). So `x-note\n`
// is an extension key, but `x-a\nb`, `x-note\n\n`, and `x-\n` are not.
export const EXTENSION_KEY_VENDOR_RE = /^x-.+\n?$/;
export const EXTENSION_KEY_COMPANION_RE = /^[a-z]+-.+\n?$/;

export function isExtensionKey(k: string): boolean {
  return EXTENSION_KEY_VENDOR_RE.test(k) || EXTENSION_KEY_COMPANION_RE.test(k);
}
