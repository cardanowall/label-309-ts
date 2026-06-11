// Label 309 v1 PoE record Zod schemas.
//
// Scope: structural shape gate over the DECODED record body. The schema
// enforces per-field CBOR types (every map position rejects a CBOR byte
// string — see the text-keyed-map gate below), the fixed byte lengths a field
// can assert in isolation (32-byte `supersedes`, 32-byte `slots_mac`, the
// 16..64-byte passphrase salt), closed-map invariants (`items[i]`,
// `merkle[i]`, `sigs[i]`, `passphrase`), and the `v == 1` literal.
// Cross-field rules (content-hash binding under `enc`, slots/passphrase
// exclusivity, `crit[]` shape, registry membership of algorithm identifiers,
// COSE_Sign1 structural decode, URI shape, non-empty-array rules, integer
// ranges) fire in `validator.ts` so each violation emits its precise
// canonical code rather than a generic schema mismatch.
//
// Every logical byte string is a SINGLE CBOR byte string and every URI is a
// SINGLE text string: record-body fields carry no 64-byte cap and no chunk
// wrappers. The ledger's 64-byte metadata-string cap is satisfied by the
// whole-body transport chunk array alone (see `carriage.ts`), which is
// reassembled before the validator ever sees the body.

import { z } from 'zod';

// =============================================================================
// Text-keyed-map gate
// =============================================================================
//
// Every map position in the record grammar is a CBOR text-keyed map. The
// canonical decoder surfaces such a map as a plain object — but a CBOR byte
// string surfaces as a Uint8Array, which is ALSO an object to Zod, so an
// ungated object schema would walk its byte indices as if they were map keys
// and mis-report one unknown-key issue per byte plus a missing-required issue
// per absent field. The gate runs ahead of the map schema and fails a byte
// string with a SINGLE issue at the position itself — the same one-issue
// rejection every other non-map CBOR shape already receives from the object
// parser; the validator's issue mapper then lifts it to the position's
// canonical code by path. (`z.record` positions need no gate: Zod's record
// parser rejects a Uint8Array outright. A map carrying non-text keys decodes
// to a `Map` and is handled by the validator's pre-guard, not here.)
function textKeyedMap<S extends z.ZodType>(inner: S) {
  return z
    .custom<unknown>((value) => !(value instanceof Uint8Array), {
      message: 'CBOR byte string present where a text-keyed map is required',
    })
    .pipe(inner);
}

// =============================================================================
// Hashes map
// =============================================================================
//
// `hashes` is a non-empty CBOR map keyed by content-hash algorithm identifier
// (a text string from the content-hash registry) with the 32-byte digest as
// value. The canonical decoder surfaces a text-keyed CBOR map as a plain JS
// object — `z.record` admits any string key here. Registry membership
// (`UNSUPPORTED_HASH_ALG`), per-algorithm digest length
// (`HASH_DIGEST_LENGTH_MISMATCH`), and the non-empty rule live in the
// validator's domain pass.

export const HashDigestSchema = z.instanceof(Uint8Array);

export const HashesMapSchema = z.record(z.string(), HashDigestSchema);
export type HashesMap = z.infer<typeof HashesMapSchema>;

// =============================================================================
// URIs
// =============================================================================
//
// One absolute URI in a single text string. Absolute-URI / fragment / scheme
// / per-scheme body rules (`INVALID_URI`) are domain checks.

export const UriSchema = z.string();
export type Uri = z.infer<typeof UriSchema>;

// =============================================================================
// Top-level `merkle[]`
// =============================================================================
//
// Each commit is a closed map `{alg, root, leaf_count, ? uris}`. `alg` is open
// (registry membership → `UNSUPPORTED_MERKLE_COMMIT_ALG` in the domain pass).
// `leaf_count` is a CBOR unsigned integer pinned to `1 .. 2^32 − 1`, handled
// as an EXACT integer: the canonical decoder surfaces values above 2^53 − 1 as
// `bigint`, so the schema admits both representations and the domain pass
// enforces the range (`SCHEMA_MERKLE_LEAF_COUNT_INVALID`) without ever
// rounding through a float.

export const MerkleCommitSchema = textKeyedMap(
  z
    .object({
      alg: z.string(),
      root: z.instanceof(Uint8Array),
      leaf_count: z.union([z.number().int(), z.bigint()]),
      uris: z.array(UriSchema).optional(),
    })
    .strict(),
);
export type MerkleCommit = z.infer<typeof MerkleCommitSchema>;

// =============================================================================
// Encryption envelope
// =============================================================================
//
// The wire `enc` value is a CHOICE between two readings, mirroring the
// grammar's `enc = enc-scheme-1 / enc-opaque`:
//
//   - the scheme-1 shape — the closed map this revision defines, applied by
//     the validator only when `scheme`, `kem`, and `aead` are ALL supported
//     identifiers;
//   - the opaque reading — `scheme` (any CBOR unsigned integer) plus
//     arbitrary text-keyed bounded metadata, the degrade-to-opaque escape
//     hatch for envelopes under identifiers this implementation does not
//     support (`ENC_UNSUPPORTED`).
//
// The choice is not a discriminator: a `scheme: 1` envelope that fails the
// scheme-1 shape is rejected with its typed code, never reclassified as
// opaque. The validator therefore keeps `enc` as `unknown` at the item layer
// and dispatches on raw `scheme` / `kem` / `aead` support before applying
// `EncScheme1Schema`.

// Per-slot recipient entry. The slot shape is KEM-driven:
//
//   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }` — `epk` is the
//     ephemeral X25519 public key.
//   - mlkem768x25519: `{ kem_ct: bstr(1120), wrap: bstr(48) }` — `kem_ct` is
//     the single 1120-byte X-Wing encapsulation; there is NO per-slot `epk`
//     on the hybrid path (the X25519 ephemeral is the trailing 32 bytes of
//     `kem_ct`).
//
// The schema is deliberately PERMISSIVE: all three fields are optional and
// `.strict()` is not applied, because the required shape depends on the
// envelope-level `kem`, which a slot cannot see in isolation. The KEM-driven
// gate in the validator emits the precise codes (`KEM_EPK_LENGTH_MISMATCH`,
// `KEM_CT_LENGTH_MISMATCH`, `WRAP_LENGTH_MISMATCH`, `ENC_SLOT_INVALID_SHAPE`)
// against the RAW decoded slot key set, so cross-KEM contamination and stray
// keys are rejected even though the schema strips nothing here.
export const SlotSchema = textKeyedMap(
  z.object({
    epk: z.instanceof(Uint8Array).optional(),
    kem_ct: z.instanceof(Uint8Array).optional(),
    wrap: z.instanceof(Uint8Array).optional(),
  }),
);
export type Slot = z.infer<typeof SlotSchema>;

// Argon2id params `{m, t, p}` — a closed map of CBOR unsigned integers in the
// pinned `0 .. 2^32 − 1` exact-integer range. The closed-map rule, the range,
// and the floor checks all emit their codes in the validator's domain pass;
// this schema is the public convenience type for producers.
export const Argon2idParamsSchema = textKeyedMap(
  z
    .object({
      m: z.union([z.number().int(), z.bigint()]),
      t: z.union([z.number().int(), z.bigint()]),
      p: z.union([z.number().int(), z.bigint()]),
    })
    .strict(),
);
export type Argon2idParams = z.infer<typeof Argon2idParamsSchema>;

// Passphrase block. `alg` is open (registry membership →
// `ENC_PASSPHRASE_ALG_UNSUPPORTED` in the domain pass); `params` is open here
// (the domain pass narrows on the registered `alg` and emits
// `SCHEMA_UNKNOWN_FIELD` / `SCHEMA_MISSING_REQUIRED` / `SCHEMA_TYPE_MISMATCH`
// / the floor and ceiling codes per sub-field). Salt length bounds are
// schema-layer refinements carrying their dedicated codes.
export const PassphraseBlockSchema = textKeyedMap(
  z
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
    .strict(),
);
export type PassphraseBlock = z.infer<typeof PassphraseBlockSchema>;

// The typed scheme-1 envelope arm. Applied by the validator only when
// `scheme` / `kem` / `aead` are all supported identifiers; under an
// unsupported identifier the envelope takes the opaque reading instead and
// this schema never runs. The map is CLOSED (`.strict()`): an unknown key in
// a supported envelope is `SCHEMA_UNKNOWN_FIELD`, never a reason to fall back
// to the opaque reading. Cross-field key-path invariants (exclusivity,
// `slots` ↔ `slots_mac` ↔ `kem`, non-empty `slots`) are domain checks.
export const EncScheme1Schema = textKeyedMap(
  z
    .object({
      scheme: z.literal(1),
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
    .strict(),
);
export type EncScheme1 = z.infer<typeof EncScheme1Schema>;

// The opaque reading: `scheme` is the only structurally required key (any
// CBOR unsigned integer — `bigint` admits values above 2^53), and every other
// text-keyed entry is unconstrained bounded metadata. A verifier escape
// hatch, never a producer surface.
export const EncOpaqueSchema = textKeyedMap(
  z.looseObject({
    scheme: z.union([z.number().int().nonnegative(), z.bigint().nonnegative()]),
  }),
);
export type EncOpaque = z.infer<typeof EncOpaqueSchema>;

export const EncryptionEnvelopeSchema = z.union([EncScheme1Schema, EncOpaqueSchema]);
export type EncryptionEnvelope = z.infer<typeof EncryptionEnvelopeSchema>;

// =============================================================================
// Item entry
// =============================================================================

export const ItemEntrySchema = textKeyedMap(
  z
    .object({
      hashes: HashesMapSchema,
      uris: z.array(UriSchema).optional(),
      // Captured as `unknown`: the envelope is a union whose disposition
      // (typed scheme-1 vs opaque) depends on identifier support, so the
      // validator's domain pass — not this schema — narrows it.
      enc: z.unknown().optional(),
    })
    .strict(),
);
export type ItemEntry = z.infer<typeof ItemEntrySchema>;

// =============================================================================
// Sig entry
// =============================================================================
//
// Closed CBOR map `{cose_sign1, ? cose_key}`. Each value is a SINGLE byte
// string carrying the CBOR-encoded COSE_Sign1 / COSE_Key. Canonical CBOR
// map-key sort (RFC 8949 §4.2.1, bytewise lex on encoded keys) places
// `cose_key` before `cose_sign1`; schema property order is irrelevant.
export const SigEntrySchema = textKeyedMap(
  z
    .object({
      cose_key: z.instanceof(Uint8Array).optional(),
      cose_sign1: z.instanceof(Uint8Array),
    })
    .strict(),
);
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
// the inferred `PoeRecord["v"]` and emits Zod's `invalid_value` code, which
// the validator's mapper lifts to `SCHEMA_INVALID_LITERAL`.
//
// `looseObject` admits extension keys; the validator's domain pass rejects
// unknown keys that match neither extension namespace with
// `SCHEMA_UNKNOWN_FIELD`.
export const VersionLiteralSchema = z.literal(1);

export const PoeRecordSchema = textKeyedMap(
  z.looseObject({
    v: VersionLiteralSchema,
    items: z.array(ItemEntrySchema).optional(),
    merkle: z.array(MerkleCommitSchema).optional(),
    supersedes: SupersedesSchema.optional(),
    sigs: z.array(SigEntrySchema).optional(),
    crit: z.array(z.string()).optional(),
  }),
);
export type PoeRecord = z.infer<typeof PoeRecordSchema>;

// =============================================================================
// Closed top-level base-key registry
// =============================================================================
//
// Used by the validator's domain pass to distinguish unknown-typo keys from
// well-formed extension keys.
export const TOP_LEVEL_BASE_KEYS: ReadonlySet<string> = new Set([
  'v',
  'items',
  'merkle',
  'supersedes',
  'sigs',
  'crit',
]);

// Extension-key namespaces: `^x-.+` (vendor / experimental) and `^[a-z]+-.+`
// (companion namespace), with control characters (U+0000–U+001F,
// U+007F–U+009F) rejected ANYWHERE in the key — including a trailing newline,
// so `x-note\n` and `x-a\nb` are both outside the namespace. The suffix
// character class spells the exclusion out rather than relying on `.`
// semantics, the literal `x-` / `[a-z]+-` prefixes admit no control
// characters by construction, and `$` in JavaScript matches only at the true
// end of the string, so a trailing newline cannot hide behind the anchor.
// eslint-disable-next-line no-control-regex -- the control-character exclusion IS the admissibility rule
export const EXTENSION_KEY_VENDOR_RE = /^x-[^\u0000-\u001f\u007f-\u009f]+$/;
// eslint-disable-next-line no-control-regex -- the control-character exclusion IS the admissibility rule
export const EXTENSION_KEY_COMPANION_RE = /^[a-z]+-[^\u0000-\u001f\u007f-\u009f]+$/;

export function isExtensionKey(k: string): boolean {
  return EXTENSION_KEY_VENDOR_RE.test(k) || EXTENSION_KEY_COMPANION_RE.test(k);
}
