// Label 309 v1 structural validator (the Part A structural-validation role).
//
// Pure function over the reassembled CBOR record body — performs no I/O,
// opens no socket, verifies no signature cryptographically, decodes no
// ciphertext. Chain resolution, URI fetching, decryption, and
// confirmation-depth checks are the verifier's concern (the Part B role).
// The transport chunk array is reassembled BEFORE this function runs (see
// `carriage.ts`); the carriage codes (`CHUNK_TOO_LARGE`, the transport
// `MALFORMED_CBOR` reuse) are emitted by that step, not here.
//
// Pipeline:
//   Step 1  Canonical CBOR decode — `decodeCanonicalCbor` surfaces malformed /
//           non-canonical / duplicate-key / indefinite-length inputs as the
//           single MALFORMED_CBOR code.
//   Step 2  Schema parse — the closed Zod shapes in `./schema.ts`; the mapper
//           below lifts each Zod issue to its canonical structural code.
//   Step 3  Domain checks — cross-field rules, registry membership, URI shape
//           (the offline CID profile), the encryption-envelope union
//           (typed scheme-1 vs the degrade-to-opaque reading), `sigs[i]`
//           COSE_Sign1 structural decode, `crit[]` shape, exact-integer
//           range enforcement.
//   Step 4  Result emission — every collected issue is sorted (path
//           segment-wise, registry-order tie-break) and the record is valid
//           iff no error-severity issue is present.
//
// The validator NEVER throws — failure paths route through the discriminated
// `ValidationResult` union so callers handle errors as data, and its output
// is deterministic for any given `(bytes, options)` pair.

import { z } from 'zod';

import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type CanonicalCborValue,
} from '@cardanowall/crypto-core/cbor';
import { CoseVerifyError, decodeCoseSign1 } from '@cardanowall/crypto-core/cose';
// The verifier resource bounds the sealed-PoE unwrap layer enforces. Importing
// the same constants, rather than re-declaring them, makes the structural
// validator and the unwrap layer default to identical thresholds. Both are
// deployment-pinned reference values, not wire fields — `ValidatorOptions`
// overrides them per deployment.
import { MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS } from '@cardanowall/crypto-core/sealed-poe';

import { SEVERITY, errorCodeRegistryIndex, type ErrorCode, type Severity } from './error-codes';
import {
  EncScheme1Schema,
  isExtensionKey,
  PoeRecordSchema,
  TOP_LEVEL_BASE_KEYS,
  type EncScheme1,
  type ItemEntry,
  type MerkleCommit,
  type PassphraseBlock,
  type PoeRecord,
  type SigEntry,
  type Slot,
} from './schema';

// =============================================================================
// Registries (closed catalogue of this implementation)
// =============================================================================

// Content-hash algorithm registry. Map value = digest length.
const HASH_ALG_LENGTHS: Readonly<Record<string, number>> = {
  'sha2-256': 32,
  'blake2b-256': 32,
};

// Merkle list-commitment algorithm registry. Map value = root length.
const MERKLE_COMMIT_ALG_LENGTHS: Readonly<Record<string, number>> = {
  'rfc9162-sha256': 32,
};

// Content-format (AEAD) registry. Value = the registered `enc.nonce` length.
const AEAD_NONCE_LENGTHS: Readonly<Record<string, number>> = {
  'chacha20-poly1305-stream64k': 24,
};

// Unauthenticated-cipher family. An `enc.aead` naming any of these is rejected
// with `UNAUTHENTICATED_CIPHER_FORBIDDEN` in EVERY role — a forbidden
// primitive is a recognised hazard, not an unknown identifier, so it never
// takes the degrade-to-opaque reading. Two arms:
//   - block-cipher modes with no integrity (`cbc`, `ctr`, `ecb`, `cfb`,
//     `ofb`) appearing as a delimited token, matching every key-size spelling
//     (`aes-cbc`, `aes-256-cbc`, `des-ede3-cbc`, …);
//   - legacy stream/block ciphers as a leading token (`rc4`, `des`, `3des`).
// The token delimiters keep authenticated AEADs (`aes-256-gcm`,
// `chacha20-poly1305-stream64k`) from matching.
const UNAUTHENTICATED_CIPHER_RE =
  /(?:^|[-_])(?:cbc|ctr|ecb|cfb|ofb)(?:[-_]|$)|^(?:rc4|des|3des)(?:[-_]|$)/i;

// KEM registry, expressed as a per-KEM slot DESCRIPTOR. Each registered KEM
// pins the exact recipient-slot shape:
//
//   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }` — classical
//     ephemeral-static X25519.
//   - mlkem768x25519: `{ kem_ct: bstr(1120), wrap: bstr(48) }` — the X-Wing
//     hybrid; the encapsulation is a SINGLE 1120-byte byte string and there
//     is NO per-slot `epk` (the X25519 ephemeral is the trailing 32 bytes of
//     `kem_ct`).
//
// A descriptor declares the slot's ciphertext-bearing field and its exact
// byte length; `wrap` is 48 bytes for every KEM (32-byte CEK + 16-byte AEAD
// tag). The validator branches on the descriptor so adding a future KEM is a
// registry edit, not a new code path.
type KemSlotField = 'epk' | 'kem_ct';
interface KemSlotDescriptor {
  readonly field: KemSlotField;
  readonly fieldLength: number;
  readonly wrapLength: number;
}
const KEM_SLOT_DESCRIPTORS: Readonly<Record<string, KemSlotDescriptor>> = {
  x25519: { field: 'epk', fieldLength: 32, wrapLength: 48 },
  mlkem768x25519: { field: 'kem_ct', fieldLength: 1120, wrapLength: 48 },
};

const KEM_FIELD_LENGTH_CODE: Readonly<Record<KemSlotField, ErrorCode>> = {
  epk: 'KEM_EPK_LENGTH_MISMATCH',
  kem_ct: 'KEM_CT_LENGTH_MISMATCH',
};

// Passphrase KDF registry.
const PASSPHRASE_KDF_ALGS: ReadonlySet<string> = new Set(['argon2id']);

// Signature-algorithm registry: COSE `alg` labels. `-8` (EdDSA, pinned to
// Ed25519) is the mandatory baseline; `-19` (Ed25519 fully-specified) is
// verified identically when accepted. Anything else is tagged
// `SIGNATURE_UNSUPPORTED` (info-severity) — signatures are optional, so an
// unrecognised algorithm never fails the record by itself.
const KNOWN_SIG_ALG_IDS: ReadonlySet<number> = new Set([-8, -19]);

// Every numeric wire field is a CBOR unsigned integer pinned to this range
// and handled as an EXACT integer (the canonical decoder surfaces values
// above 2^53 − 1 as `bigint`, so no precision is ever lost before the range
// check rejects).
const UINT32_MAX = 0xffff_ffff;

// =============================================================================
// Options
// =============================================================================

export type ValidatorRole = 'public' | 'recipient_or_strict';

export interface Argon2ParamsCeiling {
  readonly m: number;
  readonly t: number;
  readonly p: number;
}

// The reference deployment ceiling on Argon2id work factors — a verifier-side
// denial-of-service backstop (a 64 GiB `m` must not be able to stall a
// decrypt-on-paste consumer), enforced by default and distinct from the
// normative floors. Ceilings are deployment policy, not a wire rule: override
// per deployment, or pass `passphraseParamsCeiling: null` to disable.
export const DEFAULT_PASSPHRASE_PARAMS_CEILING: Argon2ParamsCeiling = Object.freeze({
  m: 2_097_152, // KiB = 2 GiB
  t: 16,
  p: 8,
});

export interface ValidatorOptions {
  /**
   * Names of the critical extensions this validator implements. Default: the
   * empty set — a default-configured validator therefore fails every
   * `crit`-bearing record with `EXTENSION_UNSUPPORTED_CRITICAL`, by design.
   */
  readonly supportedCriticalExtensions?: ReadonlySet<string>;
  /**
   * The validation reading for dual-severity envelope dispositions.
   * `public` (default): an envelope under an unsupported `scheme` / `kem` /
   * `aead` degrades to opaque and `ENC_UNSUPPORTED` is informational.
   * `recipient_or_strict` (the recipient verifier and strict sealed-crypto
   * mode): the same condition is a hard reject — `ENC_UNSUPPORTED` escalates
   * to `error` and co-fires with the identifier-specific `UNSUPPORTED_*`
   * code.
   */
  readonly role?: ValidatorRole;
  /** Slot-count resource bound (reference bound 1024; deployments MAY tighten). */
  readonly maxSlots?: number;
  /** Decoded-envelope byte resource bound (reference bound 65536). */
  readonly maxEncEnvelopeBytes?: number;
  /**
   * Upper policy ceiling on Argon2id parameters
   * (`ENC_PASSPHRASE_PARAMS_EXCEED_POLICY`). Defaults to
   * `DEFAULT_PASSPHRASE_PARAMS_CEILING`; `null` disables the ceiling.
   */
  readonly passphraseParamsCeiling?: Argon2ParamsCeiling | null;
}

interface ResolvedOptions {
  readonly supportedCriticalExtensions: ReadonlySet<string>;
  readonly role: ValidatorRole;
  readonly maxSlots: number;
  readonly maxEncEnvelopeBytes: number;
  readonly passphraseParamsCeiling: Argon2ParamsCeiling | null;
}

const EMPTY_EXTENSION_SET: ReadonlySet<string> = new Set();

function resolveOptions(options?: ValidatorOptions): ResolvedOptions {
  return {
    supportedCriticalExtensions: options?.supportedCriticalExtensions ?? EMPTY_EXTENSION_SET,
    role: options?.role ?? 'public',
    maxSlots: options?.maxSlots ?? MAX_SLOTS,
    maxEncEnvelopeBytes: options?.maxEncEnvelopeBytes ?? MAX_DECODED_ENVELOPE_BYTES,
    passphraseParamsCeiling:
      options?.passphraseParamsCeiling === undefined
        ? DEFAULT_PASSPHRASE_PARAMS_CEILING
        : options.passphraseParamsCeiling,
  };
}

// =============================================================================
// Result types
// =============================================================================

export interface ValidationIssue {
  /**
   * Segments from the record root: text map keys and integer array indices
   * (e.g. `["items", 0, "hashes", "sha2-256"]`). A dotted string is a display
   * rendering only — the segment list is the API form, so map keys containing
   * `.` need no escaping.
   */
  readonly path: ReadonlyArray<string | number>;
  readonly code: ErrorCode;
  readonly severity: Severity;
  readonly message: string;
}

export type ValidationResult =
  | {
      readonly valid: true;
      readonly record: PoeRecord;
      readonly warnings?: ReadonlyArray<ValidationIssue>;
      readonly info?: ReadonlyArray<ValidationIssue>;
    }
  | { readonly valid: false; readonly issues: ReadonlyArray<ValidationIssue> };

// =============================================================================
// Public entry point
// =============================================================================

export function validatePoeRecord(bytes: Uint8Array, options?: ValidatorOptions): ValidationResult {
  const opts = resolveOptions(options);

  // Step 1 — canonical CBOR decode. Every decode failure surfaces as the
  // single MALFORMED_CBOR code: malformed/truncated bytes, indefinite-length
  // (streaming) encodings, non-canonical map-key ordering, duplicate map
  // keys, non-minimal integers, and invalid UTF-8. There is no separate
  // duplicate-key code — canonical-decode rejection covers it.
  let decoded: unknown;
  try {
    decoded = decodeCanonicalCbor(bytes);
  } catch (cause) {
    return {
      valid: false,
      issues: [
        {
          code: 'MALFORMED_CBOR',
          path: [],
          message: cause instanceof Error ? cause.message : String(cause),
          severity: 'error',
        },
      ],
    };
  }

  // Step 2 pre-guard — non-text map keys. Every map at a typed grammar
  // position is text-keyed; the canonical decoder surfaces a map carrying any
  // non-text key as a `Map` (an all-text-key map decodes to a plain object).
  // A `Map` is still a JS object, so an object schema run over it would read
  // its (absent) named properties and mis-report every required field as
  // missing — the violation is detected here instead and attributed at the
  // containing map as SCHEMA_TYPE_MISMATCH, foreclosing the parse the same
  // way any other unparseable shape does.
  const nonTextKeyIssues = collectNonTextKeyMapIssues(decoded);
  if (nonTextKeyIssues.length > 0) {
    return { valid: false, issues: sortIssues(nonTextKeyIssues) };
  }

  // Step 2 — schema parse. A failed parse forecloses the domain pass (there
  // is no typed record to walk); its issues are emitted sorted.
  const parse = PoeRecordSchema.safeParse(decoded);
  if (!parse.success) {
    return { valid: false, issues: sortIssues(mapZodIssues(parse.error.issues, decoded)) };
  }

  // Step 3 — domain checks. Issues of every severity are collected together;
  // no error-severity issue stops the walk.
  const record = parse.data;
  const issues: ValidationIssue[] = [];

  checkContentCommitmentPresence(record, issues);

  // `crit[]` shape rules run before the per-entry support check.
  const decodedTopKeys = topLevelKeysOf(decoded);
  checkCrit(record, decodedTopKeys, opts.supportedCriticalExtensions, issues);

  // Unknown top-level fields: keys outside the base set that match neither
  // extension-key namespace (typos, control-character keys).
  for (const key of decodedTopKeys) {
    if (TOP_LEVEL_BASE_KEYS.has(key)) continue;
    if (isExtensionKey(key)) continue;
    issues.push(issueOf('SCHEMA_UNKNOWN_FIELD', [key], `unknown top-level field: ${key}`));
  }

  const items = record.items ?? [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i]!;
    checkItemHashes(item, i, issues);
    if (item.uris !== undefined) checkUris(item.uris, ['items', i, 'uris'], issues);
    if (item.enc !== undefined) checkItemEnc(item, i, opts, issues);
  }

  const merkle = record.merkle ?? [];
  for (let i = 0; i < merkle.length; i++) {
    checkMerkleCommit(merkle[i]!, i, issues);
  }

  if (record.sigs !== undefined) {
    if (record.sigs.length === 0) {
      issues.push(
        issueOf('SCHEMA_TYPE_MISMATCH', ['sigs'], 'sigs[] must be non-empty when present'),
      );
    }
    for (let i = 0; i < record.sigs.length; i++) {
      checkSigEntry(record.sigs[i]!, i, issues);
    }
  }

  // Step 4 — result emission. The full issue list is sorted once (path
  // segment-wise, registry-order tie-break); the record is valid iff no
  // error-severity issue is present, and warnings / info never fail it.
  const sorted = sortIssues(issues);
  if (sorted.some((issue) => issue.severity === 'error')) {
    return { valid: false, issues: sorted };
  }
  const warnings = sorted.filter((issue) => issue.severity === 'warning');
  const info = sorted.filter((issue) => issue.severity === 'info');
  const result: {
    valid: true;
    record: PoeRecord;
    warnings?: ReadonlyArray<ValidationIssue>;
    info?: ReadonlyArray<ValidationIssue>;
  } = { valid: true, record };
  if (warnings.length > 0) result.warnings = warnings;
  if (info.length > 0) result.info = info;
  return result;
}

// =============================================================================
// Step 2 helpers — Zod issue → structural-code mapping
// =============================================================================

// Lift a Zod issue list to canonical structural issues. An
// `unrecognized_keys` issue names every stray key of one closed map in a
// single Zod issue; it is expanded here into one canonical issue per key,
// attributed at the key itself — the same per-key attribution the domain
// pass uses for closed maps it walks by hand.
function mapZodIssues(
  zissues: ReadonlyArray<z.core.$ZodIssue>,
  decodedRoot?: unknown,
): ValidationIssue[] {
  const out: ValidationIssue[] = [];
  for (const zissue of zissues) {
    if (zissue.code === 'unrecognized_keys') {
      for (const key of zissue.keys) {
        const path = [...(zissue.path as ReadonlyArray<string | number>), key];
        const code = unknownKeyCode(path);
        out.push(issueOf(code, path, `unrecognized key '${key}' in a closed map`));
      }
      continue;
    }
    out.push(mapZodIssue(zissue, decodedRoot));
  }
  return out;
}

// The canonical code for a stray key, by position: a stray key inside a
// `sigs[i]` entry violates the sig-entry closed-map rule; everywhere else a
// stray key in a closed map is the generic SCHEMA_UNKNOWN_FIELD. (Slot maps
// never reach this dispatch — their schema is permissive and the KEM-driven
// domain gate emits ENC_SLOT_INVALID_SHAPE for stray slot keys.)
function unknownKeyCode(path: ReadonlyArray<string | number>): ErrorCode {
  if (path.length >= 2 && path[0] === 'sigs' && typeof path[1] === 'number') {
    return 'SIG_ENTRY_INVALID_SHAPE';
  }
  return 'SCHEMA_UNKNOWN_FIELD';
}

// Non-text-key detection over the typed grammar positions reachable from the
// record root: the root map, each `items[i]` / `merkle[i]` / `sigs[i]` entry,
// and the `hashes` / `enc` maps inside an item. Positions inside extension
// values are deliberately NOT walked — extension values admit any CBOR value
// the canonical profile allows, integer-keyed maps included. The interior of
// a supported `enc` envelope is scanned by the envelope dispatch itself (the
// opaque reading likewise admits arbitrary extension values).
function collectNonTextKeyMapIssues(decoded: unknown): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const flag = (path: ReadonlyArray<string | number>): void => {
    issues.push(
      issueOf(
        'SCHEMA_TYPE_MISMATCH',
        path,
        'CBOR map carries a non-text key where a text-keyed map is required',
      ),
    );
  };
  if (decoded instanceof Map) {
    flag([]);
    return issues;
  }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) return issues;
  const record = decoded as Record<string, unknown>;
  for (const field of ['items', 'merkle', 'sigs'] as const) {
    const entries = record[field];
    if (!Array.isArray(entries)) continue;
    entries.forEach((entry, i) => {
      if (entry instanceof Map) {
        flag([field, i]);
        return;
      }
      if (field !== 'items' || entry === null || typeof entry !== 'object') return;
      const item = entry as Record<string, unknown>;
      if (item['hashes'] instanceof Map) flag([field, i, 'hashes']);
      if (item['enc'] instanceof Map) flag([field, i, 'enc']);
    });
  }
  return issues;
}

function mapZodIssue(zissue: z.core.$ZodIssue, decodedRoot?: unknown): ValidationIssue {
  const path = zissue.path as ReadonlyArray<string | number>;
  // Refinements with an explicit `params.code` win unconditionally — they are
  // the canonical taxonomy code attached at schema-definition time
  // (SUPERSEDES_TX_INVALID_LENGTH, ENC_SLOTS_MAC_INVALID_LENGTH, the salt
  // bounds).
  const explicit = (zissue as { params?: { code?: string } }).params?.code as ErrorCode | undefined;
  if (explicit !== undefined) {
    return issueOf(explicit, path, zissue.message);
  }

  const valueAtIssue = valueAtPath(decodedRoot, path);

  // A CBOR map carrying any non-text key decodes to a `Map` (an all-text-key
  // map decodes to a plain object), and every registered map position in the
  // grammar is text-keyed — so a `Map` anywhere a registered map is expected
  // is a non-text-key violation, reported as SCHEMA_TYPE_MISMATCH at the
  // containing map regardless of which position it sits in.
  if (valueAtIssue instanceof Map) {
    return issueOf(
      'SCHEMA_TYPE_MISMATCH',
      path,
      'CBOR map carries a non-text key where a text-keyed map is required',
    );
  }

  // Path-based dispatch:
  //   `sigs[i]…` → SIG_ENTRY_INVALID_SHAPE (the sig-entry closed-map rule)
  //   a slot element or a field within a slot → ENC_SLOT_INVALID_SHAPE
  //   `v` literal mismatch / missing → SCHEMA_INVALID_LITERAL vs
  //     SCHEMA_MISSING_REQUIRED.
  const inSigsEntry = path.length >= 2 && path[0] === 'sigs' && typeof path[1] === 'number';

  // The typed envelope parse runs with the `enc` map as its root, so a slot
  // issue arrives with the relative path `slots[j]…`; `checkItemEnc` prefixes
  // the `items[i].enc` segments afterwards. (The top-level record parse never
  // descends into `enc` — the item schema holds it as `unknown` for the
  // typed-vs-opaque dispatch.)
  const isInSlotEntry = path.length >= 2 && path[0] === 'slots' && typeof path[1] === 'number';

  const isMissing = valueAtIssue === undefined;

  switch (zissue.code) {
    case 'invalid_type':
      if (isInSlotEntry) return issueOf('ENC_SLOT_INVALID_SHAPE', path, zissue.message);
      if (isMissing) {
        if (inSigsEntry) return issueOf('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
        return issueOf('SCHEMA_MISSING_REQUIRED', path, zissue.message);
      }
      if (inSigsEntry) return issueOf('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
      return issueOf('SCHEMA_TYPE_MISMATCH', path, zissue.message);
    case 'invalid_value':
      // `z.literal(1)` emits `invalid_value` for both a missing field AND a
      // present-but-wrong value; disambiguate via the runtime value.
      if (isMissing) return issueOf('SCHEMA_MISSING_REQUIRED', path, zissue.message);
      return issueOf('SCHEMA_INVALID_LITERAL', path, zissue.message);
    case 'invalid_union':
    case 'invalid_format':
    case 'too_big':
    case 'too_small':
    case 'invalid_key':
    case 'invalid_element':
    case 'custom':
    default:
      if (isInSlotEntry) return issueOf('ENC_SLOT_INVALID_SHAPE', path, zissue.message);
      if (inSigsEntry) return issueOf('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
      return issueOf('SCHEMA_TYPE_MISMATCH', path, zissue.message);
  }
}

// =============================================================================
// Step 3 helpers — domain checks
// =============================================================================

// Content-commitment rule: a record MUST carry at least one of `items[]` or
// `merkle[]` non-empty (SCHEMA_EMPTY_RECORD when both are empty or absent).
// When exactly one of them is present-but-empty beside a non-empty sibling,
// the empty array itself violates its `1*` cardinality.
function checkContentCommitmentPresence(record: PoeRecord, issues: ValidationIssue[]): void {
  const itemsLen = record.items?.length ?? 0;
  const merkleLen = record.merkle?.length ?? 0;
  if (itemsLen === 0 && merkleLen === 0) {
    issues.push(
      issueOf(
        'SCHEMA_EMPTY_RECORD',
        [],
        'record must carry at least one of items[] or merkle[] non-empty',
      ),
    );
    return;
  }
  if (record.items !== undefined && itemsLen === 0) {
    issues.push(
      issueOf('SCHEMA_TYPE_MISMATCH', ['items'], 'items[] must be non-empty when present'),
    );
  }
  if (record.merkle !== undefined && merkleLen === 0) {
    issues.push(
      issueOf('SCHEMA_TYPE_MISMATCH', ['merkle'], 'merkle[] must be non-empty when present'),
    );
  }
}

// Hash-map: non-empty, registry membership, per-algorithm digest length.
function checkItemHashes(item: ItemEntry, idx: number, issues: ValidationIssue[]): void {
  const entries = Object.entries(item.hashes);
  if (entries.length === 0) {
    issues.push(
      issueOf(
        'SCHEMA_TYPE_MISMATCH',
        ['items', idx, 'hashes'],
        'hashes must be a non-empty CBOR map of <alg-id> -> <digest>',
      ),
    );
    return;
  }
  for (const [alg, digest] of entries) {
    if (!(alg in HASH_ALG_LENGTHS)) {
      issues.push(
        issueOf('UNSUPPORTED_HASH_ALG', ['items', idx, 'hashes', alg], `unknown hash alg: ${alg}`),
      );
      continue;
    }
    const expected = HASH_ALG_LENGTHS[alg]!;
    if (digest.length !== expected) {
      issues.push(
        issueOf(
          'HASH_DIGEST_LENGTH_MISMATCH',
          ['items', idx, 'hashes', alg],
          `hashes['${alg}'] digest length ${digest.length} != ${expected}`,
        ),
      );
    }
  }
}

// URI shape: each entry is one absolute URI in a single text string.
function checkUris(
  uris: ReadonlyArray<string>,
  basePath: ReadonlyArray<string | number>,
  issues: ValidationIssue[],
): void {
  if (uris.length === 0) {
    issues.push(issueOf('SCHEMA_TYPE_MISMATCH', basePath, 'uris[] must be non-empty when present'));
    return;
  }
  uris.forEach((uri, ui) => checkOneUri(uri, [...basePath, ui], issues));
}

function checkOneUri(
  uri: string,
  path: ReadonlyArray<string | number>,
  issues: ValidationIssue[],
): void {
  // Absolute URI, no fragment, scheme in `{ar://, ipfs://}`.
  if (uri.includes('#')) {
    issues.push(
      issueOf('INVALID_URI', path, "URI contains a fragment identifier ('#'), which is forbidden"),
    );
    return;
  }
  const sepIdx = uri.indexOf('://');
  if (sepIdx <= 0 || !/^[a-z][a-z0-9+.-]*$/i.test(uri.slice(0, sepIdx))) {
    issues.push(
      issueOf('INVALID_URI', path, 'URI is not absolute (missing scheme://hierarchical-part)'),
    );
    return;
  }
  // RFC 3986 §3.1: the scheme is case-insensitive, so case-fold the SCHEME
  // ONLY, then ALWAYS validate the body. The body is matched verbatim — a
  // base64url Arweave txid and a base58btc CID are case-significant.
  const scheme = uri.slice(0, sepIdx).toLowerCase();
  const rest = uri.slice(sepIdx + '://'.length);
  if (scheme === 'ar') {
    if (!/^[A-Za-z0-9_-]{43}$/.test(rest)) {
      issues.push(
        issueOf(
          'INVALID_URI',
          path,
          'ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` (43-char base64url txid, no path/query/fragment)',
        ),
      );
    }
    return;
  }
  if (scheme === 'ipfs') {
    // Full offline CID parse (not a prefix heuristic).
    const slashIdx = rest.indexOf('/');
    const cid = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    if (!validateCidProfile(cid)) {
      issues.push(
        issueOf('INVALID_URI', path, 'ipfs:// URI is not a valid CID under the Label 309 profile'),
      );
    }
    return;
  }
  issues.push(
    issueOf('INVALID_URI', path, 'unsupported URI scheme; v1 PoE URI set is {ar://, ipfs://}'),
  );
}

// =============================================================================
// Encryption envelope — the typed-vs-opaque union
// =============================================================================
//
// `enc = enc-scheme-1 / enc-opaque`. The disposition is decided by identifier
// support, never by shape success:
//
//   - When `scheme`, `kem`, and `aead` are ALL supported identifiers, the
//     envelope is held to the full scheme-1 shape and key-path rules; an
//     envelope that fails them is rejected with its typed code, never
//     reclassified as opaque.
//   - When any of the three names an identifier this implementation does not
//     support, the envelope becomes OPAQUE: no shape, length, or key-path
//     rule is applied against an unknown identifier; the item is tagged
//     ENC_UNSUPPORTED (info in the public reading; error co-firing with the
//     identifier-specific UNSUPPORTED_* code in the recipient role / strict
//     sealed-crypto mode).
//   - Carve-out: an `aead` naming a forbidden unauthenticated cipher family
//     is rejected UNAUTHENTICATED_CIPHER_FORBIDDEN in every role — a
//     recognised hazard, not an unknown identifier.
//
// The content-hash binding (ENC_REQUIRES_CONTENT_HASH) inspects the item's
// `hashes` map, not the envelope, so it applies even under an opaque
// envelope.

function checkItemEnc(
  item: ItemEntry,
  idx: number,
  opts: ResolvedOptions,
  issues: ValidationIssue[],
): void {
  const encPath: ReadonlyArray<string | number> = ['items', idx, 'enc'];

  // Content-hash binding: an `enc`-bearing item MUST commit to at least one
  // REGISTERED content hash — the ciphertext is otherwise bound to no
  // plaintext digest. A presence check, not a non-empty check: `{md5: …}`
  // fails it (and MAY co-fire with UNSUPPORTED_HASH_ALG on the same item).
  const hasContentHash = Object.keys(item.hashes).some((alg) => alg in HASH_ALG_LENGTHS);
  if (!hasContentHash) {
    issues.push(
      issueOf(
        'ENC_REQUIRES_CONTENT_HASH',
        encPath,
        'item carries `enc` but `hashes` has no registered content-hash entry (sha2-256 or blake2b-256)',
      ),
    );
  }

  // The pre-guard has already rejected an `enc` that decoded to a `Map`
  // (non-text keys), so a well-typed envelope arrives here as a plain object.
  const rawEnc = item.enc;
  if (
    rawEnc === null ||
    typeof rawEnc !== 'object' ||
    Array.isArray(rawEnc) ||
    rawEnc instanceof Uint8Array
  ) {
    issues.push(issueOf('SCHEMA_TYPE_MISMATCH', encPath, 'enc must be a CBOR map'));
    return;
  }
  const enc = rawEnc as Record<string, unknown>;

  // Decoded-envelope byte resource bound — a generic decode limit that
  // applies in every reading, opaque included. Canonical decode → canonical
  // encode is byte-identical, so re-encoding the decoded envelope measures
  // exactly the wire bytes of the `enc` subtree.
  const envelopeBytes = encodeCanonicalCbor(rawEnc as CanonicalCborValue).length;
  if (envelopeBytes > opts.maxEncEnvelopeBytes) {
    issues.push(
      issueOf(
        'ENC_ENVELOPE_TOO_LARGE',
        encPath,
        `decoded envelope is ${envelopeBytes} bytes; the resource bound is ${opts.maxEncEnvelopeBytes}`,
      ),
    );
  }

  // `scheme` is structurally required in BOTH readings, as a CBOR unsigned
  // integer (the opaque grammar admits any uint; the typed grammar pins 1).
  const scheme = enc['scheme'];
  if (scheme === undefined) {
    issues.push(
      issueOf('SCHEMA_MISSING_REQUIRED', [...encPath, 'scheme'], 'enc.scheme is required'),
    );
    return;
  }
  if (!isUint(scheme)) {
    issues.push(
      issueOf(
        'SCHEMA_TYPE_MISMATCH',
        [...encPath, 'scheme'],
        'enc.scheme must be a CBOR unsigned integer',
      ),
    );
    return;
  }

  // Forbidden-cipher carve-out: rejected in every role, never opaque.
  const aead = enc['aead'];
  if (typeof aead === 'string' && UNAUTHENTICATED_CIPHER_RE.test(aead)) {
    issues.push(
      issueOf(
        'UNAUTHENTICATED_CIPHER_FORBIDDEN',
        [...encPath, 'aead'],
        `'${aead}' is an unauthenticated cipher; Label 309 mandates an authenticated (AEAD) cipher`,
      ),
    );
    return;
  }

  // Unknown-envelope rule: collect every identifier outside the implemented
  // set. A non-text `kem` / `aead` is not an identifier at all — it is a type
  // violation of whichever reading applies, handled by the typed pass below.
  const kem = enc['kem'];
  const unsupported: Array<{ field: 'scheme' | 'kem' | 'aead'; code: ErrorCode; id: string }> = [];
  if (!(typeof scheme === 'number' && scheme === 1)) {
    unsupported.push({ field: 'scheme', code: 'UNSUPPORTED_ENVELOPE_SCHEME', id: String(scheme) });
  }
  if (typeof kem === 'string' && !(kem in KEM_SLOT_DESCRIPTORS)) {
    unsupported.push({ field: 'kem', code: 'UNSUPPORTED_KEM_ALG', id: kem });
  }
  if (typeof aead === 'string' && !(aead in AEAD_NONCE_LENGTHS)) {
    unsupported.push({ field: 'aead', code: 'UNSUPPORTED_AEAD_ALG', id: aead });
  }
  if (unsupported.length > 0) {
    // Degrade to opaque: the envelope is bounded metadata only. No shape,
    // length, nonce, slot, or key-path rule may be applied against an
    // unknown identifier.
    const named = unsupported.map((u) => `${u.field}=${u.id}`).join(', ');
    const message =
      `envelope uses identifiers this implementation does not support (${named}); ` +
      'the envelope is opaque and only the content-hash claim is validated';
    if (opts.role === 'recipient_or_strict') {
      issues.push({ code: 'ENC_UNSUPPORTED', path: encPath, message, severity: 'error' });
      for (const u of unsupported) {
        issues.push(
          issueOf(u.code, [...encPath, u.field], `enc.${u.field} '${u.id}' is not supported`),
        );
      }
    } else {
      issues.push({ code: 'ENC_UNSUPPORTED', path: encPath, message, severity: 'info' });
    }
    return;
  }

  // Fully supported identifiers → the typed scheme-1 pass is mandatory.
  // Non-text-key maps inside the typed envelope (a slot, the passphrase
  // block, its params) are rejected first, at the containing map — the same
  // pre-guard rule the record level applies, scoped here because only the
  // typed reading constrains the envelope interior.
  const internalMapIssues = encInternalNonTextKeyIssues(enc, encPath);
  if (internalMapIssues.length > 0) {
    issues.push(...internalMapIssues);
    return;
  }
  const encParse = EncScheme1Schema.safeParse(rawEnc);
  if (!encParse.success) {
    for (const mapped of mapZodIssues(encParse.error.issues, rawEnc)) {
      issues.push({ ...mapped, path: [...encPath, ...mapped.path] });
    }
    return;
  }
  checkScheme1Envelope(encParse.data, rawEnc, encPath, opts, issues);
}

// Non-text-key maps at the typed envelope's interior positions: each slot,
// the passphrase block, and its `params` map.
function encInternalNonTextKeyIssues(
  enc: Record<string, unknown>,
  encPath: ReadonlyArray<string | number>,
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const flag = (path: ReadonlyArray<string | number>): void => {
    issues.push(
      issueOf(
        'SCHEMA_TYPE_MISMATCH',
        path,
        'CBOR map carries a non-text key where a text-keyed map is required',
      ),
    );
  };
  const slots = enc['slots'];
  if (Array.isArray(slots)) {
    slots.forEach((slot, i) => {
      if (slot instanceof Map) flag([...encPath, 'slots', i]);
    });
  }
  const passphrase = enc['passphrase'];
  if (passphrase instanceof Map) {
    flag([...encPath, 'passphrase']);
  } else if (passphrase !== null && typeof passphrase === 'object' && !Array.isArray(passphrase)) {
    const params = (passphrase as Record<string, unknown>)['params'];
    if (params instanceof Map) flag([...encPath, 'passphrase', 'params']);
  }
  return issues;
}

function checkScheme1Envelope(
  enc: EncScheme1,
  rawEnc: object,
  encPath: ReadonlyArray<string | number>,
  opts: ResolvedOptions,
  issues: ValidationIssue[],
): void {
  // Nonce length is registered per content format (24 bytes for
  // chacha20-poly1305-stream64k). Checked only under a supported `aead` —
  // which is guaranteed on this path.
  const expectedNonceLen = AEAD_NONCE_LENGTHS[enc.aead]!;
  if (enc.nonce.length !== expectedNonceLen) {
    issues.push(
      issueOf(
        'NONCE_LENGTH_MISMATCH',
        [...encPath, 'nonce'],
        `nonce length ${enc.nonce.length} != ${expectedNonceLen} for ${enc.aead}`,
      ),
    );
  }

  // Key-path cross-field rules. Exactly one of `slots` / `passphrase` is
  // present; `passphrase` forbids `kem`, `slots`, and `slots_mac`; `slots`
  // requires both `kem` and `slots_mac`; `slots_mac` binds nothing without
  // `slots`. Each independent rule emits its own code — they co-fire where
  // several apply.
  const hasSlots = enc.slots !== undefined;
  const hasSlotsMac = enc.slots_mac !== undefined;
  const hasPassphrase = enc.passphrase !== undefined;
  const hasKem = enc.kem !== undefined;

  if (hasPassphrase && (hasSlots || hasSlotsMac || hasKem)) {
    issues.push(
      issueOf(
        'ENC_EXCLUSIVITY_VIOLATION',
        encPath,
        'enc.passphrase is mutually exclusive with kem / slots / slots_mac; exactly one key path is allowed',
      ),
    );
  }
  if (hasSlots && !hasSlotsMac) {
    issues.push(
      issueOf('ENC_SLOTS_MAC_REQUIRED', encPath, 'enc.slots present but enc.slots_mac absent'),
    );
  }
  if (hasSlotsMac && !hasSlots) {
    issues.push(
      issueOf('ENC_SLOTS_REQUIRED', encPath, 'enc.slots_mac present but enc.slots absent'),
    );
  }
  if (hasSlots && !hasKem) {
    issues.push(issueOf('ENC_KEM_REQUIRED', encPath, 'enc.slots present but enc.kem absent'));
  }
  if (!hasSlots && !hasPassphrase) {
    issues.push(
      issueOf(
        'ENC_NO_KEY_PATH',
        encPath,
        'enc requires either slots or passphrase — no on-chain key path otherwise',
      ),
    );
  }

  if (hasSlots) {
    const slots = enc.slots!;
    if (slots.length < 1) {
      issues.push(
        issueOf('ENC_SLOTS_EMPTY', [...encPath, 'slots'], 'slots[] must carry at least one slot'),
      );
    } else if (slots.length > opts.maxSlots) {
      // Slot-count resource bound: reject before walking any slot, so a
      // hostile record cannot drive unbounded per-slot work.
      issues.push(
        issueOf(
          'ENC_SLOTS_TOO_MANY',
          [...encPath, 'slots'],
          `slots length ${slots.length} exceeds the slot-count bound ${opts.maxSlots}`,
        ),
      );
    } else if (hasKem) {
      // The descriptor exists — `kem` is registered on this path.
      const descriptor = KEM_SLOT_DESCRIPTORS[enc.kem!]!;
      const rawSlotKeys = rawSlotKeySets(rawEnc);
      // Per-slot KEK uniqueness: the zero-nonce per-slot wrap is safe only
      // because each slot draws fresh KEM randomness; two slots sharing the
      // same encapsulation material would derive the same KEK. Reject the
      // repeat before any cryptographic layer would.
      const seenKemMaterial = new Set<string>();
      slots.forEach((slot, si) => {
        const slotPath = [...encPath, 'slots', si] as const;
        checkSlotShape(
          slot,
          rawSlotKeys[si] ?? new Set<string>(),
          descriptor,
          enc.kem!,
          slotPath,
          issues,
        );
        const material = descriptor.field === 'epk' ? slot.epk : slot.kem_ct;
        if (material !== undefined) {
          const key = bytesToHex(material);
          if (seenKemMaterial.has(key)) {
            issues.push(
              issueOf(
                'ENC_SLOTS_DUPLICATE_KEM_MATERIAL',
                [...slotPath, descriptor.field],
                `slot ${si} ${descriptor.field} duplicates an earlier slot — per-slot KEK uniqueness is violated`,
              ),
            );
          } else {
            seenKemMaterial.add(key);
          }
        }
      });
    }
  }

  if (hasPassphrase) {
    checkPassphraseBlock(enc.passphrase!, [...encPath, 'passphrase'], opts, issues);
  }
}

// KEM-driven per-slot shape gate. The descriptor for the declared envelope
// `kem` pins which ciphertext-bearing field MUST be present at what exact
// length, and forbids everything else: the other KEM's field, any stray key
// (a slot is a CLOSED 2-key map), and a missing required field all surface
// as ENC_SLOT_INVALID_SHAPE. `rawKeys` is the slot's key set exactly as it
// appeared on the wire, so the permissive slot schema cannot mask a foreign
// field.
const SLOT_KEY_UNIVERSE: ReadonlySet<string> = new Set(['epk', 'kem_ct', 'wrap']);

function checkSlotShape(
  slot: Slot,
  rawKeys: ReadonlySet<string>,
  descriptor: KemSlotDescriptor,
  kem: string,
  slotPath: ReadonlyArray<string | number>,
  issues: ValidationIssue[],
): void {
  const foreignField: KemSlotField = descriptor.field === 'epk' ? 'kem_ct' : 'epk';
  if (rawKeys.has(foreignField)) {
    issues.push(
      issueOf(
        'ENC_SLOT_INVALID_SHAPE',
        [...slotPath, foreignField],
        `slot carries '${foreignField}' but kem='${kem}' expects '${descriptor.field}'`,
      ),
    );
  }
  for (const key of rawKeys) {
    if (!SLOT_KEY_UNIVERSE.has(key)) {
      issues.push(
        issueOf(
          'ENC_SLOT_INVALID_SHAPE',
          [...slotPath, key],
          `slot carries unexpected key '${key}'; a slot is a 2-key map {${descriptor.field}, wrap}`,
        ),
      );
    }
  }

  const ctField = descriptor.field === 'epk' ? slot.epk : slot.kem_ct;
  if (ctField === undefined) {
    issues.push(
      issueOf(
        'ENC_SLOT_INVALID_SHAPE',
        [...slotPath, descriptor.field],
        `slot for kem='${kem}' is missing required '${descriptor.field}'`,
      ),
    );
  } else if (ctField.length !== descriptor.fieldLength) {
    issues.push(
      issueOf(
        KEM_FIELD_LENGTH_CODE[descriptor.field],
        [...slotPath, descriptor.field],
        `slot.${descriptor.field} length ${ctField.length} != ${descriptor.fieldLength} for ${kem}`,
      ),
    );
  }

  if (slot.wrap === undefined) {
    issues.push(
      issueOf(
        'ENC_SLOT_INVALID_SHAPE',
        [...slotPath, 'wrap'],
        `slot for kem='${kem}' is missing required 'wrap'`,
      ),
    );
  } else if (slot.wrap.length !== descriptor.wrapLength) {
    issues.push(
      issueOf(
        'WRAP_LENGTH_MISMATCH',
        [...slotPath, 'wrap'],
        `slot.wrap length ${slot.wrap.length} != ${descriptor.wrapLength}`,
      ),
    );
  }
}

// Passphrase block: KDF registry membership, then the registered algorithm's
// CLOSED parameter map with exact-integer range, floors, and the deployment
// ceiling. Salt bounds are schema refinements and have already fired.
function checkPassphraseBlock(
  pp: PassphraseBlock,
  ppPath: ReadonlyArray<string | number>,
  opts: ResolvedOptions,
  issues: ValidationIssue[],
): void {
  if (!PASSPHRASE_KDF_ALGS.has(pp.alg)) {
    issues.push(
      issueOf(
        'ENC_PASSPHRASE_ALG_UNSUPPORTED',
        [...ppPath, 'alg'],
        `unknown passphrase kdf alg: ${pp.alg}`,
      ),
    );
    return; // no algorithm-specific params rule can apply
  }

  // argon2id: `params` is the CLOSED map of exactly {m, t, p}.
  const paramsPath = [...ppPath, 'params'] as const;
  const params = pp.params;
  for (const key of Object.keys(params)) {
    if (key !== 'm' && key !== 't' && key !== 'p') {
      issues.push(
        issueOf(
          'SCHEMA_UNKNOWN_FIELD',
          [...paramsPath, key],
          `unknown argon2id params field: ${key}`,
        ),
      );
    }
  }

  const floors = { m: 65_536, t: 3, p: 1 } as const;
  const ceiling = opts.passphraseParamsCeiling;
  for (const name of ['m', 't', 'p'] as const) {
    const value: unknown = params[name];
    if (value === undefined) {
      issues.push(
        issueOf(
          'SCHEMA_MISSING_REQUIRED',
          [...paramsPath, name],
          `argon2id params.${name} is required`,
        ),
      );
      continue;
    }
    // Exact-integer discipline: values above 2^53 − 1 arrive as `bigint`,
    // so an out-of-range value is rejected without precision loss.
    if (!isUint(value)) {
      issues.push(
        issueOf(
          'SCHEMA_TYPE_MISMATCH',
          [...paramsPath, name],
          `argon2id params.${name} must be a CBOR unsigned integer`,
        ),
      );
      continue;
    }
    if (!uintWithin(value, 0, UINT32_MAX)) {
      issues.push(
        issueOf(
          'SCHEMA_TYPE_MISMATCH',
          [...paramsPath, name],
          `argon2id params.${name} exceeds the pinned wire range 0 .. 2^32 - 1`,
        ),
      );
      continue;
    }
    const num = Number(value);
    if (num < floors[name]) {
      issues.push(
        issueOf(
          'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
          [...paramsPath, name],
          `argon2id requires ${name} >= ${floors[name]}`,
        ),
      );
      continue;
    }
    if (ceiling !== null && num > ceiling[name]) {
      issues.push(
        issueOf(
          'ENC_PASSPHRASE_PARAMS_EXCEED_POLICY',
          [...paramsPath, name],
          `argon2id params.${name} = ${num} exceeds the deployment ceiling ${ceiling[name]}`,
        ),
      );
    }
  }
}

// Extract the per-slot RAW key sets from the decoded `enc` value, so the
// closed-slot rule sees keys the permissive slot schema does not model. The
// canonical decoder yields a plain object for a text-keyed CBOR map and a
// `Map` for a map carrying any non-text key.
function rawSlotKeySets(rawEnc: object): ReadonlyArray<ReadonlySet<string>> {
  const slots = (rawEnc as Record<string, unknown>)['slots'];
  if (!Array.isArray(slots)) return [];
  return slots.map((slot) => {
    const keys = new Set<string>();
    if (slot instanceof Map) {
      for (const k of slot.keys()) if (typeof k === 'string') keys.add(k);
    } else if (typeof slot === 'object' && slot !== null) {
      for (const k of Object.keys(slot as Record<string, unknown>)) keys.add(k);
    }
    return keys;
  });
}

// =============================================================================
// Merkle commitments
// =============================================================================

function checkMerkleCommit(commit: MerkleCommit, idx: number, issues: ValidationIssue[]): void {
  const basePath: ReadonlyArray<string | number> = ['merkle', idx];
  if (!(commit.alg in MERKLE_COMMIT_ALG_LENGTHS)) {
    issues.push(
      issueOf(
        'UNSUPPORTED_MERKLE_COMMIT_ALG',
        [...basePath, 'alg'],
        `unknown merkle commitment alg: ${commit.alg}`,
      ),
    );
  } else {
    const expected = MERKLE_COMMIT_ALG_LENGTHS[commit.alg]!;
    if (commit.root.length !== expected) {
      issues.push(
        issueOf(
          'HASH_DIGEST_LENGTH_MISMATCH',
          [...basePath, 'root'],
          `merkle entry root length ${commit.root.length} != ${expected} for ${commit.alg}`,
        ),
      );
    }
  }

  // `leaf_count` is REQUIRED and pinned to `1 .. 2^32 − 1`, compared as an
  // exact integer: the decoder surfaces values above 2^53 − 1 as `bigint`,
  // so 2^53 + 1 cannot round to a boundary value before rejection. A
  // negative value is a CBOR type violation (nint where uint is required),
  // distinct from an out-of-range unsigned value.
  const leafCount = commit.leaf_count;
  if (!isUint(leafCount)) {
    issues.push(
      issueOf(
        'SCHEMA_TYPE_MISMATCH',
        [...basePath, 'leaf_count'],
        'leaf_count must be a CBOR unsigned integer',
      ),
    );
  } else if (!uintWithin(leafCount, 1, UINT32_MAX)) {
    issues.push(
      issueOf(
        'SCHEMA_MERKLE_LEAF_COUNT_INVALID',
        [...basePath, 'leaf_count'],
        `leaf_count ${String(leafCount)} is outside the pinned range 1 .. 2^32 - 1`,
      ),
    );
  }

  if (commit.uris !== undefined) {
    checkUris(commit.uris, [...basePath, 'uris'], issues);
  }
}

// =============================================================================
// Record-level signature entries
// =============================================================================

function checkSigEntry(entry: SigEntry, idx: number, issues: ValidationIssue[]): void {
  // Path-2 `cose_key` private-material guard runs FIRST: a leaked private
  // scalar must be named even when the COSE_Sign1 is also malformed.
  if (entry.cose_key !== undefined) {
    const keyIssue = inspectCoseKey(entry.cose_key, idx);
    if (keyIssue !== null) {
      issues.push(keyIssue);
      return;
    }
  }

  let cose: ReturnType<typeof decodeCoseSign1>;
  try {
    cose = decodeCoseSign1(entry.cose_sign1);
  } catch (cause) {
    issues.push(
      issueOf(
        'MALFORMED_SIG_COSE_SIGN1',
        ['sigs', idx],
        cause instanceof CoseVerifyError || cause instanceof Error ? cause.message : String(cause),
      ),
    );
    return;
  }

  // Detached-only: the COSE_Sign1 payload MUST be CBOR null. An attached
  // payload — even zero-length — is rejected; a producer chaining a CIP-30
  // signData result must null the payload before embedding.
  if (cose.payload !== null) {
    issues.push(
      issueOf(
        'MALFORMED_SIG_COSE_SIGN1',
        ['sigs', idx],
        'COSE_Sign1 payload must be null (detached); attached form forbidden',
      ),
    );
    return;
  }

  // Signature-algorithm registry check (info severity — signatures are
  // optional, so an unrecognised algorithm never fails the record alone).
  const alg = cose.protectedHeader.get(1);
  if (typeof alg !== 'number' || !KNOWN_SIG_ALG_IDS.has(alg)) {
    issues.push(
      issueOf(
        'SIGNATURE_UNSUPPORTED',
        ['sigs', idx],
        `COSE_Sign1 protected alg ${String(alg)} not in {-8, -19}`,
      ),
    );
  }

  // Path-1 (32-byte protected-header `kid`) and path-2 (`cose_key` sidecar)
  // are mutually exclusive.
  const protectedKid = cose.protectedHeader.get(4);
  if (
    protectedKid instanceof Uint8Array &&
    protectedKid.length === 32 &&
    entry.cose_key !== undefined
  ) {
    issues.push(
      issueOf(
        'SIG_ENTRY_KID_COSE_KEY_CONFLICT',
        ['sigs', idx],
        'sigs[i] carries both a 32-byte protected `kid` (path 1) and an inline `cose_key` (path 2); paths are mutually exclusive',
      ),
    );
  }
}

// COSE_Key inspector (path-2 `sigs[i].cose_key` blob). Two structural checks:
//   1. Private-material guard (FIRST). COSE_Key label `-4` (the private
//      scalar `d` for OKP / EC2 per RFC 9052 §7.1) → SIG_PRIVATE_KEY_LEAKED.
//      Publishing a private key on the permanent ledger is catastrophic and
//      irreversible, so this is a load-bearing producer-side preflight.
//   2. Positive-shape guard: `kty = 1` (OKP), `crv = 6` (Ed25519), and a
//      32-byte `-2` (x). Any failure → MALFORMED_SIG_COSE_SIGN1.
function inspectCoseKey(keyBytes: Uint8Array, i: number): ValidationIssue | null {
  let decoded: unknown;
  try {
    decoded = decodeCanonicalCbor(keyBytes);
  } catch (cause) {
    return issueOf(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key failed to decode as cbor<COSE_Key>: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  // A COSE_Key map is int-keyed, so the canonical decoder surfaces it as a
  // `Map`; a text-keyed look-alike arrives as a plain object and fails the
  // label lookups below.
  const getLabel = (label: number): unknown => {
    if (decoded instanceof Map) return decoded.get(label);
    return undefined;
  };
  const hasLabel = (label: number): boolean => {
    if (decoded instanceof Map) return decoded.has(label);
    return false;
  };

  if (hasLabel(-4)) {
    return issueOf(
      'SIG_PRIVATE_KEY_LEAKED',
      ['sigs', i, 'cose_key'],
      'cose_key carries COSE_Key private-key material (label -4, the OKP/EC2 private scalar d); publishing a private key on the permanent ledger is forbidden',
    );
  }

  const kty = getLabel(1);
  if (kty !== 1) {
    return issueOf(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key COSE_Key kty (label 1) must be 1 (OKP); got ${String(kty)}`,
    );
  }
  const crv = getLabel(-1);
  if (crv !== 6) {
    return issueOf(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key COSE_Key crv (label -1) must be 6 (Ed25519); got ${String(crv)}`,
    );
  }
  const x = getLabel(-2);
  if (!(x instanceof Uint8Array) || x.length !== 32) {
    const got = x instanceof Uint8Array ? `${x.length}-byte bstr` : typeof x;
    return issueOf(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key COSE_Key label -2 must be a 32-byte byte string (Ed25519 public key); got ${got}`,
    );
  }
  return null;
}

// =============================================================================
// `crit[]` shape + critical-extension support
// =============================================================================

function checkCrit(
  record: PoeRecord,
  decodedTopKeys: ReadonlySet<string>,
  supportedCriticalExtensions: ReadonlySet<string>,
  issues: ValidationIssue[],
): void {
  if (!Array.isArray(record.crit)) return;
  // `crit` has `1*` cardinality: an empty array is a malformed shape.
  if (record.crit.length === 0) {
    issues.push(
      issueOf(
        'SCHEMA_TYPE_MISMATCH',
        ['crit'],
        'crit[] must carry at least one entry when present',
      ),
    );
    return;
  }
  const seen = new Set<string>();
  for (let i = 0; i < record.crit.length; i++) {
    const critName = record.crit[i]!;
    let reason: string | null = null;
    if (TOP_LEVEL_BASE_KEYS.has(critName)) {
      reason = `'${critName}' is a base key and MUST NOT appear in crit[]`;
    } else if (!isExtensionKey(critName)) {
      reason = `'${critName}' does not match the extension-key form (^x-.+ or ^[a-z]+-.+, no control characters)`;
    } else if (!decodedTopKeys.has(critName)) {
      reason = `'${critName}' is named in crit but absent from the record map`;
    } else if (seen.has(critName)) {
      reason = `'${critName}' appears more than once in crit[]`;
    }
    seen.add(critName);
    if (reason !== null) {
      issues.push(issueOf('CRIT_SHAPE_INVALID', ['crit', i], reason));
      continue;
    }
    // Shape-valid entry: accepted iff this validator implements the named
    // extension. The default supported set is empty, so a default-configured
    // validator fails every `crit`-bearing record — by design.
    if (!supportedCriticalExtensions.has(critName)) {
      issues.push(
        issueOf(
          'EXTENSION_UNSUPPORTED_CRITICAL',
          ['crit', i],
          `crit lists extension '${critName}' that this validator does not implement`,
        ),
      );
    }
  }
}

function topLevelKeysOf(decoded: unknown): Set<string> {
  if (decoded === null || typeof decoded !== 'object') return new Set();
  if (decoded instanceof Map) {
    const out = new Set<string>();
    for (const k of decoded.keys()) {
      if (typeof k === 'string') out.add(k);
    }
    return out;
  }
  return new Set(Object.keys(decoded as Record<string, unknown>));
}

// =============================================================================
// Label 309 CID profile
// =============================================================================
//
// Accept CIDv0 (`Qm` prefix, 46-char base58btc, sha2-256 multihash) and
// CIDv1 (multibase prefix + version 0x01 + codec + multihash) per the
// closed profile:
//   - Multibase: b, B, f, F, z
//   - Multicodec: 0x55 (raw), 0x70 (dag-pb), 0x71 (dag-cbor)
//   - Multihash: 0x12 (sha2-256, 32 B), 0xb220 (blake2b-256, 32 B)
//
// Returns true iff the CID conforms to the Label 309 profile.

const ACCEPTED_CIDV1_MULTIBASE: ReadonlySet<string> = new Set(['b', 'B', 'f', 'F', 'z']);

const ACCEPTED_MULTICODECS: ReadonlySet<number> = new Set([0x55, 0x70, 0x71]);

// Multihash table: code → digest length (bytes).
const ACCEPTED_MULTIHASHES: ReadonlyMap<number, number> = new Map([
  [0x12, 32],
  [0xb220, 32],
]);

export function validateCidProfile(cid: string): boolean {
  if (cid.length === 0) return false;
  // CIDv0: a base58btc-encoded sha2-256 multihash. Decode the WHOLE string
  // and verify the multihash prefix (0x12 = sha2-256, 0x20 = 32-byte digest)
  // and total length (34 bytes); a `Qm` prefix alone is not sufficient.
  if (cid.startsWith('Qm')) {
    let decoded: Uint8Array;
    try {
      decoded = decodeBase58btc(cid);
    } catch {
      return false;
    }
    return decoded.length === 34 && decoded[0] === 0x12 && decoded[1] === 0x20;
  }
  // CIDv1: multibase + binary CID body.
  const mbPrefix = cid[0]!;
  if (!ACCEPTED_CIDV1_MULTIBASE.has(mbPrefix)) return false;
  let bytes: Uint8Array;
  try {
    bytes = decodeMultibase(mbPrefix, cid.slice(1));
  } catch {
    return false;
  }
  if (bytes.length < 4) return false;
  // CIDv1 layout: <version varint> <multicodec varint> <multihash>
  const versionParse = readVarint(bytes, 0);
  if (versionParse === null || versionParse.value !== 1) return false;
  const codecParse = readVarint(bytes, versionParse.next);
  if (codecParse === null) return false;
  if (!ACCEPTED_MULTICODECS.has(codecParse.value)) return false;
  const mhParse = readVarint(bytes, codecParse.next);
  if (mhParse === null) return false;
  const lenParse = readVarint(bytes, mhParse.next);
  if (lenParse === null) return false;
  const digestLen = lenParse.value;
  const expectedLen = ACCEPTED_MULTIHASHES.get(mhParse.value);
  if (expectedLen === undefined || digestLen !== expectedLen) return false;
  if (lenParse.next + digestLen !== bytes.length) return false;
  return true;
}

function readVarint(bytes: Uint8Array, start: number): { value: number; next: number } | null {
  let value = 0;
  let shift = 0;
  let i = start;
  while (i < bytes.length) {
    const b = bytes[i]!;
    value |= (b & 0x7f) << shift;
    i++;
    if ((b & 0x80) === 0) return { value, next: i };
    shift += 7;
    if (shift > 28) return null; // overflow guard; the profile uses ≤ 16-bit codes
  }
  return null;
}

// Multibase decoders for the closed set the CID profile admits.
function decodeMultibase(prefix: string, body: string): Uint8Array {
  switch (prefix) {
    case 'b':
      return decodeBase32(body.toLowerCase(), 'rfc4648-lower');
    case 'B':
      return decodeBase32(body.toUpperCase(), 'rfc4648-upper');
    case 'f':
      return decodeBase16(body.toLowerCase());
    case 'F':
      return decodeBase16(body.toUpperCase());
    case 'z':
      return decodeBase58btc(body);
    default:
      throw new Error(`unsupported multibase prefix ${prefix}`);
  }
}

const BASE16_LOWER = '0123456789abcdef';
const BASE16_UPPER = '0123456789ABCDEF';

function decodeBase16(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('base16: odd-length');
  const out = new Uint8Array(s.length / 2);
  const alphabet = s === s.toLowerCase() ? BASE16_LOWER : BASE16_UPPER;
  for (let i = 0; i < out.length; i++) {
    const hi = alphabet.indexOf(s[i * 2]!);
    const lo = alphabet.indexOf(s[i * 2 + 1]!);
    if (hi < 0 || lo < 0) throw new Error(`base16: non-hex char at ${i * 2}`);
    out[i] = (hi << 4) | lo;
  }
  return out;
}

const BASE32_RFC4648_LOWER = 'abcdefghijklmnopqrstuvwxyz234567';
const BASE32_RFC4648_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(s: string, variant: 'rfc4648-lower' | 'rfc4648-upper'): Uint8Array {
  const alphabet = variant === 'rfc4648-lower' ? BASE32_RFC4648_LOWER : BASE32_RFC4648_UPPER;
  // Multibase strips padding per spec; accept either form for robustness.
  const trimmed = s.replace(/=+$/, '');
  const out: number[] = [];
  let buf = 0;
  let bits = 0;
  for (const ch of trimmed) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`base32: invalid char '${ch}'`);
    buf = (buf << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function decodeBase58btc(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  const size = Math.floor(((s.length - zeros) * 733) / 1000) + 1;
  const b256 = new Uint8Array(size);
  let length = 0;
  for (let i = zeros; i < s.length; i++) {
    const ch = s[i]!;
    const carryIdx = BASE58_ALPHABET.indexOf(ch);
    if (carryIdx < 0) throw new Error(`base58: invalid char '${ch}'`);
    let carry = carryIdx;
    let k = 0;
    for (let j = size - 1; (carry !== 0 || k < length) && j >= 0; j--, k++) {
      carry += 58 * b256[j]!;
      b256[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    length = k;
  }
  let it = size - length;
  while (it < size && b256[it] === 0) it++;
  const out = new Uint8Array(zeros + (size - it));
  let j = zeros;
  while (it < size) {
    out[j++] = b256[it++]!;
  }
  return out;
}

// Hex rendering for byte-equality keys (the duplicate-KEM-material set).
function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

// =============================================================================
// Exact-integer helpers
// =============================================================================

// A CBOR unsigned integer as the canonical decoder surfaces it: a
// non-negative `number` for values up to 2^53 − 1, a non-negative `bigint`
// above (exact in both representations). A negative value is a different
// CBOR major type and is never a uint.
function isUint(value: unknown): value is number | bigint {
  if (typeof value === 'number') return Number.isInteger(value) && value >= 0;
  if (typeof value === 'bigint') return value >= 0n;
  return false;
}

function uintWithin(value: number | bigint, min: number, max: number): boolean {
  if (typeof value === 'bigint') return value >= BigInt(min) && value <= BigInt(max);
  return value >= min && value <= max;
}

// =============================================================================
// Issue construction and deterministic ordering
// =============================================================================

function issueOf(
  code: ErrorCode,
  path: ReadonlyArray<string | number>,
  message: string,
): ValidationIssue {
  return { code, path, message, severity: SEVERITY[code] };
}

const PATH_UTF8 = new TextEncoder();

// Bytewise comparison of the UTF-8 encodings — the only collation that is
// byte-stable across runs and across language implementations (no locale
// tables, no UTF-16 code-unit artefacts for non-BMP keys).
function compareTextSegments(a: string, b: string): number {
  const ab = PATH_UTF8.encode(a);
  const bb = PATH_UTF8.encode(b);
  const n = Math.min(ab.length, bb.length);
  for (let i = 0; i < n; i++) {
    const d = ab[i]! - bb[i]!;
    if (d !== 0) return d;
  }
  return ab.length - bb.length;
}

// Segment-wise path order: integer segments compare numerically, text
// segments compare by UTF-8 bytes, an integer segment orders before a text
// segment where the kinds differ, and a strict prefix orders before its
// extensions. Issues on an identical path tie-break by the position of their
// code in the canonical error-code registry.
function compareIssues(a: ValidationIssue, b: ValidationIssue): number {
  const ap = a.path;
  const bp = b.path;
  const n = Math.min(ap.length, bp.length);
  for (let i = 0; i < n; i++) {
    const x = ap[i]!;
    const y = bp[i]!;
    const xIsNum = typeof x === 'number';
    const yIsNum = typeof y === 'number';
    if (xIsNum !== yIsNum) return xIsNum ? -1 : 1;
    if (xIsNum && yIsNum) {
      if (x !== y) return (x as number) < (y as number) ? -1 : 1;
    } else {
      const d = compareTextSegments(x as string, y as string);
      if (d !== 0) return d;
    }
  }
  if (ap.length !== bp.length) return ap.length - bp.length;
  return errorCodeRegistryIndex(a.code) - errorCodeRegistryIndex(b.code);
}

function sortIssues(issues: ReadonlyArray<ValidationIssue>): ValidationIssue[] {
  return [...issues].sort(compareIssues);
}

function valueAtPath(root: unknown, path: ReadonlyArray<string | number>): unknown {
  let cur: unknown = root;
  for (const seg of path) {
    if (cur === null || cur === undefined) return undefined;
    if (cur instanceof Map) {
      cur = cur.get(seg);
      continue;
    }
    if (typeof cur !== 'object') return undefined;
    cur = (cur as Record<string | number, unknown>)[seg];
  }
  return cur;
}
