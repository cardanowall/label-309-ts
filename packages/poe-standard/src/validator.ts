// Label 309 v1 structural validator (the Part A structural-validation role).
//
// Pure function over CBOR bytes — performs no I/O, opens no socket, decodes
// no ciphertext. Cryptographic signature verification, chain resolution, URI
// fetching, decryption, and confirmation-depth checks are the verifier's
// concern (the Part B verifier role) and live in `@cardanowall/sdk-ts`.
//
// Pipeline:
//   Step 1  Resource boundary       — n/a here (validator has no fixed cap;
//                                     transactions are bounded by maxTxSize
//                                     enforced at submission)
//   Step 2  Canonical CBOR decode   — `decodeCanonicalCbor` from crypto-core
//                                     surfaces malformed / non-canonical /
//                                     duplicate-key inputs as typed errors.
//   Step 3  Schema parse            — Zod schema in `./schema.ts`; the mapper
//                                     below lifts each Zod issue to a
//                                     SCREAMING_SNAKE structural code.
//   Step 4  Domain checks           — cross-field rules, registry membership,
//                                     URI reconstruction + per-scheme shape
//                                     (the IPFS CID profile), `enc`
//                                     cross-field invariants, `sigs[i]`
//                                     closed-map check + COSE_Sign1 structural
//                                     decode (path-1/path-2 mutual exclusion,
//                                     `SIG_PRIVATE_KEY_LEAKED` guard).
//   Step 5  Result emission         — `{ ok: true, record, info?, warnings? }`
//                                     or `{ ok: false, issues }`.
//
// The validator NEVER throws — failure paths route through the discriminated
// `ValidateResult` union so callers handle errors as data.

import { z } from 'zod';

import { decodeCanonicalCbor } from '@cardanowall/crypto-core/cbor';
import { CoseVerifyError, decodeCoseSign1 } from '@cardanowall/crypto-core/cose';

import { bytesChunkArrayConcat, reconstructChunkedUri } from './chunked';
import { SEVERITY, type ErrorCode, type Severity } from './error-codes';
import {
  EncryptionEnvelopeSchema,
  isExtensionKey,
  PoeRecordSchema,
  TOP_LEVEL_BASE_KEYS,
  type ItemEntry,
  type MerkleCommit,
  type PoeRecord,
  type SigEntry,
  type Slot,
} from './schema';

// =============================================================================
// Registries
// =============================================================================

// Content-hash algorithm registry. Map value = digest length.
const HASH_ALG_LENGTHS: Readonly<Record<string, number>> = {
  'sha2-256': 32,
  'blake2b-256': 32,
};

// Merkle list-commitment algorithm registry.
const MERKLE_COMMIT_ALG_LENGTHS: Readonly<Record<string, number>> = {
  'rfc9162-sha256': 32,
};

// Content AEAD registry. Value = nonce length.
const AEAD_NONCE_LENGTHS: Readonly<Record<string, number>> = {
  'xchacha20-poly1305': 24,
};

// Unauthenticated-cipher family. An `enc.aead` naming any of these is rejected
// with `UNAUTHENTICATED_CIPHER_FORBIDDEN` (not the generic `UNSUPPORTED_AEAD_ALG`)
// so the failure names the integrity hazard. Two arms:
//   - block-cipher modes with no integrity (`cbc`, `ctr`, `ecb`, `cfb`, `ofb`)
//     appearing as a delimited token, which matches every key-size spelling
//     (`aes-cbc`, `aes-256-cbc`, `aes-128-cbc`, `des-ede3-cbc`, …);
//   - legacy stream/block ciphers as a leading token (`rc4`, `des`, `3des`).
// The token delimiters keep the authenticated AEADs (`aes-256-gcm`,
// `chacha20-poly1305`, `xchacha20-poly1305`) from matching. The trailing
// boundary tolerates a single trailing `\n` (`\n?$`) so a forbidden cipher
// cannot evade the denylist by appending one newline (`aes-256-cbc\n` /
// `rc4\n`), matching the Python/Rust validators.
const UNAUTHENTICATED_CIPHER_RE =
  /(?:^|[-_])(?:cbc|ctr|ecb|cfb|ofb)(?:[-_]|\n?$)|^(?:rc4|des|3des)(?:[-_]|\n?$)/i;

// KEM registry, expressed as a per-KEM slot DESCRIPTOR.
//
// Each registered KEM pins the exact recipient-slot shape:
//
//   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }` — classical
//     ephemeral-static X25519. The per-slot `epk` is the 32-byte ephemeral
//     public key.
//   - mlkem768x25519: `{ kem_ct: <1120-byte X-Wing enc>, wrap: bstr(48) }` —
//     the X-Wing hybrid (ML-KEM-768 + X25519). The ciphertext is carried as a
//     chunked byte-string array (`kem_ct`) that MUST reassemble to exactly
//     1120 bytes; there is NO per-slot `epk` on the hybrid path.
//
// A descriptor declares the slot's *ciphertext-bearing* field (`epk` for a
// classical KEM, `kem_ct` for a hybrid) and its expected reassembled byte
// length. `wrap` is 48 bytes for every KEM (32-byte CEK + 16-byte AEAD tag).
// The validator branches on the descriptor's `field` to know which field MUST
// be present and which MUST be absent, so adding a future KEM is a one-line
// registry edit, not a new code path.
type KemSlotField = 'epk' | 'kem_ct';
interface KemSlotDescriptor {
  /** The ciphertext-bearing slot field this KEM uses. */
  readonly field: KemSlotField;
  /** Expected length of that field (reassembled length for a chunked field). */
  readonly fieldLength: number;
  /** `wrap` length — 32-byte CEK + 16-byte AEAD tag. */
  readonly wrapLength: number;
}
const KEM_SLOT_DESCRIPTORS: Readonly<Record<string, KemSlotDescriptor>> = {
  x25519: { field: 'epk', fieldLength: 32, wrapLength: 48 },
  mlkem768x25519: { field: 'kem_ct', fieldLength: 1120, wrapLength: 48 },
};

// The length-mismatch code emitted when a slot's ciphertext-bearing field has
// the wrong (reassembled) length, keyed by the descriptor's `field`.
const KEM_FIELD_LENGTH_CODE: Readonly<Record<KemSlotField, ErrorCode>> = {
  epk: 'KEM_EPK_LENGTH_MISMATCH',
  kem_ct: 'KEM_CT_LENGTH_MISMATCH',
};

// Passphrase KDF registry.
const PASSPHRASE_KDF_ALGS: ReadonlySet<string> = new Set(['argon2id']);

// Signature-algorithm baseline. `-8` (EdDSA, curve-agnostic — pinned to
// Ed25519) is the mandatory baseline; `-19` (Ed25519 fully-specified) is
// optional and verified identically under the Ed25519 primitive when
// accepted. The reference validator accepts both; anything else surfaces as
// `SIGNATURE_UNSUPPORTED` (info-severity).
const KNOWN_SIG_ALG_IDS: ReadonlySet<number> = new Set([-8, -19]);

// =============================================================================
// Result types
// =============================================================================

export interface ValidationIssue {
  readonly code: ErrorCode;
  readonly path: ReadonlyArray<string | number>;
  readonly message: string;
  readonly severity: Severity;
}

export type ValidateResult =
  | {
      readonly ok: true;
      readonly record: PoeRecord;
      readonly warnings?: ReadonlyArray<ValidationIssue>;
      readonly info?: ReadonlyArray<ValidationIssue>;
    }
  | { readonly ok: false; readonly issues: ReadonlyArray<ValidationIssue> };

// =============================================================================
// Public entry point
// =============================================================================

export function validatePoeRecord(bytes: Uint8Array): ValidateResult {
  // Step 2 — canonical CBOR decode. Every decode failure surfaces as the single
  // MALFORMED_CBOR code: malformed/truncated bytes, indefinite-length
  // (streaming) encodings, non-canonical map-key ordering, duplicate map keys,
  // non-minimal integers, and invalid UTF-8. The taxonomy has no finer-grained
  // CBOR-decode codes — the validator catches all of these at decode and
  // reports one error.
  let decoded: unknown;
  try {
    decoded = decodeCanonicalCbor(bytes);
  } catch (cause) {
    return {
      ok: false,
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

  // Step 3 — schema parse
  const parse = PoeRecordSchema.safeParse(decoded);
  if (!parse.success) {
    const issues = parse.error.issues
      .map((issue) => mapZodIssue(issue, decoded))
      .sort(compareIssuePath);
    return { ok: false, issues };
  }

  // Step 4 — domain checks
  const record = parse.data;
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];
  const info: ValidationIssue[] = [];

  // 4a — content-commitment rule (`SCHEMA_EMPTY_RECORD`).
  const itemsLen = Array.isArray(record.items) ? record.items.length : 0;
  const merkleLen = Array.isArray(record.merkle) ? record.merkle.length : 0;
  if (itemsLen === 0 && merkleLen === 0) {
    errors.push(
      issue(
        'SCHEMA_EMPTY_RECORD',
        [],
        'record must carry at least one of items[] or merkle[] non-empty',
      ),
    );
  }

  // `crit[]` shape rules. Runs BEFORE the per-entry
  // `EXTENSION_UNSUPPORTED_CRITICAL` check.
  const decodedTopKeys = topLevelKeysOf(decoded);
  const critShapeInvalidIndices = checkCritShape(record, decodedTopKeys, errors);

  // Unknown top-level fields (typos like `supersedess`, `Sigs` that fall
  // outside both the base set and the extension-key namespaces).
  for (const k of decodedTopKeys) {
    if (TOP_LEVEL_BASE_KEYS.has(k)) continue;
    if (isExtensionKey(k)) continue;
    errors.push(issue('SCHEMA_UNKNOWN_FIELD', [k], `unknown top-level field: ${k}`));
  }

  // `EXTENSION_UNSUPPORTED_CRITICAL`: v1 reference validator implements no
  // extension keys, so every shape-valid `crit` entry is unsupported.
  if (Array.isArray(record.crit)) {
    for (let i = 0; i < record.crit.length; i++) {
      if (critShapeInvalidIndices.has(i)) continue;
      const critName = record.crit[i]!;
      errors.push(
        issue(
          'EXTENSION_UNSUPPORTED_CRITICAL',
          ['crit', i],
          `crit lists extension '${critName}' that this validator does not implement`,
        ),
      );
    }
  }

  // 4b – 4e — per-item walk.
  for (let i = 0; i < (record.items ?? []).length; i++) {
    const item = record.items![i]!;
    checkItemHashes(item, i, errors);
    if (item.uris) checkItemUris(item.uris, ['items', i, 'uris'], errors);
    if (item.enc !== undefined) checkItemEnc(item, i, errors);
  }

  // 4i — top-level `merkle[]` walk.
  for (let i = 0; i < (record.merkle ?? []).length; i++) {
    const commit = record.merkle![i]!;
    checkMerkleCommit(commit, i, errors);
  }

  // 4h — supersedes length is enforced by the schema-layer refinement; this
  // step adds no further check.

  // 4f + 4g — `sigs[i]` closed map shape + COSE_Sign1 structural decode.
  if (record.sigs) {
    for (let i = 0; i < record.sigs.length; i++) {
      checkSigEntry(record.sigs[i]!, i, errors, info);
    }
  }

  // Step 5 — result emission. `info`-severity entries do NOT fail the record;
  // `warning`-severity entries (none among the structural codes) also remain
  // non-fatal.
  if (errors.length > 0) {
    return { ok: false, issues: errors.sort(compareIssuePath) };
  }
  const result: {
    ok: true;
    record: PoeRecord;
    warnings?: ReadonlyArray<ValidationIssue>;
    info?: ReadonlyArray<ValidationIssue>;
  } = {
    ok: true,
    record,
  };
  if (warnings.length > 0) result.warnings = warnings.sort(compareIssuePath);
  if (info.length > 0) result.info = info.sort(compareIssuePath);
  return result;
}

// =============================================================================
// Step 3 helpers — Zod issue → structural-code mapping
// =============================================================================

function mapZodIssue(zissue: z.core.$ZodIssue, decoded?: unknown): ValidationIssue {
  const path = zissue.path as ReadonlyArray<string | number>;
  // Refinements with an explicit `params.code` win unconditionally — they
  // are the canonical taxonomy code attached at schema-definition time.
  const explicit = (zissue as { params?: { code?: string } }).params?.code as ErrorCode | undefined;
  if (explicit !== undefined) {
    return issue(explicit, path, zissue.message);
  }

  // Path-based dispatch:
  //   `sigs[i].*` → `SIG_ENTRY_INVALID_SHAPE` (the sig-entry closed-map rule)
  //   `items[i].enc.slots[j].(epk|wrap)` → `ENC_SLOT_INVALID_SHAPE`
  //     (structurally malformed slots)
  //   `v` literal mismatch / missing → `SCHEMA_INVALID_LITERAL` vs
  //     `SCHEMA_MISSING_REQUIRED`.
  const inSigsEntry = path.length >= 2 && path[0] === 'sigs' && typeof path[1] === 'number';

  // Match either the absolute path (`items[i].enc.slots[j]…`) or the
  // relative-to-`enc` path (`slots[j]…`) — the latter is what
  // `EncryptionEnvelopeSchema.safeParse(item.enc)` emits before
  // `checkItemEnc` prefixes the `items[i].enc.` segment.
  //
  // The match includes the whole slot ELEMENT (path ending at `slots[j]`, no
  // trailing field) as well as a field WITHIN a slot (`slots[j].epk`). A
  // wrong-typed slot (`slots: [[1, 2]]` → array instead of `{epk, wrap}`) and
  // a slot carrying an extra key both classify as `ENC_SLOT_INVALID_SHAPE`,
  // matching the spec's "a slot is not a 2-key map {epk, wrap}".
  const isInSlotEntry = (() => {
    if (
      path.length >= 5 &&
      path[0] === 'items' &&
      typeof path[1] === 'number' &&
      path[2] === 'enc' &&
      path[3] === 'slots' &&
      typeof path[4] === 'number'
    ) {
      return true;
    }
    if (path.length >= 2 && path[0] === 'slots' && typeof path[1] === 'number') {
      return true;
    }
    return false;
  })();

  const valueAtIssue = valueAtPath(decoded, path);
  const isMissing = valueAtIssue === undefined;

  switch (zissue.code) {
    case 'invalid_type':
      if (isInSlotEntry) return issue('ENC_SLOT_INVALID_SHAPE', path, zissue.message);
      if (isMissing) {
        if (inSigsEntry) return issue('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
        return issue('SCHEMA_MISSING_REQUIRED', path, zissue.message);
      }
      if (inSigsEntry) return issue('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
      return issue('SCHEMA_TYPE_MISMATCH', path, zissue.message);
    case 'invalid_value':
      // Zod 4's `z.literal(1)` emits `invalid_value` for both a missing field
      // AND a present-but-wrong value. Disambiguate via the runtime value:
      // missing → `SCHEMA_MISSING_REQUIRED`; present-but-wrong → `SCHEMA_INVALID_LITERAL`.
      if (path.length === 1 && path[0] === 'v') {
        return issue(
          isMissing ? 'SCHEMA_MISSING_REQUIRED' : 'SCHEMA_INVALID_LITERAL',
          path,
          zissue.message,
        );
      }
      return issue('SCHEMA_INVALID_LITERAL', path, zissue.message);
    case 'unrecognized_keys':
      if (isInSlotEntry) return issue('ENC_SLOT_INVALID_SHAPE', path, zissue.message);
      if (inSigsEntry) return issue('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
      return issue('SCHEMA_UNKNOWN_FIELD', path, zissue.message);
    case 'invalid_format':
    case 'too_big':
    case 'too_small':
      if (inSigsEntry) return issue('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
      return issue('SCHEMA_TYPE_MISMATCH', path, zissue.message);
    case 'invalid_union':
    case 'invalid_key':
    case 'invalid_element':
    case 'custom':
    default:
      if (isInSlotEntry) return issue('ENC_SLOT_INVALID_SHAPE', path, zissue.message);
      if (inSigsEntry) return issue('SIG_ENTRY_INVALID_SHAPE', path, zissue.message);
      return issue('SCHEMA_TYPE_MISMATCH', path, zissue.message);
  }
}

// =============================================================================
// Step 4 helpers — domain checks
// =============================================================================

// 4b — hash-map registry membership + digest length per algorithm.
function checkItemHashes(item: ItemEntry, idx: number, errors: ValidationIssue[]): void {
  const entries = Object.entries(item.hashes);
  if (entries.length === 0) {
    errors.push(
      issue(
        'SCHEMA_TYPE_MISMATCH',
        ['items', idx, 'hashes'],
        'hashes must be a non-empty CBOR map of <alg-id> -> <digest>',
      ),
    );
    return;
  }
  for (const [alg, digest] of entries) {
    if (!(alg in HASH_ALG_LENGTHS)) {
      errors.push(
        issue('UNSUPPORTED_HASH_ALG', ['items', idx, 'hashes', alg], `unknown hash alg: ${alg}`),
      );
      continue;
    }
    const expected = HASH_ALG_LENGTHS[alg]!;
    if (digest.length !== expected) {
      errors.push(
        issue(
          'HASH_DIGEST_LENGTH_MISMATCH',
          ['items', idx, 'hashes', alg],
          `hashes['${alg}'] digest length ${digest.length} != ${expected}`,
        ),
      );
    }
  }
}

// 4c — URI chunk reconstruction + per-scheme shape.
function checkItemUris(
  uris: ReadonlyArray<ReadonlyArray<string>>,
  basePath: ReadonlyArray<string | number>,
  errors: ValidationIssue[],
): void {
  uris.forEach((chunks, ui) => validateOneUri(chunks, [...basePath, ui], errors));
}

function validateOneUri(
  chunks: ReadonlyArray<string>,
  path: ReadonlyArray<string | number>,
  errors: ValidationIssue[],
): void {
  const reconstructed = reconstructChunkedUri(chunks);
  if (!reconstructed.ok) {
    errors.push(issue(reconstructed.code, path, reconstructed.reason));
    return;
  }
  const uri = reconstructed.uri;

  // Absolute URI, no fragment, scheme in `{ar://, ipfs://}`.
  if (uri.includes('#')) {
    errors.push(
      issue('INVALID_URI', path, "URI contains a fragment identifier ('#'), which is forbidden"),
    );
    return;
  }
  const sepIdx = uri.indexOf('://');
  if (sepIdx <= 0 || !/^[a-z][a-z0-9+.-]*$/i.test(uri.slice(0, sepIdx))) {
    errors.push(
      issue('INVALID_URI', path, 'URI is not absolute (missing scheme://hierarchical-part)'),
    );
    return;
  }
  // RFC 3986 §3.1: the scheme is case-insensitive, so case-fold the SCHEME ONLY,
  // then ALWAYS validate the body. The host / CID / txid is NOT case-folded — a
  // base64url Arweave txid and a base58btc CID are case-significant. An
  // uppercase scheme (`AR://`, `IPFS://`) is accepted iff its body passes the
  // same per-scheme shape check a lowercase scheme would.
  const scheme = uri.slice(0, sepIdx).toLowerCase();
  const rest = uri.slice(sepIdx + '://'.length);
  if (scheme === 'ar') {
    if (!/^ar:\/\/[A-Za-z0-9_-]{43}$/.test('ar://' + rest)) {
      errors.push(
        issue(
          'INVALID_URI',
          path,
          'ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` (43-char base64url txid, no path/query/fragment)',
        ),
      );
    }
    return;
  }
  if (scheme === 'ipfs') {
    // The structural validator does a full CID parse (not just a prefix check).
    const slashIdx = rest.indexOf('/');
    const cid = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    if (!validateCidProfile(cid)) {
      errors.push(
        issue('INVALID_URI', path, 'ipfs:// URI is not a valid CID under the Label 309 profile'),
      );
    }
    return;
  }
  // Scheme not in `{ar://, ipfs://}`.
  errors.push(
    issue('INVALID_URI', path, 'unsupported URI scheme; v1 PoE URI set is {ar://, ipfs://}'),
  );
}

// 4d — encryption envelope.
function checkItemEnc(item: ItemEntry, idx: number, errors: ValidationIssue[]): void {
  // Pre-check: an `enc`-bearing item MUST commit to a content hash. The claim
  // is the *plaintext* digest, so the hashes map MUST carry at least one
  // registered content-hash entry (sha2-256 / blake2b-256). This is a PRESENCE
  // check, not merely a non-empty check: a `hashes` map that exists but carries
  // only a non-content algorithm (e.g. `{md5}`) still fails — there is no
  // content digest to bind the ciphertext to. The empty-map case is also caught
  // here (and additionally fails the CDDL `1*` cardinality in checkItemHashes).
  const hasContentHash = Object.keys(item.hashes).some((alg) => alg in HASH_ALG_LENGTHS);
  if (!hasContentHash) {
    errors.push(
      issue(
        'ENC_REQUIRES_CONTENT_HASH',
        ['items', idx, 'enc'],
        'item carries `enc` but `hashes` has no content-hash entry (sha2-256 or blake2b-256)',
      ),
    );
    return;
  }

  // Schema-parse the envelope independently so we can lift its issues with
  // the correct path prefix.
  const encParse = EncryptionEnvelopeSchema.safeParse(item.enc);
  if (!encParse.success) {
    for (const zissue of encParse.error.issues) {
      const mapped = mapZodIssue(zissue, item.enc);
      errors.push({
        ...mapped,
        path: ['items', idx, 'enc', ...mapped.path],
      });
    }
    return;
  }
  const enc = encParse.data;
  const basePath: ReadonlyArray<string | number> = ['items', idx, 'enc'];

  // `enc.scheme` MUST be the unsigned integer 1.
  if (typeof enc.scheme !== 'number' || !Number.isInteger(enc.scheme) || enc.scheme !== 1) {
    errors.push(
      issue(
        'UNSUPPORTED_ENVELOPE_SCHEME',
        [...basePath, 'scheme'],
        `enc.scheme must be the unsigned integer 1; got ${String(enc.scheme)}`,
      ),
    );
    // Continue — other checks remain informative.
  }

  // AEAD checks (forbidden cipher first, then registry). The forbidden set is
  // the unauthenticated-cipher family — block-cipher modes that provide no
  // integrity (CBC, CTR, ECB, CFB, OFB) in any key-size spelling
  // (`aes-256-cbc`, `aes-128-cbc`, OpenSSL/JCA form) plus the legacy stream
  // ciphers (RC4, DES/3DES). Matching this family — rather than a generic
  // "unknown alg" fall-through to `UNSUPPORTED_AEAD_ALG` — names the security
  // hazard precisely: the record selected an authenticated-encryption-absent
  // cipher, not merely an unregistered one.
  if (UNAUTHENTICATED_CIPHER_RE.test(enc.aead)) {
    errors.push(
      issue(
        'UNAUTHENTICATED_CIPHER_FORBIDDEN',
        [...basePath, 'aead'],
        `'${enc.aead}' is an unauthenticated cipher; Label 309 mandates an authenticated (AEAD) cipher`,
      ),
    );
    return; // unrecoverable — nonce / kem / slot checks become noise
  }
  if (!(enc.aead in AEAD_NONCE_LENGTHS)) {
    errors.push(
      issue('UNSUPPORTED_AEAD_ALG', [...basePath, 'aead'], `unknown aead alg: ${enc.aead}`),
    );
    return;
  }
  const expectedNonceLen = AEAD_NONCE_LENGTHS[enc.aead]!;
  if (enc.nonce.length !== expectedNonceLen) {
    errors.push(
      issue(
        'NONCE_LENGTH_MISMATCH',
        [...basePath, 'nonce'],
        `nonce length ${enc.nonce.length} != ${expectedNonceLen} for ${enc.aead}`,
      ),
    );
  }

  // Envelope-level KEM check (when present).
  if (enc.kem !== undefined && !(enc.kem in KEM_SLOT_DESCRIPTORS)) {
    errors.push(issue('UNSUPPORTED_KEM_ALG', [...basePath, 'kem'], `unknown kem alg: ${enc.kem}`));
  }

  // Key-path branching.
  const hasSlots = enc.slots !== undefined;
  const hasSlotsMac = enc.slots_mac !== undefined;
  const hasPassphrase = enc.passphrase !== undefined;

  if (hasSlots && hasPassphrase) {
    errors.push(
      issue('ENC_EXCLUSIVITY_VIOLATION', basePath, 'enc combines slots with passphrase; pick one'),
    );
  }
  if (hasSlots && !hasSlotsMac) {
    errors.push(
      issue('ENC_SLOTS_MAC_REQUIRED', basePath, 'enc.slots present but enc.slots_mac absent'),
    );
  }
  if (hasSlotsMac && !hasSlots) {
    errors.push(
      issue('ENC_SLOTS_REQUIRED', basePath, 'enc.slots_mac present but enc.slots absent'),
    );
  }
  if (hasSlots && enc.kem === undefined) {
    errors.push(issue('ENC_KEM_REQUIRED', basePath, 'enc.slots present but enc.kem absent'));
  }
  if (!hasSlots && !hasPassphrase) {
    errors.push(
      issue(
        'ENC_NO_KEY_PATH',
        basePath,
        'enc requires either slots or passphrase — no on-chain key path otherwise',
      ),
    );
  }

  // Slots shape checks. The slot shape is KEM-driven: the descriptor for the
  // declared `kem` pins which ciphertext-bearing field (`epk` for x25519,
  // `kem_ct` for mlkem768x25519) MUST be present and at what length, and
  // forbids the other KEM's field. Because the schema is permissive (no
  // `.strict()`), this domain pass is the ONLY thing rejecting cross-KEM
  // contamination — an x25519 slot carrying a stray `kem_ct`, or a hybrid slot
  // carrying a stray `epk`, surfaces as `ENC_SLOT_INVALID_SHAPE`.
  if (hasSlots) {
    if (enc.slots!.length < 1) {
      errors.push(
        issue('ENC_SLOTS_EMPTY', [...basePath, 'slots'], `slots length ${enc.slots!.length} < 1`),
      );
    }
    // Only validate slot shape when the KEM is known; an unknown / absent KEM
    // already emits its own code above, and we cannot pick a descriptor.
    const descriptor = enc.kem !== undefined ? KEM_SLOT_DESCRIPTORS[enc.kem] : undefined;
    if (descriptor !== undefined) {
      // The permissive `SlotSchema` strips unknown keys before they reach the
      // parsed slot, so the closed-map invariant ("a slot is exactly {<ct
      // field>, wrap}") is enforced against the RAW decoded slot key set here.
      const rawSlotKeys = rawSlotKeySets(item.enc);
      enc.slots!.forEach((slot, si) => {
        checkSlotShape(
          slot,
          rawSlotKeys[si] ?? new Set<string>(),
          descriptor,
          enc.kem!,
          [...basePath, 'slots', si],
          errors,
        );
      });
    }
  }

  // Passphrase block checks (registry membership + Argon2id closed-params + floor).
  if (hasPassphrase) {
    const pp = enc.passphrase!;
    const ppPath: ReadonlyArray<string | number> = [...basePath, 'passphrase'];
    if (!PASSPHRASE_KDF_ALGS.has(pp.alg)) {
      errors.push(
        issue(
          'ENC_PASSPHRASE_ALG_UNSUPPORTED',
          [...ppPath, 'alg'],
          `unknown passphrase kdf alg: ${pp.alg}`,
        ),
      );
      return; // can't apply alg-specific params check
    }
    if (pp.alg === 'argon2id') {
      const allowed = new Set(['m', 't', 'p']);
      for (const k of Object.keys(pp.params)) {
        if (!allowed.has(k)) {
          errors.push(
            issue(
              'SCHEMA_UNKNOWN_FIELD',
              [...ppPath, 'params', k],
              `unknown argon2id params field: ${k}`,
            ),
          );
        }
      }
      const p = pp.params as { m?: unknown; t?: unknown; p?: unknown };
      const argonInt = (val: unknown, name: 'm' | 't' | 'p'): number | null => {
        if (typeof val !== 'number' || !Number.isInteger(val)) {
          errors.push(
            issue(
              'SCHEMA_TYPE_MISMATCH',
              [...ppPath, 'params', name],
              `argon2id params.${name} must be a CBOR unsigned integer`,
            ),
          );
          return null;
        }
        return val;
      };
      const mVal = argonInt(p.m, 'm');
      const tVal = argonInt(p.t, 't');
      const pVal = argonInt(p.p, 'p');
      if (mVal !== null && mVal < 65_536) {
        errors.push(
          issue(
            'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
            [...ppPath, 'params', 'm'],
            'argon2id requires m >= 65536 KiB',
          ),
        );
      }
      if (tVal !== null && tVal < 3) {
        errors.push(
          issue(
            'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
            [...ppPath, 'params', 't'],
            'argon2id requires t >= 3',
          ),
        );
      }
      if (pVal !== null && pVal < 1) {
        errors.push(
          issue(
            'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
            [...ppPath, 'params', 'p'],
            'argon2id requires p >= 1',
          ),
        );
      }
    }
  }
}

// KEM-driven per-slot shape gate (pure). Branches on the descriptor for the
// declared envelope `kem`:
//
//   - The descriptor's ciphertext-bearing field (`epk` for x25519, `kem_ct`
//     for mlkem768x25519) MUST be present at the expected (reassembled) length.
//   - The OTHER KEM's ciphertext field MUST be absent — its presence is
//     cross-KEM contamination and surfaces as `ENC_SLOT_INVALID_SHAPE` (the
//     hole that dropping `.strict()` on `SlotSchema` would otherwise open).
//   - `wrap` MUST be present at 48 bytes.
//
// This stays a pure function over already-decoded values: `kem_ct` reassembly
// uses `bytesChunkArrayConcat` (byte concatenation only) — no crypto, no I/O.
//
// `rawKeys` is the slot's key set as it appeared on the wire (before the
// permissive schema stripped unknowns); any key outside {<ct field>, wrap}
// for this KEM is a closed-map violation.
const SLOT_KEY_UNIVERSE: ReadonlySet<string> = new Set(['epk', 'kem_ct', 'wrap']);

function checkSlotShape(
  slot: Slot,
  rawKeys: ReadonlySet<string>,
  descriptor: KemSlotDescriptor,
  kem: string,
  slotPath: ReadonlyArray<string | number>,
  errors: ValidationIssue[],
): void {
  // The ciphertext field that does NOT belong to this KEM. Its presence is a
  // shape violation regardless of length. Drive this off the RAW key set so a
  // future schema change cannot silently drop the foreign field before we see
  // it.
  const foreignField: KemSlotField = descriptor.field === 'epk' ? 'kem_ct' : 'epk';
  if (rawKeys.has(foreignField)) {
    errors.push(
      issue(
        'ENC_SLOT_INVALID_SHAPE',
        [...slotPath, foreignField],
        `slot carries '${foreignField}' but kem='${kem}' expects '${descriptor.field}'`,
      ),
    );
  }

  // Any key outside the slot universe is a closed-map violation (the schema is
  // permissive and would otherwise strip it silently).
  for (const k of rawKeys) {
    if (!SLOT_KEY_UNIVERSE.has(k)) {
      errors.push(
        issue(
          'ENC_SLOT_INVALID_SHAPE',
          [...slotPath, k],
          `slot carries unexpected key '${k}'; a slot is a 2-key map {${descriptor.field}, wrap}`,
        ),
      );
    }
  }

  // The required ciphertext-bearing field MUST be present at the expected
  // (reassembled) length.
  if (descriptor.field === 'epk') {
    if (slot.epk === undefined) {
      errors.push(
        issue(
          'ENC_SLOT_INVALID_SHAPE',
          [...slotPath, 'epk'],
          `slot for kem='${kem}' is missing required 'epk'`,
        ),
      );
    } else if (slot.epk.length !== descriptor.fieldLength) {
      errors.push(
        issue(
          KEM_FIELD_LENGTH_CODE.epk,
          [...slotPath, 'epk'],
          `slot.epk length ${slot.epk.length} != ${descriptor.fieldLength} for ${kem}`,
        ),
      );
    }
  } else {
    if (slot.kem_ct === undefined) {
      errors.push(
        issue(
          'ENC_SLOT_INVALID_SHAPE',
          [...slotPath, 'kem_ct'],
          `slot for kem='${kem}' is missing required 'kem_ct'`,
        ),
      );
    } else {
      const reassembled = bytesChunkArrayConcat(slot.kem_ct).length;
      if (reassembled !== descriptor.fieldLength) {
        errors.push(
          issue(
            KEM_FIELD_LENGTH_CODE.kem_ct,
            [...slotPath, 'kem_ct'],
            `slot.kem_ct reassembles to ${reassembled} bytes != ${descriptor.fieldLength} for ${kem}`,
          ),
        );
      }
    }
  }

  // `wrap` is 48 bytes for every KEM.
  if (slot.wrap === undefined) {
    errors.push(
      issue(
        'ENC_SLOT_INVALID_SHAPE',
        [...slotPath, 'wrap'],
        `slot for kem='${kem}' is missing required 'wrap'`,
      ),
    );
  } else if (slot.wrap.length !== descriptor.wrapLength) {
    errors.push(
      issue(
        'WRAP_LENGTH_MISMATCH',
        [...slotPath, 'wrap'],
        `slot.wrap length ${slot.wrap.length} != ${descriptor.wrapLength}`,
      ),
    );
  }
}

// Extract the per-slot RAW key sets from a decoded `enc` value, BEFORE the
// permissive schema strips unknown slot keys. cbor2 surfaces a CBOR map either
// as a `Map` (int/heterogeneous keys) or a plain object (text keys); slot maps
// are text-keyed, so this reads string keys from whichever form. A slot that
// is not a map at all yields an empty set — the slot's own type errors are
// already emitted by the schema parse, so the shape gate simply finds no keys.
function rawSlotKeySets(rawEnc: unknown): ReadonlyArray<ReadonlySet<string>> {
  const slots = mapLikeGet(rawEnc, 'slots');
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

function mapLikeGet(value: unknown, key: string): unknown {
  if (value instanceof Map) return value.get(key);
  if (typeof value === 'object' && value !== null) {
    return (value as Record<string, unknown>)[key];
  }
  return undefined;
}

// 4i — `merkle[i]` walk.
function checkMerkleCommit(commit: MerkleCommit, idx: number, errors: ValidationIssue[]): void {
  const basePath: ReadonlyArray<string | number> = ['merkle', idx];
  if (!(commit.alg in MERKLE_COMMIT_ALG_LENGTHS)) {
    errors.push(
      issue(
        'UNSUPPORTED_MERKLE_COMMIT_ALG',
        [...basePath, 'alg'],
        `unknown merkle commitment alg: ${commit.alg}`,
      ),
    );
    return;
  }
  const expected = MERKLE_COMMIT_ALG_LENGTHS[commit.alg]!;
  if (commit.root.length !== expected) {
    errors.push(
      issue(
        'HASH_DIGEST_LENGTH_MISMATCH',
        [...basePath, 'root'],
        `merkle entry root length ${commit.root.length} != ${expected} for ${commit.alg}`,
      ),
    );
  }
  if (commit.uris) {
    checkItemUris(commit.uris, [...basePath, 'uris'], errors);
  }
}

// 4f + 4g — record-level signature entries.
function checkSigEntry(
  entry: SigEntry,
  idx: number,
  errors: ValidationIssue[],
  info: ValidationIssue[],
): void {
  // Path-2 `cose_key` private-material guard runs FIRST.
  if (entry.cose_key !== undefined) {
    const keyIssue = inspectCoseKey(entry.cose_key, idx);
    if (keyIssue !== null) {
      errors.push(keyIssue);
      return;
    }
  }

  // 4g — COSE_Sign1 structural decode.
  const merged = bytesChunkArrayConcat(entry.cose_sign1);
  let cose: ReturnType<typeof decodeCoseSign1>;
  try {
    cose = decodeCoseSign1(merged);
  } catch (cause) {
    errors.push(
      issue(
        'MALFORMED_SIG_COSE_SIGN1',
        ['sigs', idx],
        cause instanceof CoseVerifyError || cause instanceof Error ? cause.message : String(cause),
      ),
    );
    return;
  }

  // Detached-only payload — the COSE_Sign1 payload MUST be null.
  if (cose.payload !== null) {
    errors.push(
      issue(
        'MALFORMED_SIG_COSE_SIGN1',
        ['sigs', idx],
        'COSE_Sign1 payload must be null (detached); attached form forbidden',
      ),
    );
    return;
  }

  // Signature-algorithm registry check (info-severity — an unrecognised alg
  // does not fail the record).
  const alg = cose.protectedHeader.get(1);
  if (typeof alg !== 'number' || !KNOWN_SIG_ALG_IDS.has(alg)) {
    info.push(
      issue(
        'SIGNATURE_UNSUPPORTED',
        ['sigs', idx],
        `COSE_Sign1 protected alg ${String(alg)} not in {-8, -19}`,
      ),
    );
  }

  // Path-1 (32-byte protected-header `kid`) and path-2 (`cose_key` sidecar)
  // are mutually exclusive — a sig entry must not carry both.
  const protectedKid = cose.protectedHeader.get(4);
  if (
    protectedKid instanceof Uint8Array &&
    protectedKid.length === 32 &&
    entry.cose_key !== undefined
  ) {
    errors.push(
      issue(
        'SIG_ENTRY_KID_COSE_KEY_CONFLICT',
        ['sigs', idx],
        'sigs[i] carries both a 32-byte protected `kid` (path 1) and an inline `cose_key` (path 2); paths are mutually exclusive',
      ),
    );
  }
}

// =============================================================================
// COSE_Key inspector (path-2 `sigs[i].cose_key` blob)
// =============================================================================
//
// Two structural checks:
//   5a — Private-material guard (FIRST). COSE_Key label `-4` (the private
//        scalar `d` for OKP / EC2 per RFC 9052 §7.1) → `SIG_PRIVATE_KEY_LEAKED`.
//        This check is load-bearing producer-side preflight: publishing a
//        private key on the permanent ledger is catastrophic and irreversible.
//   5b — Positive-shape guard. The decoded `cbor<COSE_Key>` map MUST carry
//        `kty=1` (OKP), `crv=6` (Ed25519), and a 32-byte `-2` (x). Any
//        failure → `MALFORMED_SIG_COSE_SIGN1`.

function inspectCoseKey(keyChunks: ReadonlyArray<Uint8Array>, i: number): ValidationIssue | null {
  let decoded: unknown;
  try {
    decoded = decodeCanonicalCbor(bytesChunkArrayConcat(keyChunks));
  } catch (cause) {
    return issue(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key failed to decode as cbor<COSE_Key>: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  // cbor2 surfaces int-keyed COSE_Key maps as `Map`; string-keyed maps as
  // plain JS objects (a malformed COSE_Key would carry string keys).
  const getLabel = (label: number): unknown => {
    if (decoded instanceof Map) return decoded.get(label);
    if (typeof decoded === 'object' && decoded !== null) {
      return (decoded as Record<string, unknown>)[String(label)];
    }
    return undefined;
  };
  const hasLabel = (label: number): boolean => {
    if (decoded instanceof Map) return decoded.has(label);
    if (typeof decoded === 'object' && decoded !== null) {
      return Object.prototype.hasOwnProperty.call(decoded, String(label));
    }
    return false;
  };

  // 5a — Private-material guard.
  if (hasLabel(-4)) {
    return issue(
      'SIG_PRIVATE_KEY_LEAKED',
      ['sigs', i, 'cose_key'],
      'cose_key carries COSE_Key private-key material (label -4, the OKP/EC2 private scalar d); publishing a private key on the permanent ledger is forbidden',
    );
  }

  // 5b — Positive-shape guard.
  const kty = getLabel(1);
  if (kty !== 1) {
    return issue(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key COSE_Key kty (label 1) must be 1 (OKP); got ${String(kty)}`,
    );
  }
  const crv = getLabel(-1);
  if (crv !== 6) {
    return issue(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key COSE_Key crv (label -1) must be 6 (Ed25519); got ${String(crv)}`,
    );
  }
  if (!hasLabel(-2)) {
    return issue(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key COSE_Key missing label -2 (Ed25519 public-key bytes)`,
    );
  }
  const x = getLabel(-2);
  if (!(x instanceof Uint8Array) || x.length !== 32) {
    const got = x instanceof Uint8Array ? `${x.length}-byte bstr` : typeof x;
    return issue(
      'MALFORMED_SIG_COSE_SIGN1',
      ['sigs', i, 'cose_key'],
      `sigs[${i}].cose_key COSE_Key label -2 must be a 32-byte byte string (Ed25519 public key); got ${got}`,
    );
  }
  return null;
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
// `0x12` = sha2-256; `0xb220` = blake2b-256.
const ACCEPTED_MULTIHASHES: ReadonlyMap<number, number> = new Map([
  [0x12, 32],
  [0xb220, 32],
]);

export function validateCidProfile(cid: string): boolean {
  if (cid.length === 0) return false;
  // CIDv0: a base58btc-encoded sha2-256 multihash. Decode the WHOLE string and
  // verify the multihash prefix (0x12 = sha2-256, 0x20 = 32-byte digest length)
  // and total length (34 bytes = 2-byte prefix + 32-byte digest). A `Qm`
  // prefix alone is not sufficient — a malformed body must be rejected.
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
    if (shift > 28) return null; // overflow guard; Label 309 profile uses ≤ 16-bit codes
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
  // Multibase strips padding per spec; we accept either form for robustness.
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

// =============================================================================
// `crit[]` shape rule helper
// =============================================================================

function checkCritShape(
  record: PoeRecord,
  decodedTopKeys: ReadonlySet<string>,
  errors: ValidationIssue[],
): Set<number> {
  const invalid = new Set<number>();
  if (!Array.isArray(record.crit)) return invalid;
  // `crit` has `1*` cardinality: when present it MUST carry at least one
  // entry. An empty array is a malformed shape — reject it here in the
  // domain pass (rather than via a schema `.min(1)`) so the emitted message
  // string is identical across the TS/PY/RS validators.
  if (record.crit.length === 0) {
    errors.push(
      issue('SCHEMA_TYPE_MISMATCH', ['crit'], 'crit[] must carry at least one entry when present'),
    );
    return invalid;
  }
  const seen = new Set<string>();
  for (let i = 0; i < record.crit.length; i++) {
    const critName = record.crit[i]!;
    let reason: string | null = null;
    if (TOP_LEVEL_BASE_KEYS.has(critName)) {
      reason = `'${critName}' is a base key and MUST NOT appear in crit[]`;
    } else if (!isExtensionKey(critName)) {
      reason = `'${critName}' does not match the extension-key regex (^x-.+ or ^[a-z]+-.+)`;
    } else if (!decodedTopKeys.has(critName)) {
      reason = `'${critName}' is named in crit but absent from the record map`;
    } else if (seen.has(critName)) {
      reason = `'${critName}' appears more than once in crit[]`;
    }
    seen.add(critName);
    if (reason !== null) {
      invalid.add(i);
      errors.push(issue('CRIT_SHAPE_INVALID', ['crit', i], reason));
    }
  }
  return invalid;
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
// Path / issue helpers
// =============================================================================

function issue(
  code: ErrorCode,
  path: ReadonlyArray<string | number>,
  message: string,
): ValidationIssue {
  return { code, path, message, severity: SEVERITY[code] };
}

function compareIssuePath(a: ValidationIssue, b: ValidationIssue): number {
  return a.path.join('.').localeCompare(b.path.join('.'));
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
