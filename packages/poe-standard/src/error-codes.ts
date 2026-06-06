// Label 309 v1 error-code catalogue — single source of truth for the
// structural-validator codes (Part A) and the verifier-layer codes (Part B)
// that downstream verifiers re-export from this package.
//
// The structural validator emits ONLY Part A codes. Part B codes are
// re-exported so consumers can `import { ErrorCode } from '@cardanowall/poe-standard'`
// and dispatch on a single union type without round-tripping through the
// verifier package.
//
// Codes are SCREAMING_SNAKE_CASE and MUST match the canonical taxonomy
// byte-exact across the TS/PY/RS implementations — no lowercase synonyms,
// no `schema_*`-prefixed parser-internal codes.

// =============================================================================
// Part A — structural validator codes
// =============================================================================
export const STRUCTURAL_ERROR_CODES = [
  // CBOR decode layer. A single code covers every canonical-decode failure —
  // malformed/truncated bytes, indefinite-length encodings, non-canonical
  // (unsorted) map-key ordering, duplicate map keys, non-minimal integers, and
  // invalid UTF-8 — by design (no separate duplicate-key code).
  'MALFORMED_CBOR',
  // Generic schema-layer
  'SCHEMA_TYPE_MISMATCH',
  'SCHEMA_MISSING_REQUIRED',
  'SCHEMA_UNKNOWN_FIELD',
  'SCHEMA_INVALID_LITERAL',
  'SCHEMA_EMPTY_RECORD',
  // Hash-map
  'HASH_DIGEST_LENGTH_MISMATCH',
  'UNSUPPORTED_HASH_ALG',
  // Top-level `merkle[]`
  'UNSUPPORTED_MERKLE_COMMIT_ALG',
  // URI / chunking. A chunk whose bytes do not reconstruct to valid UTF-8
  // surfaces as MALFORMED_CBOR at decode (cbor2 rejects invalid-UTF-8 tstr)
  // or, in the residual reconstruct guard, as INVALID_URI — there is no
  // separate codepoint-split code.
  'INVALID_URI',
  'CHUNK_TOO_LARGE',
  // Encryption envelope
  'UNAUTHENTICATED_CIPHER_FORBIDDEN',
  'UNSUPPORTED_AEAD_ALG',
  'NONCE_LENGTH_MISMATCH',
  'UNSUPPORTED_ENVELOPE_SCHEME',
  'ENC_SLOTS_EMPTY',
  'ENC_SLOT_INVALID_SHAPE',
  'ENC_SLOTS_DUPLICATE_KEM_MATERIAL',
  'ENC_SLOTS_TOO_MANY',
  'ENC_ENVELOPE_TOO_LARGE',
  'UNSUPPORTED_KEM_ALG',
  'ENC_KEM_REQUIRED',
  'KEM_EPK_LENGTH_MISMATCH',
  'KEM_CT_LENGTH_MISMATCH',
  'WRAP_LENGTH_MISMATCH',
  'ENC_SLOTS_MAC_INVALID_LENGTH',
  'ENC_SLOTS_MAC_REQUIRED',
  'ENC_SLOTS_REQUIRED',
  'ENC_EXCLUSIVITY_VIOLATION',
  'ENC_NO_KEY_PATH',
  'ENC_REQUIRES_CONTENT_HASH',
  'ENC_PASSPHRASE_ALG_UNSUPPORTED',
  'ENC_PASSPHRASE_SALT_TOO_SHORT',
  'ENC_PASSPHRASE_SALT_TOO_LONG',
  'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW',
  'ENC_PASSPHRASE_PARAMS_EXCEED_POLICY',
  // Signatures
  'MALFORMED_SIG_COSE_SIGN1',
  'SIGNATURE_UNSUPPORTED',
  'SIG_ENTRY_INVALID_SHAPE',
  'SIG_ENTRY_KID_COSE_KEY_CONFLICT',
  'SIG_PRIVATE_KEY_LEAKED',
  // Supersedence
  'SUPERSEDES_TX_INVALID_LENGTH',
  // Forward-compat critical extensions
  'EXTENSION_UNSUPPORTED_CRITICAL',
  'CRIT_SHAPE_INVALID',
] as const;

// =============================================================================
// Part B — verifier-layer codes
// Re-exported so downstream verifiers can dispatch on a single union.
// The structural validator NEVER emits these.
// =============================================================================
export const VERIFIER_ERROR_CODES = [
  'METADATA_NOT_FOUND',
  'INSUFFICIENT_CONFIRMATIONS',
  'SIGNATURE_INVALID',
  'SIGNER_KEY_UNRESOLVED',
  'WALLET_ADDRESS_MISMATCH',
  'URI_TARGET_FORBIDDEN',
  'URI_INTEGRITY_MISMATCH',
  'URI_FETCH_FAILED',
  'CONTENT_UNAVAILABLE',
  'CIPHERTEXT_UNAVAILABLE',
  'PROVIDER_UNAVAILABLE',
  'SERVICE_INDEPENDENCE_VIOLATION',
  'WRONG_DECRYPTION_INPUT_SHAPE',
  'WRONG_RECIPIENT_KEY',
  'TAMPERED_HEADER',
  'TAMPERED_CIPHERTEXT',
  'KDF_DERIVATION_FAILED',
  'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH',
  'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED',
  'SCHEMA_MERKLE_LEAVES_MALFORMED',
  'MERKLE_ROOT_MISMATCH',
  'MERKLE_LEAVES_UNAVAILABLE',
  'MERKLE_LEAVES_INFORMATIVE_FORM',
  'MERKLE_UNSUPPORTED',
  'OUT_OF_PROFILE_SKIPPED',
] as const;

export const ERROR_CODES = [...STRUCTURAL_ERROR_CODES, ...VERIFIER_ERROR_CODES] as const;

export type StructuralErrorCode = (typeof STRUCTURAL_ERROR_CODES)[number];
export type VerifierErrorCode = (typeof VERIFIER_ERROR_CODES)[number];
export type ErrorCode = (typeof ERROR_CODES)[number];

// Severity classification. Codes not listed are `error` by default.
//
// `info` — a deliberate non-check (algorithm out of profile, unrecognised
// signature algorithm at the opt-in informational tier).
//
// `warning` — a non-fatal anomaly that occurred at runtime but did not
// invalidate the record (e.g. a transient gateway failure, partial leaves
// availability).
//
// `MERKLE_UNSUPPORTED` / `OUT_OF_PROFILE_SKIPPED` carry dual severity
// (`info` when another commitment was validated; `error` for the
// merkle-only / strict-mode case). The verifier emits the resolved severity
// per-issue; this map records the default `info` reading.
export type Severity = 'error' | 'warning' | 'info';

export const SEVERITY: Readonly<Record<ErrorCode, Severity>> = Object.freeze({
  // --- Part A ---
  MALFORMED_CBOR: 'error',
  SCHEMA_TYPE_MISMATCH: 'error',
  SCHEMA_MISSING_REQUIRED: 'error',
  SCHEMA_UNKNOWN_FIELD: 'error',
  SCHEMA_INVALID_LITERAL: 'error',
  SCHEMA_EMPTY_RECORD: 'error',
  HASH_DIGEST_LENGTH_MISMATCH: 'error',
  UNSUPPORTED_HASH_ALG: 'error',
  UNSUPPORTED_MERKLE_COMMIT_ALG: 'error',
  INVALID_URI: 'error',
  CHUNK_TOO_LARGE: 'error',
  UNAUTHENTICATED_CIPHER_FORBIDDEN: 'error',
  UNSUPPORTED_AEAD_ALG: 'error',
  NONCE_LENGTH_MISMATCH: 'error',
  UNSUPPORTED_ENVELOPE_SCHEME: 'error',
  ENC_SLOTS_EMPTY: 'error',
  ENC_SLOT_INVALID_SHAPE: 'error',
  ENC_SLOTS_DUPLICATE_KEM_MATERIAL: 'error',
  ENC_SLOTS_TOO_MANY: 'error',
  ENC_ENVELOPE_TOO_LARGE: 'error',
  UNSUPPORTED_KEM_ALG: 'error',
  ENC_KEM_REQUIRED: 'error',
  KEM_EPK_LENGTH_MISMATCH: 'error',
  KEM_CT_LENGTH_MISMATCH: 'error',
  WRAP_LENGTH_MISMATCH: 'error',
  ENC_SLOTS_MAC_INVALID_LENGTH: 'error',
  ENC_SLOTS_MAC_REQUIRED: 'error',
  ENC_SLOTS_REQUIRED: 'error',
  ENC_EXCLUSIVITY_VIOLATION: 'error',
  ENC_NO_KEY_PATH: 'error',
  ENC_REQUIRES_CONTENT_HASH: 'error',
  ENC_PASSPHRASE_ALG_UNSUPPORTED: 'error',
  ENC_PASSPHRASE_SALT_TOO_SHORT: 'error',
  ENC_PASSPHRASE_SALT_TOO_LONG: 'error',
  ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW: 'error',
  ENC_PASSPHRASE_PARAMS_EXCEED_POLICY: 'error',
  MALFORMED_SIG_COSE_SIGN1: 'error',
  SIGNATURE_UNSUPPORTED: 'info',
  SIG_ENTRY_INVALID_SHAPE: 'error',
  SIG_ENTRY_KID_COSE_KEY_CONFLICT: 'error',
  SIG_PRIVATE_KEY_LEAKED: 'error',
  SUPERSEDES_TX_INVALID_LENGTH: 'error',
  EXTENSION_UNSUPPORTED_CRITICAL: 'error',
  CRIT_SHAPE_INVALID: 'error',
  // --- Part B ---
  METADATA_NOT_FOUND: 'error',
  INSUFFICIENT_CONFIRMATIONS: 'info',
  SIGNATURE_INVALID: 'error',
  SIGNER_KEY_UNRESOLVED: 'error',
  WALLET_ADDRESS_MISMATCH: 'error',
  URI_TARGET_FORBIDDEN: 'error',
  URI_INTEGRITY_MISMATCH: 'error',
  URI_FETCH_FAILED: 'warning',
  CONTENT_UNAVAILABLE: 'error',
  CIPHERTEXT_UNAVAILABLE: 'error',
  PROVIDER_UNAVAILABLE: 'error',
  SERVICE_INDEPENDENCE_VIOLATION: 'error',
  WRONG_DECRYPTION_INPUT_SHAPE: 'error',
  WRONG_RECIPIENT_KEY: 'error',
  TAMPERED_HEADER: 'error',
  TAMPERED_CIPHERTEXT: 'error',
  KDF_DERIVATION_FAILED: 'error',
  SCHEMA_MERKLE_LEAF_COUNT_MISMATCH: 'error',
  SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED: 'error',
  SCHEMA_MERKLE_LEAVES_MALFORMED: 'error',
  MERKLE_ROOT_MISMATCH: 'error',
  MERKLE_LEAVES_UNAVAILABLE: 'warning',
  MERKLE_LEAVES_INFORMATIVE_FORM: 'info',
  // Dual-severity — default reading is `info`; the verifier promotes to
  // `error` for merkle-only records (no `items[]` content claim was
  // validated in the same record).
  MERKLE_UNSUPPORTED: 'info',
  // Dual-severity — default reading is `info` (render mode); strict
  // end-to-end verifiers promote to `error`.
  OUT_OF_PROFILE_SKIPPED: 'info',
});

export function severityOf(code: ErrorCode): Severity {
  return SEVERITY[code];
}
