// Sealed-PoE construction error taxonomy (wire-shape + partitioning-oracle
// pre-checks + caller-input validation).
//
// Codes whose concept exists in the wire error-code registry reuse the registry
// string verbatim (UNSUPPORTED_ENVELOPE_SCHEME, UNSUPPORTED_AEAD_ALG,
// ENC_PASSPHRASE_EMPTY, ...), so a consumer correlating construction failures
// with validator/verifier reports sees one vocabulary. Conditions that exist
// only at the construction API boundary (raw caller-input lengths, deterministic
// test-override mismatches) carry construction-local names with no wire
// counterpart.

export type EciesSealedPoeErrorCode =
  // Wire-registry codes (same concept, same string).
  | 'ENC_SLOTS_EMPTY'
  | 'ENC_SLOTS_MAC_INVALID_LENGTH'
  | 'ENC_SLOTS_DUPLICATE_KEM_MATERIAL'
  | 'ENC_SLOTS_TOO_MANY'
  | 'ENC_ENVELOPE_TOO_LARGE'
  | 'ENC_REQUIRES_CONTENT_HASH'
  | 'ENC_PASSPHRASE_EMPTY'
  | 'ENC_PASSPHRASE_UNNORMALIZABLE'
  | 'ENC_PASSPHRASE_ALG_UNSUPPORTED'
  | 'ENC_PASSPHRASE_SALT_TOO_SHORT'
  | 'ENC_PASSPHRASE_SALT_TOO_LONG'
  | 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW'
  | 'KEM_EPK_LENGTH_MISMATCH'
  | 'KEM_CT_LENGTH_MISMATCH'
  | 'NONCE_LENGTH_MISMATCH'
  | 'WRAP_LENGTH_MISMATCH'
  | 'UNSUPPORTED_ENVELOPE_SCHEME'
  | 'UNSUPPORTED_AEAD_ALG'
  | 'UNSUPPORTED_KEM_ALG'
  | 'KDF_DERIVATION_FAILED'
  // Construction-local codes (no wire counterpart).
  | 'INVALID_CEK_LENGTH'
  | 'INVALID_EPHEMERAL_SECRET_LENGTH'
  | 'EPHEMERAL_SECRETS_COUNT_MISMATCH'
  | 'INVALID_RECIPIENT_KEY'
  | 'INVALID_PASSPHRASE_PARAMS'
  | 'PASSPHRASE_INPUT_TOO_LONG';

export class EciesSealedPoeError extends Error {
  readonly code: EciesSealedPoeErrorCode;

  constructor(code: EciesSealedPoeErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'EciesSealedPoeError';
    this.code = code;
  }
}
