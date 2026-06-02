// Sealed-PoE error taxonomy (wire-shape + partitioning-oracle pre-checks).

export type EciesSealedPoeErrorCode =
  | 'ENC_SLOTS_EMPTY'
  | 'ENC_SLOTS_REQUIRED'
  | 'ENC_SLOTS_MAC_REQUIRED'
  | 'ENC_SLOTS_MAC_INVALID_LENGTH'
  | 'KEM_EPK_LENGTH_MISMATCH'
  | 'KEM_CT_LENGTH_MISMATCH'
  | 'INVALID_CEK_LENGTH'
  | 'NONCE_LENGTH_MISMATCH'
  | 'INVALID_EPHEMERAL_SECRET_LENGTH'
  | 'EPHEMERAL_SECRETS_COUNT_MISMATCH'
  | 'UNSUPPORTED_ENC_VERSION'
  | 'UNSUPPORTED_AEAD_ALG'
  | 'UNSUPPORTED_KEM_ALG'
  | 'INVALID_ENVELOPE_SHAPE'
  | 'INVALID_RECIPIENT_KEY'
  | 'WRAP_LENGTH_MISMATCH';

export class EciesSealedPoeError extends Error {
  readonly code: EciesSealedPoeErrorCode;

  constructor(code: EciesSealedPoeErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'EciesSealedPoeError';
    this.code = code;
  }
}
