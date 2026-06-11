export type SeedDeriveErrorCode = 'INVALID_SEED_LENGTH';

export class SeedDeriveError extends Error {
  readonly code: SeedDeriveErrorCode;

  constructor(code: SeedDeriveErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'SeedDeriveError';
    this.code = code;
  }
}

export type SeedEncodingErrorCode =
  | 'INVALID_SEED_LENGTH'
  | 'SEED_STRING_MIXED_CASE'
  | 'SEED_STRING_BAD_CHECKSUM'
  | 'SEED_STRING_WRONG_HRP'
  | 'SEED_STRING_WRONG_LENGTH'
  | 'SEED_STRING_UNRECOGNIZED';

// Raised by the identity-seed string codec (`encodeIdentitySeed` /
// `parseIdentitySeed`). The codes are the cross-implementation contract: every
// conforming implementation rejects the same malformed input with the same code.
export class SeedEncodingError extends Error {
  readonly code: SeedEncodingErrorCode;

  constructor(code: SeedEncodingErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'SeedEncodingError';
    this.code = code;
  }
}
