export type SeedDeriveErrorCode = 'INVALID_SEED_LENGTH';

export class SeedDeriveError extends Error {
  readonly code: SeedDeriveErrorCode;

  constructor(code: SeedDeriveErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'SeedDeriveError';
    this.code = code;
  }
}
