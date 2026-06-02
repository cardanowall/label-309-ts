export class AeadVerificationError extends Error {
  readonly code: string = 'aead_verification_failed';

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'AeadVerificationError';
  }
}
