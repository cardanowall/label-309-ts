export type CoseVerifyErrorCode =
  | 'MALFORMED_SIG_COSE'
  | 'MALFORMED_SIG_COSE_SIGN1'
  | 'UNSUPPORTED_SIG_ALG'
  | 'KID_UNRESOLVED'
  | 'SIGNATURE_INVALID';

export class CoseVerifyError extends Error {
  readonly code: CoseVerifyErrorCode;

  constructor(code: CoseVerifyErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'CoseVerifyError';
    this.code = code;
  }
}

export type CoseVerifyResult =
  | { ok: true; signerKey: Uint8Array; alg: number }
  | { ok: false; error: { code: CoseVerifyErrorCode; message: string } };
