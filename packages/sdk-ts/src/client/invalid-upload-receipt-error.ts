// Raised during resume-receipt validation when a receipt does not match the
// prepared material it claims to cover. `submitSealed` runs this check before
// any network call and, on failure, surfaces this error as the `cause` of the
// `SubmitSealedError` it rejects with — it does not escape `submitSealed`
// directly. Validating first means a mistaken receipt can never cause a
// mismatched record to publish or a wrong item to be skipped.

/** An upload receipt passed for resume failed validation. */
export class InvalidUploadReceiptError extends Error {
  /** What failed to match. */
  readonly detail: string;

  constructor(detail: string) {
    super(`INVALID_UPLOAD_RECEIPT: ${detail}`);
    this.name = 'InvalidUploadReceiptError';
    this.detail = detail;
  }
}
