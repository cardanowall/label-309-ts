// Every canonical-CBOR decode violation collapses to the single public Label 309
// taxonomy code MALFORMED_CBOR: indefinite-length (streaming) items, duplicate
// keys, unsorted keys, non-minimal integer encodings, and invalid UTF-8 in text
// strings. The taxonomy intentionally has one code for all of these; the
// specific cause survives in the human-readable error message, not as a
// separate code.
export type CanonicalCborErrorCode = 'MALFORMED_CBOR';

export class CanonicalCborError extends Error {
  readonly code: CanonicalCborErrorCode;

  constructor(code: CanonicalCborErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'CanonicalCborError';
    this.code = code;
  }
}
