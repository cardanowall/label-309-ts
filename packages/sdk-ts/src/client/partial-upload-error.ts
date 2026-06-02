// Raised by the high-level helpers (`publishSealed`, `publishMerkle`) when
// one or more files uploaded via /poe/uploads come back with `ok: false`.
//
// The error carries the full `UploadsResponse` so callers can:
//   - retry just the failed indices (use `failedIndices` to subset their input)
//   - inspect per-file `error.code` / `error.detail` for diagnostics
//   - see which files DID land (already-uploaded files are billed and the
//     URIs remain valid; reuploading them would double-charge)

import type { UploadFailureEntry, UploadsResponse } from './types';

export class PartialUploadError extends Error {
  public readonly response: UploadsResponse;
  public readonly failed: ReadonlyArray<UploadFailureEntry>;

  constructor(response: UploadsResponse) {
    const failed = response.uploads.filter((u): u is UploadFailureEntry => u.ok === false);
    super(
      `${failed.length} of ${response.uploads.length} upload(s) failed: ${failed
        .map((f) => `[${f.idx}] ${f.error.code} — ${f.error.detail}`)
        .join('; ')}`,
    );
    this.name = 'PartialUploadError';
    this.response = response;
    this.failed = failed;
  }

  /** Convenience: the `idx` of every failed entry, in input order. */
  get failedIndices(): ReadonlyArray<number> {
    return this.failed.map((f) => f.idx);
  }
}
