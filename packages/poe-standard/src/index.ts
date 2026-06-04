// Label 309 v1 Proof-of-Existence record — public surface.
//
// Implements the Label 309 wire format and its Part A structural validator.
//
// The package exports:
//   - The Zod schemas + inferred types for every wire-format role.
//   - `encodePoeRecord(record)` and `encodeRecordBodyForSigning(record)` —
//     canonical-CBOR encoders for chain submission and record-level
//     signing respectively.
//   - `validatePoeRecord(bytes)` — pure structural validator returning a
//     discriminated `ValidateResult`; never throws.
//   - `ERROR_CODES` / `STRUCTURAL_ERROR_CODES` / `VERIFIER_ERROR_CODES`
//     + the `ErrorCode` union + the `SEVERITY` map for downstream
//     verifiers to dispatch on the canonical error-code taxonomy.
//   - `chunkBytes` / `chunkUri` / `bytesChunkArrayConcat` /
//     `reconstructChunkedUri` — chunking helpers.
//   - `validateCidProfile` — offline CID-profile parser.

export {
  // Schemas
  PoeRecordSchema,
  ItemEntrySchema,
  MerkleCommitSchema,
  EncryptionEnvelopeSchema,
  SlotSchema,
  PassphraseBlockSchema,
  Argon2idParamsSchema,
  HashesMapSchema,
  HashDigestSchema,
  UriChunkArraySchema,
  ChunkedBytesArraySchema,
  SigEntrySchema,
  SupersedesSchema,
  VersionLiteralSchema,
  // Types
  type PoeRecord,
  type ItemEntry,
  type MerkleCommit,
  type EncryptionEnvelope,
  type Slot,
  type PassphraseBlock,
  type Argon2idParams,
  type HashesMap,
  type UriChunkArray,
  type ChunkedBytesArray,
  type SigEntry,
  type Supersedes,
  // Extension-key helpers
  TOP_LEVEL_BASE_KEYS,
  EXTENSION_KEY_VENDOR_RE,
  EXTENSION_KEY_COMPANION_RE,
  isExtensionKey,
} from './schema';

export { encodePoeRecord, encodeRecordBodyForSigning } from './encoder';

export {
  validatePoeRecord,
  validateCidProfile,
  type ValidateResult,
  type ValidationIssue,
} from './validator';

export {
  ERROR_CODES,
  STRUCTURAL_ERROR_CODES,
  VERIFIER_ERROR_CODES,
  SEVERITY,
  severityOf,
  type ErrorCode,
  type StructuralErrorCode,
  type VerifierErrorCode,
  type Severity,
} from './error-codes';

export {
  chunkBytes,
  chunkUri,
  bytesChunkArrayConcat,
  reconstructChunkedUri,
  type ReconstructUriResult,
} from './chunked';
