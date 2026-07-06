// Label 309 v1 Proof-of-Existence record — public surface.
//
// Implements the Label 309 wire format: the record schemas, the
// canonical-CBOR encoder, the metadata-label-309 chunk-array transport, the
// Part A structural validator, and the canonical error-code catalogue.
//
// The package exports:
//   - The Zod schemas + inferred types for every wire-format role.
//   - `encodePoeRecord(record)` / `encodeRecordBodyForSigning(record)` —
//     canonical-CBOR encoders for chain submission and record-level signing.
//   - `chunkRecordBody` / `encodeLabel309Value` / `reassembleLabel309Value` —
//     the whole-body ≤ 64-byte chunk-array transport (both directions).
//   - `validatePoeRecord(bytes, options?)` — pure structural validator
//     returning a discriminated `ValidationResult`; never throws.
//   - `validateCidProfile` — the offline CID-profile parser.
//   - `ERROR_CODES` + the per-layer views, the `ErrorCode` union, and the
//     `SEVERITY` map, for downstream verifiers to dispatch on the canonical
//     error-code taxonomy.

export {
  // Schemas
  PoeRecordSchema,
  ItemEntrySchema,
  MerkleCommitSchema,
  EncryptionEnvelopeSchema,
  EncScheme1Schema,
  EncOpaqueSchema,
  SlotSchema,
  PassphraseBlockSchema,
  Argon2idParamsSchema,
  HashesMapSchema,
  HashDigestSchema,
  UriSchema,
  SigEntrySchema,
  SupersedesSchema,
  VersionLiteralSchema,
  // Types
  type PoeRecord,
  type ItemEntry,
  type MerkleCommit,
  type EncryptionEnvelope,
  type EncScheme1,
  type EncOpaque,
  type Slot,
  type PassphraseBlock,
  type Argon2idParams,
  type HashesMap,
  type Uri,
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
  chunkRecordBody,
  encodeLabel309Value,
  reassembleLabel309Value,
  TRANSPORT_CHUNK_MAX_BYTES,
  type Label309ReassemblyResult,
} from './carriage';

export {
  validatePoeRecord,
  validateCidProfile,
  fetchSetUriRejection,
  isFetchSetUri,
  isArweaveTxUri,
  DEFAULT_PASSPHRASE_PARAMS_CEILING,
  type ValidationResult,
  type ValidationIssue,
  type ValidatorOptions,
  type ValidatorRole,
  type Argon2ParamsCeiling,
} from './validator';

export {
  ERROR_CODES,
  ERROR_CODE_PART,
  STRUCTURAL_ERROR_CODES,
  CARRIAGE_ERROR_CODES,
  VERIFIER_ERROR_CODES,
  SEVERITY,
  DUAL_SEVERITY_CODES,
  severityOf,
  errorCodeRegistryIndex,
  type ErrorCode,
  type ErrorCodePart,
  type StructuralErrorCode,
  type VerifierErrorCode,
  type Severity,
} from './error-codes';
