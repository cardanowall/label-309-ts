export * from './fetch/index';
export * from './verifier/index';
export * from './hex';
export * from './client/index';
export * from './ids/index';
// (consumers may `import { encodePrefixedId, PoeIdSchema } from '@cardanowall/sdk-ts'`)

// Namespaced re-exports — consumers may use either
//   `import { merkleSha2256Root } from '@cardanowall/sdk-ts/merkle'`
// or the bundle import
//   `import { merkle, hash } from '@cardanowall/sdk-ts'`.
export * as merkle from './merkle/index';
export * as hash from './hash/index';

export {
  validatePoeRecord,
  encodePoeRecord,
  encodeRecordBodyForSigning,
  STRUCTURAL_ERROR_CODES,
  VERIFIER_ERROR_CODES,
  ERROR_CODES,
  SEVERITY,
  severityOf,
  PoeRecordSchema,
} from '@cardanowall/poe-standard';

export type {
  ValidationResult,
  ValidationIssue,
  ValidatorOptions,
  ValidatorRole,
  ErrorCode,
  StructuralErrorCode,
  VerifierErrorCode,
  Severity,
  PoeRecord,
  ItemEntry,
  MerkleCommit,
  EncryptionEnvelope,
  Slot,
  SigEntry,
  Supersedes,
} from '@cardanowall/poe-standard';

export { eciesSealedPoeWrap, eciesSealedPoeUnwrap } from '@cardanowall/crypto-core/sealed-poe';

// Raw-seed identity surface: derive keypairs, age recipient strings, a path-1
// Signer, the recipient key bundle, and sealed-PoE decrypt — all from a
// 32-byte seed, no web account envelope required.
export {
  deriveKeysFromSeed,
  recipientsFromSeed,
  signerFromSeed,
  recipientKeyBundleFromSeed,
  decryptSealedFromSeed,
} from './identity/index';
export type { SeedKeys, SeedRecipients, DecryptSealedFromSeedArgs } from './identity/index';

// Canonical age recipient codecs (also reachable seed-free for callers that
// already hold raw KEM public keys). `parseAgeRecipient` is the decode side: a
// sender turns a recipient string a peer shared back into the raw KEM public
// key needed to seal a record to them.
export {
  encodeAgeX25519Recipient,
  encodeAgeXWingRecipient,
  parseAgeRecipient,
} from '@cardanowall/crypto-core/recipient';
export type { ParsedAgeRecipient, RecipientKem } from '@cardanowall/crypto-core/recipient';

// Re-export the derive primitives + types so a seed holder can compose flows
// the high-level helpers don't cover (these were previously only reachable via
// the private crypto-core package).
export {
  deriveEd25519KeypairFromSeed,
  deriveX25519KeypairFromSeed,
  deriveMlKem768X25519KeypairFromSeed,
} from '@cardanowall/crypto-core/seed-derive';
export type {
  DerivedEd25519KeyPair,
  DerivedX25519KeyPair,
  DerivedMlKem768X25519KeyPair,
} from '@cardanowall/crypto-core/seed-derive';

// The identity-seed string codec: `encodeIdentitySeed` renders a 32-byte seed
// as the checksummed uppercase `L309-SEED-1…` form; `parseIdentitySeed`
// accepts that form (either single case) or 64-char raw hex and returns the
// seed bytes, raising `SeedEncodingError` on anything malformed.
export {
  encodeIdentitySeed,
  parseIdentitySeed,
  IDENTITY_SEED_HRP,
  SeedEncodingError,
} from '@cardanowall/crypto-core/seed-derive';
export type { SeedEncodingErrorCode } from '@cardanowall/crypto-core/seed-derive';

// The recipient key bundle type used by the unwrap dispatch.
export type { RecipientKeyBundle } from '@cardanowall/crypto-core/sealed-poe';
