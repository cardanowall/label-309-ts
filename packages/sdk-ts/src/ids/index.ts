// Public surface for the prefixed-id helpers. Re-exported from the top-level
// SDK barrel so consumers can `import { encodePrefixedId, PoeIdSchema } from '@cardanowall/sdk-ts'`.
//
// The generic prefixed-id codec (Crockford-base32 + encode/decode) is exposed
// for any gateway that mints Stripe-style `<prefix>_<base32>` ids; the only
// schema shipped is `PoeIdSchema`, since the Label 309 record id is the one
// prefixed id the standard itself defines.

export {
  decodeBytes as decodeCrockfordBase32,
  encodeBytes as encodeCrockfordBase32,
  encodeBytesVariableLength,
  CROCKFORD_ENCODED_LENGTH_FOR_UUID,
} from './crockford-base32';

export { encodePrefixedId, decodePrefixedId, isPrefixedId, type PrefixedId } from './prefixed-id';

export { POE_ID_PREFIX, POE_ID_PATTERN, PoeIdSchema } from './zod-schemas';
