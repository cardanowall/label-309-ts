// Public Merkle namespace for the CIP-309 SDK.
//
// The `@cardanowall/crypto-core` package stays `private: true` (it is the
// internal cryptographic library — closed-catalogue primitives gated by the
// `cw/dep-graph-crypto-core` ESLint rule). The SDK is the only public
// consumption surface, so we re-export the on-wire Merkle primitives here.
//
// Surface:
//   - `merkleSha2256Root` / `merkleSha2256InclusionProof` /
//     `merkleSha2256VerifyInclusion` — RFC 9162 §2.1.1 binary Merkle tree
//     under SHA-256.
//   - `encodeLeavesList` / `decodeLeavesList` — canonical-CBOR codec for the
//     off-chain leaves-list artefact.
//   - `MERKLE_ALG_ID` / `LEAVES_LIST_FORMAT_V1` — registered string identifiers
//     embedded in the on-wire `merkle[]` commitment and the CBOR leaves-list.
//   - `MerkleLeavesListError` — typed error class for codec rejections.

export {
  merkleSha2256Root,
  merkleSha2256InclusionProof,
  merkleSha2256VerifyInclusion,
  MERKLE_ALG_ID,
} from '@cardanowall/crypto-core/hash';

export {
  encodeLeavesList,
  decodeLeavesList,
  LEAVES_LIST_FORMAT_V1,
  MerkleLeavesListError,
} from '@cardanowall/crypto-core/merkle';

export type {
  EncodeLeavesListArgs,
  DecodedLeavesList,
  MerkleLeavesListErrorCode,
} from '@cardanowall/crypto-core/merkle';
