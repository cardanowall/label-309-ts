// Public `@cardanowall/sdk-ts/certificate` namespace.
//
// The inclusion certificate is a self-contained, standalone-verifiable proof
// that one or more content hashes were committed as leaves of an RFC 9162
// SHA-256 Merkle tree whose root was published on Cardano under metadata label
// 309. Everything here is pure and browser-safe — callers fetch any external
// bytes (e.g. the off-chain leaves-list) with the platform's own fetch and pass
// the decoded leaves in; the crypto path performs no I/O.
//
// Surface:
//   - `buildInclusionCertificate` — compute + self-verify per-target proofs and
//     emit the JSON certificate object (§ JSON format).
//   - `verifyInclusionCertificate` — pure re-verification of a certificate from
//     its own bytes; reports per-item verdicts and echoes the anchor to confirm
//     on-chain separately.
//   - `encodeCoseInclusionProof` / `encodeIetfInclusionProof` — the per-item
//     COSE / RFC 9162 aligned CBOR proof, and the bare IETF inclusion-proof
//     byte string on its own.
//   - format / claim / verification string constants emitted verbatim.

export { buildInclusionCertificate } from './build';
export type { BuildInclusionCertificateArgs } from './build';

export { verifyInclusionCertificate } from './verify';

export { encodeCoseInclusionProof, encodeIetfInclusionProof } from './cose';

export {
  INCLUSION_CERTIFICATE_FORMAT_V1,
  CERTIFICATE_TREE_ALG,
  METADATA_LABEL_309,
  VDS_RFC9162_SHA256,
  CERTIFICATE_CLAIM,
  CERTIFICATE_VERIFICATION_METHOD,
  CERTIFICATE_INDEPENDENT_TOOLS,
  CERTIFICATE_TIME_ASSERTED_BY,
} from './constants';

export type {
  CertificateAnchor,
  CertificateMerkle,
  CertificateTarget,
  InclusionCertificateAnchor,
  InclusionCertificateMerkle,
  InclusionCertificateItem,
  InclusionCertificateVerification,
  InclusionCertificateV1,
  InclusionCertificateItemVerdict,
  InclusionCertificateVerifyResult,
} from './types';
