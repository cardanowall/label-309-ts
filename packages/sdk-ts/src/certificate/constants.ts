// Fixed string constants embedded verbatim in every inclusion certificate.
//
// These are part of the on-disk format: the parity twins in the Python and Rust
// SDKs must reproduce them byte-for-byte, so they are defined once here and
// never templated or localised.

export const INCLUSION_CERTIFICATE_FORMAT_V1 = 'label-309-inclusion-certificate-v1' as const;

/** RFC 9162 (Certificate Transparency) SHA-256, IANA verifiable-data-structure 1. */
export const CERTIFICATE_TREE_ALG = 'rfc9162-sha256' as const;

/** Cardano metadata label that carries Label 309 records. */
export const METADATA_LABEL_309 = 309 as const;

/** IANA "COSE Verifiable Data Structures" codepoint for RFC9162_SHA256. */
export const VDS_RFC9162_SHA256 = 1 as const;

export const CERTIFICATE_CLAIM =
  'Each listed hash was included in a Merkle tree whose root was published on ' +
  'the Cardano blockchain in the referenced transaction under metadata label ' +
  '309; therefore each hash provably existed on or before the stated block time.';

export const CERTIFICATE_VERIFICATION_METHOD =
  'RFC 9162 (Certificate Transparency) SHA-256 inclusion proof. For each item, ' +
  'recompute the Merkle root from leaf+index+tree_size+proof and compare to ' +
  'merkle.root; then confirm merkle.root equals the merkle[].root in the ' +
  'Label 309 record of anchor.tx_hash on any public Cardano explorer.';

export const CERTIFICATE_INDEPENDENT_TOOLS: readonly string[] = [
  'cardanowall certificate verify <file>',
  'cardanowall merkle verify (per item)',
  'any RFC 9162 / COSE verifiable-data-structure verifier',
];

export const CERTIFICATE_TIME_ASSERTED_BY = 'Cardano blockchain (block time), via public explorers';
