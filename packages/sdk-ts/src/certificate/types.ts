// Type surface for the Label 309 Inclusion Certificate.
//
// An inclusion certificate is a downloadable, self-contained, standalone-
// verifiable proof that one or more content hashes were committed as leaves of
// an RFC 9162 (Certificate Transparency) SHA-256 Merkle tree whose root was
// published on Cardano under metadata label 309. Each item embeds its full
// sibling path, so the artifact re-verifies forever from the file alone — no
// network, no storage gateway, no trust in any issuer.
//
// Two kinds of value live here:
//   - the *input* shapes (`CertificateAnchor`, `CertificateMerkle`,
//     `CertificateTarget`) the builder consumes, with raw `Uint8Array` byte
//     values and camelCase field names; and
//   - the *output* JSON shape (`InclusionCertificateV1` and friends) the
//     builder emits, with lowercase-hex string values and snake_case keys, so
//     it serialises directly to the on-disk certificate.

/**
 * The blockchain anchor: the Cardano transaction whose Label 309 record carries
 * the Merkle root. Every time/height/slot value here is asserted by the public
 * blockchain (via explorers), never cryptographically bound by the certificate.
 */
export interface CertificateAnchor {
  readonly chain: 'cardano';
  /** Cardano network name, e.g. `"mainnet"` or `"preprod"`. */
  readonly network: string;
  /** Transaction hash, 64 lowercase hex characters. */
  readonly txHash: string;
  readonly metadataLabel: 309;
  /** Block time in POSIX seconds, as asserted by the explorer. */
  readonly blockTime: number;
  readonly blockHeight?: number;
  readonly slot?: number;
  /** Confirmation count snapshot at generation; informational, not a claim. */
  readonly confirmationsAtGeneration?: number;
  readonly explorerUrls?: ReadonlyArray<string>;
}

/**
 * The Merkle commitment the certificate proves inclusion against. `root` is the
 * raw 32-byte tree head; `treeSize` is the on-chain `leaf_count`.
 */
export interface CertificateMerkle {
  /** Tree algorithm identifier; only `"rfc9162-sha256"` is supported. */
  readonly treeAlg: string;
  readonly root: Uint8Array;
  /** Number of leaves in the tree (the on-chain `leaf_count`). */
  readonly treeSize: number;
  readonly leavesListUri?: string;
  readonly leavesListUrl?: string;
}

/**
 * One target the caller wants proven: a committed content hash (a leaf) plus an
 * optional human label and the algorithm used to hash a file into the leaf.
 */
export interface CertificateTarget {
  /** The 32-byte content hash that was committed as a leaf. */
  readonly leaf: Uint8Array;
  /** How a file is hashed to reproduce `leaf` (default `"sha2-256"`). */
  readonly leafAlg?: string;
  /** Optional user note / filename. */
  readonly label?: string;
}

/** The anchor block of the emitted JSON certificate (snake_case, hex strings). */
export interface InclusionCertificateAnchor {
  readonly chain: 'cardano';
  readonly network: string;
  readonly tx_hash: string;
  readonly metadata_label: 309;
  readonly block_time: number;
  readonly block_time_iso: string;
  readonly block_height?: number;
  readonly slot?: number;
  readonly confirmations_at_generation?: number;
  readonly explorer_urls?: string[];
}

/** The Merkle block of the emitted JSON certificate. */
export interface InclusionCertificateMerkle {
  readonly tree_alg: string;
  /** Lowercase hex of the raw 32-byte root. */
  readonly root: string;
  readonly tree_size: number;
  readonly leaves_list_uri?: string;
  readonly leaves_list_url?: string;
}

/**
 * One certificate item: a leaf, its position, and the sibling path that
 * recomputes the root. `verified` records the builder's recomputation at
 * generation time; an independent verifier MUST recompute it and not trust this
 * stored boolean. A target absent from the tree is still emitted, with
 * `verified: false` and an explanatory `error`.
 */
export interface InclusionCertificateItem {
  /** Lowercase hex of the committed content hash. */
  readonly leaf: string;
  readonly leaf_alg?: string;
  readonly index: number;
  /** Sibling hashes, leaf→root order, lowercase hex; `[]` for a single-leaf tree. */
  readonly proof: string[];
  readonly verified: boolean;
  readonly label?: string;
  /** Present only when the target could not be proven (e.g. not in the tree). */
  readonly error?: string;
}

/** Human/machine-readable statement of what the certificate proves. */
export interface InclusionCertificateVerification {
  readonly method: string;
  readonly independent_tools: string[];
  readonly requires_trust_in_cardanowall: boolean;
  readonly time_asserted_by: string;
}

/** The full Label 309 inclusion certificate (artifact 1, the JSON form). */
export interface InclusionCertificateV1 {
  readonly format: 'label-309-inclusion-certificate-v1';
  readonly generated_at: string;
  readonly anchor: InclusionCertificateAnchor;
  readonly merkle: InclusionCertificateMerkle;
  readonly items: InclusionCertificateItem[];
  readonly claim: string;
  readonly verification: InclusionCertificateVerification;
}

/** Per-item verdict from a pure re-verification of a certificate. */
export interface InclusionCertificateItemVerdict {
  readonly index: number;
  /** Lowercase hex of the leaf, echoed from the certificate. */
  readonly leaf: string;
  readonly verified: boolean;
  readonly error?: string;
}

/**
 * Result of {@link verifyInclusionCertificate}. `ok` is true only when every
 * item's proof recomputes to the embedded root. `anchorClaim` is echoed from
 * the certificate and MUST be confirmed on a public Cardano explorer
 * separately — re-verification proves inclusion math, never the anchoring.
 */
export interface InclusionCertificateVerifyResult {
  readonly ok: boolean;
  readonly items: InclusionCertificateItemVerdict[];
  readonly anchorClaim: CertificateAnchor;
  /** Present when the whole certificate was rejected (bad format / tree alg). */
  readonly error?: string;
}
