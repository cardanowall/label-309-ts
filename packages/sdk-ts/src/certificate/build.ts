// Builder for the Label 309 inclusion certificate (artifact 1, JSON form).
//
// `buildInclusionCertificate` takes the decoded Merkle leaves and a set of
// targets, locates each target leaf, computes and self-verifies its inclusion
// proof, and emits the typed JSON object. The output serialises directly to the
// on-disk certificate; the parity twins reproduce the same value byte-for-byte.

import { compareCt } from '@cardanowall/crypto-core/util';
import {
  merkleSha2256InclusionProof,
  merkleSha2256Root,
  merkleSha2256VerifyInclusion,
} from '@cardanowall/crypto-core/hash';

import { bytesToHex } from '../hex';
import {
  CERTIFICATE_CLAIM,
  CERTIFICATE_INDEPENDENT_TOOLS,
  CERTIFICATE_TIME_ASSERTED_BY,
  CERTIFICATE_TREE_ALG,
  CERTIFICATE_VERIFICATION_METHOD,
  INCLUSION_CERTIFICATE_FORMAT_V1,
  METADATA_LABEL_309,
} from './constants';
import type {
  CertificateAnchor,
  CertificateMerkle,
  CertificateTarget,
  InclusionCertificateAnchor,
  InclusionCertificateItem,
  InclusionCertificateMerkle,
  InclusionCertificateV1,
} from './types';

const DIGEST_LENGTH = 32;

// `block_time` is POSIX seconds. It must be a non-negative integer that maps to
// a calendar year in 1..=9999, so `block_time_iso` renders the same fixed
// `YYYY-MM-DDTHH:MM:SS.000Z` shape across every producer. 253402300800 is the
// POSIX second of 10000-01-01T00:00:00Z (the first instant past year 9999).
const MAX_BLOCK_TIME_EXCLUSIVE = 253_402_300_800;

export interface BuildInclusionCertificateArgs {
  readonly anchor: CertificateAnchor;
  readonly merkle: CertificateMerkle;
  /** The full leaf set, e.g. from `decodeLeavesList(...).leaves`. */
  readonly leaves: ReadonlyArray<Uint8Array>;
  readonly targets: ReadonlyArray<CertificateTarget>;
  /**
   * Generation timestamp written verbatim to `generated_at`. Supply a fixed
   * value to make the emitted JSON reproducible (cross-language parity vectors
   * pin it); when omitted, the current time is used. `generated_at` is purely
   * informational and never trusted by a verifier.
   */
  readonly generatedAt?: string;
}

/**
 * Build an inclusion certificate over the given leaves for the given targets.
 *
 * For each target this finds the leaf's index in `leaves`, computes its sibling
 * path, re-verifies the path against `merkle.root`, and records the verdict. A
 * target not present in `leaves` is still emitted as an item with
 * `verified: false` and an `error` string — the certificate stays honest about
 * misses rather than dropping them.
 *
 * Throws only on structural misuse of the inputs:
 *   - `merkle.treeAlg` is not `"rfc9162-sha256"`,
 *   - `merkle.root` is not exactly 32 bytes,
 *   - `merkle.treeSize` does not equal `leaves.length`, or
 *   - `merkle.root` does not match the root recomputed from `leaves`.
 */
export function buildInclusionCertificate(
  args: BuildInclusionCertificateArgs,
): InclusionCertificateV1 {
  const { anchor, merkle, leaves, targets, generatedAt } = args;

  if (merkle.treeAlg !== CERTIFICATE_TREE_ALG) {
    throw new Error(
      `buildInclusionCertificate: unsupported tree_alg '${String(merkle.treeAlg)}' ` +
        `(only '${CERTIFICATE_TREE_ALG}' is supported)`,
    );
  }
  if (!(merkle.root instanceof Uint8Array) || merkle.root.length !== DIGEST_LENGTH) {
    throw new Error(
      `buildInclusionCertificate: merkle.root must be a ${DIGEST_LENGTH}-byte Uint8Array`,
    );
  }
  if (merkle.treeSize !== leaves.length) {
    throw new Error(
      `buildInclusionCertificate: merkle.treeSize (${merkle.treeSize}) ` +
        `!= leaves.length (${leaves.length})`,
    );
  }
  // The declared root must be the root the given leaves actually produce.
  // Building proofs against a root the leaves do not hash to would emit a
  // certificate every item of which fails verification — a structural misuse,
  // not an honest miss, so we refuse it up front. (Recomputing also validates
  // every leaf is a 32-byte digest, which findLeafIndex would otherwise skip.)
  const recomputedRoot = merkleSha2256Root(leaves);
  if (!compareCt(recomputedRoot, merkle.root)) {
    throw new Error(
      'buildInclusionCertificate: merkle.root does not match the root recomputed from leaves',
    );
  }
  if (
    !Number.isSafeInteger(anchor.blockTime) ||
    anchor.blockTime < 0 ||
    anchor.blockTime >= MAX_BLOCK_TIME_EXCLUSIVE
  ) {
    throw new Error(
      `buildInclusionCertificate: anchor.blockTime ${String(anchor.blockTime)} out of range ` +
        `[0, ${MAX_BLOCK_TIME_EXCLUSIVE}) (must map to a year in 1..=9999)`,
    );
  }

  const items: InclusionCertificateItem[] = targets.map((target) =>
    buildItem(target, leaves, merkle.root),
  );

  return {
    format: INCLUSION_CERTIFICATE_FORMAT_V1,
    generated_at: generatedAt ?? new Date().toISOString(),
    anchor: buildAnchor(anchor),
    merkle: buildMerkle(merkle),
    items,
    claim: CERTIFICATE_CLAIM,
    verification: {
      method: CERTIFICATE_VERIFICATION_METHOD,
      independent_tools: [...CERTIFICATE_INDEPENDENT_TOOLS],
      requires_issuer_trust: false,
      time_asserted_by: CERTIFICATE_TIME_ASSERTED_BY,
    },
  };
}

function buildItem(
  target: CertificateTarget,
  leaves: ReadonlyArray<Uint8Array>,
  root: Uint8Array,
): InclusionCertificateItem {
  const isWellFormed = target.leaf instanceof Uint8Array && target.leaf.length === DIGEST_LENGTH;
  const index = isWellFormed ? findLeafIndex(leaves, target.leaf) : -1;

  let proof: string[] = [];
  let verified = false;
  let error: string | undefined;

  if (!isWellFormed) {
    error = `leaf must be a ${DIGEST_LENGTH}-byte Uint8Array`;
  } else if (index < 0) {
    error = 'leaf not found in the committed leaf set';
  } else {
    const sibling = merkleSha2256InclusionProof(leaves, index);
    proof = sibling.map(bytesToHex);
    verified = merkleSha2256VerifyInclusion(target.leaf, index, leaves.length, sibling, root);
  }

  // Construct the item in the normative key order so the serialised JSON is
  // stable across the parity twins:
  //   { leaf, leaf_alg?, index, proof, verified, label?, error? }
  return makeItem({
    leaf: bytesToHex(target.leaf),
    leafAlg: target.leafAlg,
    index,
    proof,
    verified,
    label: target.label,
    error,
  });
}

function makeItem(parts: {
  leaf: string;
  leafAlg: string | undefined;
  index: number;
  proof: string[];
  verified: boolean;
  label: string | undefined;
  error: string | undefined;
}): InclusionCertificateItem {
  // Insert keys in the normative order; object property order follows insertion
  // order for string keys, so the serialised JSON is stable across the parity
  // twins: { leaf, leaf_alg?, index, proof, verified, label?, error? }.
  const item: Record<string, string | number | boolean | string[]> = {
    leaf: parts.leaf,
  };
  if (parts.leafAlg !== undefined) item['leaf_alg'] = parts.leafAlg;
  item['index'] = parts.index;
  item['proof'] = parts.proof;
  item['verified'] = parts.verified;
  if (parts.label !== undefined) item['label'] = parts.label;
  if (parts.error !== undefined) item['error'] = parts.error;
  return item as unknown as InclusionCertificateItem;
}

/**
 * Index of the first leaf byte-equal to `target`, or -1. Equality is checked
 * with the constant-time digest comparator on equal-length 32-byte values, so a
 * non-32-byte stored leaf simply does not match.
 */
function findLeafIndex(leaves: ReadonlyArray<Uint8Array>, target: Uint8Array): number {
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i];
    if (leaf instanceof Uint8Array && leaf.length === target.length && compareCt(leaf, target)) {
      return i;
    }
  }
  return -1;
}

function buildAnchor(anchor: CertificateAnchor): InclusionCertificateAnchor {
  const blockTimeIso = new Date(anchor.blockTime * 1000).toISOString();
  return {
    chain: anchor.chain,
    network: anchor.network,
    tx_hash: anchor.txHash,
    metadata_label: METADATA_LABEL_309,
    block_time: anchor.blockTime,
    block_time_iso: blockTimeIso,
    ...(anchor.blockHeight !== undefined ? { block_height: anchor.blockHeight } : {}),
    ...(anchor.slot !== undefined ? { slot: anchor.slot } : {}),
    ...(anchor.confirmationsAtGeneration !== undefined
      ? { confirmations_at_generation: anchor.confirmationsAtGeneration }
      : {}),
    ...(anchor.explorerUrls !== undefined ? { explorer_urls: [...anchor.explorerUrls] } : {}),
  };
}

function buildMerkle(merkle: CertificateMerkle): InclusionCertificateMerkle {
  return {
    tree_alg: merkle.treeAlg,
    root: bytesToHex(merkle.root),
    tree_size: merkle.treeSize,
    ...(merkle.leavesListUri !== undefined ? { leaves_list_uri: merkle.leavesListUri } : {}),
    ...(merkle.leavesListUrl !== undefined ? { leaves_list_url: merkle.leavesListUrl } : {}),
  };
}
