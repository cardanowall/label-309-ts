// Canonical-CBOR codec for the off-chain Merkle leaves-list artefact.
// The on-chain `merkle[]` field binds to this file via `uris[]` / `leaf_count`;
// the file itself carries the full leaf set. Canonical CBOR is RFC 8949 §4.2.1.
//
// CDDL:
//
//   leaves-list = {
//     "format":     "cardano-poe-merkle-leaves-v1",
//     "tree_alg":   "rfc9162-sha256",
//     "root":       bytes .size 32,
//     "leaves":     [ + bytes .size 32 ],
//     "leaf_count": uint,
//     ? "leaf_alg": tstr,
//   }
//
// Canonical ordering is bytewise-lexicographic on encoded map keys (RFC 8949
// §4.2.1) so the wire-key order is fixed by `cde:true` regardless of insertion
// order: root (4B) < format (6B) < leaves (6B) < leaf_alg (8B) < tree_alg (8B)
// < leaf_count (10B).

import { decodeCanonicalCbor, encodeCanonicalCbor } from '../cbor/canonical';
import { compareCt } from '../util/compare-ct';
import { merkleSha2256Root } from '../hash/merkle-sha2-256';

export const LEAVES_LIST_FORMAT_V1 = 'cardano-poe-merkle-leaves-v1' as const;
const TREE_ALG_RFC9162 = 'rfc9162-sha256' as const;
const DIGEST_LENGTH = 32;
const REGISTERED_FORMATS = new Set<string>([LEAVES_LIST_FORMAT_V1]);

export type MerkleLeavesListErrorCode =
  | 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED'
  | 'SCHEMA_MERKLE_LEAVES_MALFORMED'
  | 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH'
  | 'MERKLE_ROOT_MISMATCH';

export class MerkleLeavesListError extends Error {
  readonly code: MerkleLeavesListErrorCode;
  constructor(code: MerkleLeavesListErrorCode, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.code = code;
    this.name = 'MerkleLeavesListError';
  }
}

export interface EncodeLeavesListArgs {
  readonly leaves: ReadonlyArray<Uint8Array>;
  readonly root: Uint8Array;
  readonly leafAlg?: string;
}

export interface DecodedLeavesList {
  readonly format: typeof LEAVES_LIST_FORMAT_V1;
  readonly treeAlg: typeof TREE_ALG_RFC9162;
  readonly root: Uint8Array;
  readonly leaves: Uint8Array[];
  readonly leafCount: number;
  readonly leafAlg?: string;
}

export function encodeLeavesList(args: EncodeLeavesListArgs): Uint8Array {
  if (!(args.root instanceof Uint8Array) || args.root.length !== DIGEST_LENGTH) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      `root must be a Uint8Array(${DIGEST_LENGTH})`,
    );
  }
  if (args.leaves.length < 1) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaves array must be non-empty',
    );
  }
  const leavesCopy: Uint8Array[] = [];
  for (let i = 0; i < args.leaves.length; i++) {
    const leaf = args.leaves[i];
    if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) {
      throw new MerkleLeavesListError(
        'SCHEMA_MERKLE_LEAVES_MALFORMED',
        `leaves[${i}] must be a Uint8Array(${DIGEST_LENGTH})`,
      );
    }
    leavesCopy.push(leaf);
  }
  if (args.leafAlg !== undefined && typeof args.leafAlg !== 'string') {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaf_alg must be a string when present',
    );
  }
  const map: Record<string, unknown> = {
    format: LEAVES_LIST_FORMAT_V1,
    tree_alg: TREE_ALG_RFC9162,
    root: args.root,
    leaves: leavesCopy,
    leaf_count: leavesCopy.length,
  };
  if (args.leafAlg !== undefined) {
    map['leaf_alg'] = args.leafAlg;
  }
  return encodeCanonicalCbor(map as never);
}

export function decodeLeavesList(bytes: Uint8Array): DecodedLeavesList {
  const decoded = decodeCanonicalCbor(bytes);
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaves-list MUST be a CBOR map',
    );
  }
  const m = decoded as Record<string, unknown>;

  const format = m['format'];
  if (typeof format !== 'string') {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'format must be a text string',
    );
  }
  if (!REGISTERED_FORMATS.has(format)) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED',
      `format '${format}' is not in the registered set`,
    );
  }

  const treeAlg = m['tree_alg'];
  if (treeAlg !== TREE_ALG_RFC9162) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      `tree_alg '${String(treeAlg)}' is not '${TREE_ALG_RFC9162}'`,
    );
  }

  const root = m['root'];
  if (!(root instanceof Uint8Array) || root.length !== DIGEST_LENGTH) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      `root must be a ${DIGEST_LENGTH}-byte byte string`,
    );
  }

  const leavesRaw = m['leaves'];
  if (!Array.isArray(leavesRaw) || leavesRaw.length < 1) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaves must be a non-empty array',
    );
  }
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < leavesRaw.length; i++) {
    const leaf = leavesRaw[i];
    if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) {
      throw new MerkleLeavesListError(
        'SCHEMA_MERKLE_LEAVES_MALFORMED',
        `leaves[${i}] must be a ${DIGEST_LENGTH}-byte byte string`,
      );
    }
    leaves.push(leaf);
  }

  const leafCountRaw = m['leaf_count'];
  let leafCount: number;
  if (typeof leafCountRaw === 'number' && Number.isInteger(leafCountRaw) && leafCountRaw >= 0) {
    leafCount = leafCountRaw;
  } else if (typeof leafCountRaw === 'bigint' && leafCountRaw >= 0n) {
    if (leafCountRaw > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new MerkleLeavesListError(
        'SCHEMA_MERKLE_LEAVES_MALFORMED',
        'leaf_count exceeds Number.MAX_SAFE_INTEGER',
      );
    }
    leafCount = Number(leafCountRaw);
  } else {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaf_count must be a non-negative CBOR uint',
    );
  }
  if (leaves.length !== leafCount) {
    throw new MerkleLeavesListError(
      'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH',
      `leaves.length (${leaves.length}) != leaf_count (${leafCount})`,
    );
  }

  let leafAlg: string | undefined;
  if (m['leaf_alg'] !== undefined) {
    if (typeof m['leaf_alg'] !== 'string') {
      throw new MerkleLeavesListError(
        'SCHEMA_MERKLE_LEAVES_MALFORMED',
        'leaf_alg must be a text string when present',
      );
    }
    leafAlg = m['leaf_alg'];
  }

  const recomputed = merkleSha2256Root(leaves);
  if (!compareCt(recomputed, root)) {
    throw new MerkleLeavesListError(
      'MERKLE_ROOT_MISMATCH',
      'leaves recompute does not match declared root',
    );
  }

  const out: DecodedLeavesList = {
    format: LEAVES_LIST_FORMAT_V1,
    treeAlg: TREE_ALG_RFC9162,
    root,
    leaves,
    leafCount,
    ...(leafAlg !== undefined ? { leafAlg } : {}),
  };
  return out;
}
