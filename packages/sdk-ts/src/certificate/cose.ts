// Artifact 2 — the per-item COSE / RFC 9162 aligned CBOR inclusion proof.
//
// The inner `inclusion-proof` structure is byte-identical to the IETF COSE
// Merkle-tree-proofs encoding, so third-party COSE / SCITT verifiers read the
// proof math directly:
//
//   inclusion-proof = bstr .cbor [ tree_size: uint, leaf_index: uint, [ + bstr ] ]
//
// Note the `bstr .cbor` wrapper: the standalone IETF value is a CBOR *byte
// string* whose contents are the canonical-CBOR encoding of the
// `[tree_size, leaf_index, inclusion-path]` array.
//
// We wrap that bstr in a `cw-inclusion-proof` map that carries the blockchain
// anchor in place of the COSE_Sign1 signature an IETF Receipt would hold — the
// proof is deliberately unsigned-and-blockchain-anchored (the timestamp
// authority is the Cardano transaction, not a key we control):
//
//   cw-inclusion-proof = {
//     "vds":             1,                 ; RFC9162_SHA256 (IANA value 1)
//     "inclusion_proof": inclusion-proof,   ; the IETF bstr.cbor array
//     "root":            bytes .size 32,
//     "anchor": { "chain", "network", "tx_hash": bytes, "metadata_label": 309 },
//     "leaf":            bytes .size 32,
//     ? "leaf_alg":      tstr
//   }
//
// The CBOR artifact exists only for a *proven* inclusion: a missing or
// unverified item has no valid proof to encode, so the encoders refuse it
// rather than emit a sentinel that decodes to a malformed proof.
//
// All encoding goes through the shared canonical-CBOR codec (RFC 8949 §4.2.1).

import { encodeCanonicalCbor } from '@cardanowall/crypto-core/cbor';
import type { CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { hexToBytes } from '@cardanowall/crypto-core/util';

import { METADATA_LABEL_309, VDS_RFC9162_SHA256 } from './constants';
import type { CertificateAnchor, CertificateMerkle, InclusionCertificateItem } from './types';

const DIGEST_LENGTH = 32;
const MAX_TREE_SIZE = 0xffffffff;

/**
 * Decode + validate a proven inclusion item into raw bytes ready for CBOR.
 * Throws `TypeError` if the item is not a proven inclusion — a miss
 * (`item.error` set), an unverified item, an out-of-range index, or any
 * leaf/root/sibling that is not exactly 32 bytes. The COSE artifact must never
 * be produced for anything but a valid proof.
 */
function decodeProvenItem(
  item: InclusionCertificateItem,
  merkle: CertificateMerkle,
): { leaf: Uint8Array; siblings: Uint8Array[]; treeSize: number; index: number } {
  if (item.error !== undefined) {
    throw new TypeError(
      `encodeCoseInclusionProof: refusing to encode an item with error '${item.error}'`,
    );
  }
  if (item.verified !== true) {
    throw new TypeError('encodeCoseInclusionProof: refusing to encode an unverified item');
  }
  if (!Number.isSafeInteger(item.index) || item.index < 0) {
    throw new TypeError(`encodeCoseInclusionProof: invalid item index ${String(item.index)}`);
  }
  if (
    !Number.isSafeInteger(merkle.treeSize) ||
    merkle.treeSize < 1 ||
    merkle.treeSize > MAX_TREE_SIZE ||
    item.index >= merkle.treeSize
  ) {
    throw new TypeError(
      `encodeCoseInclusionProof: index ${item.index} out of range for tree_size ${String(
        merkle.treeSize,
      )}`,
    );
  }

  const leaf = decode32(item.leaf, 'leaf');
  const siblings = item.proof.map((hex, i) => decode32(hex, `proof[${i}]`));
  return { leaf, siblings, treeSize: merkle.treeSize, index: item.index };
}

function decode32(hex: string, field: string): Uint8Array {
  const bytes = decodeHexCaseInsensitive(hex);
  if (bytes.length !== DIGEST_LENGTH) {
    throw new TypeError(
      `encodeCoseInclusionProof: ${field} must be ${DIGEST_LENGTH} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

// A certificate's hex fields are valid in either case, so normalise to
// lowercase before the strict decoder. The decoder still rejects any non-hex
// character (including whitespace) and odd length; the COSE encoders surface
// that as a throw, consistent with how they reject any non-inclusion item.
function decodeHexCaseInsensitive(hex: string): Uint8Array {
  return hexToBytes(hex.toLowerCase());
}

/**
 * The canonical-CBOR bytes of the bare `[tree_size, leaf_index, [siblings]]`
 * array — the *contents* that the IETF `bstr .cbor` wraps. Internal: callers
 * embed this directly in the map (where the encoder turns the Uint8Array into a
 * bstr) and the bare helper wraps it once more.
 */
function encodeInclusionPathArray(
  item: InclusionCertificateItem,
  merkle: CertificateMerkle,
): Uint8Array {
  const { siblings, treeSize, index } = decodeProvenItem(item, merkle);
  const array: CanonicalCborValue = [treeSize, index, siblings];
  return encodeCanonicalCbor(array);
}

/**
 * Encode the bare IETF `inclusion-proof` value for one item: a CBOR byte string
 * whose contents are the canonical CBOR of `[tree_size, leaf_index,
 * [ ...siblings ]]` (the `bstr .cbor [...]` form). This is exactly the value a
 * pure COSE / RFC 9162 verifier consumes — decode it as a byte string, then
 * decode those bytes as the array. Refuses non-inclusion items.
 */
export function encodeIetfInclusionProof(
  item: InclusionCertificateItem,
  merkle: CertificateMerkle,
): Uint8Array {
  const arrayBytes = encodeInclusionPathArray(item, merkle);
  // Wrap the array bytes as a CBOR byte string (the `bstr .cbor` envelope).
  return encodeCanonicalCbor(arrayBytes);
}

/**
 * Encode the full `cw-inclusion-proof` CBOR map for one item: the IETF
 * inclusion-proof bstr plus the root, the blockchain anchor, the committed
 * leaf, and the optional leaf algorithm. Canonical CBOR; the parity twins
 * reproduce the bytes exactly. Refuses non-inclusion items.
 */
export function encodeCoseInclusionProof(
  item: InclusionCertificateItem,
  merkle: CertificateMerkle,
  anchor: CertificateAnchor,
): Uint8Array {
  // The map stores the *array bytes* as a Uint8Array; the encoder renders that
  // as a bstr, so `inclusion_proof` is byte-identical to encodeIetfInclusionProof.
  const inclusionPathArray = encodeInclusionPathArray(item, merkle);
  const leaf = decode32(item.leaf, 'leaf');

  if (!(merkle.root instanceof Uint8Array) || merkle.root.length !== DIGEST_LENGTH) {
    throw new TypeError(`encodeCoseInclusionProof: merkle.root must be ${DIGEST_LENGTH} bytes`);
  }

  const map: Record<string, CanonicalCborValue> = {
    vds: VDS_RFC9162_SHA256,
    inclusion_proof: inclusionPathArray,
    root: merkle.root,
    anchor: {
      chain: anchor.chain,
      network: anchor.network,
      tx_hash: decodeHexCaseInsensitive(anchor.txHash),
      metadata_label: METADATA_LABEL_309,
    },
    leaf,
    ...(item.leaf_alg !== undefined ? { leaf_alg: item.leaf_alg } : {}),
  };

  return encodeCanonicalCbor(map);
}
