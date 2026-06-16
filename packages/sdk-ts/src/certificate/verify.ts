// Pure re-verification of a Label 309 inclusion certificate.
//
// `verifyInclusionCertificate` recomputes each item's Merkle proof from the
// certificate alone — no Arweave fetch, no chain query — and reports a verdict.
// It proves the *inclusion* claim (each leaf is at its stated index of a tree
// with the embedded root). It does NOT and cannot prove the *anchoring* claim:
// that `merkle.root` actually appears in the Label 309 record of
// `anchor.tx_hash` on chain. The anchor is echoed as `anchorClaim` for the
// caller to confirm on any public Cardano explorer as a separate step.
//
// This function never throws on attacker-controlled input: a forged or
// malformed certificate (bad format, tree algorithm, anchor fixed fields, or an
// out-of-range tree_size / index) is reported as `ok: false` with a clear
// error, not an exception.

import { hexToBytes } from '@cardanowall/crypto-core/util';
import { merkleSha2256VerifyInclusion } from '@cardanowall/crypto-core/hash';

import {
  CERTIFICATE_TREE_ALG,
  INCLUSION_CERTIFICATE_FORMAT_V1,
  METADATA_LABEL_309,
} from './constants';
import type {
  CertificateAnchor,
  InclusionCertificateItem,
  InclusionCertificateItemVerdict,
  InclusionCertificateV1,
  InclusionCertificateVerifyResult,
} from './types';

// The verify primitive is only exact while tree_size stays within the 32-bit
// fold domain (the on-chain commitment caps leaf_count at the same value). A
// certificate claiming a larger tree_size is forged; we reject it here so the
// primitive's range guard is never reached from this path.
const MAX_TREE_SIZE = 0xffffffff;

/**
 * Re-verify an inclusion certificate purely from its own bytes.
 *
 * For every item this recomputes `merkleSha2256VerifyInclusion(leaf, index,
 * tree_size, proof, root)` and records the verdict. `ok` is true only when
 * every item verifies. The stored `verified` flag in the certificate is never
 * trusted — this recomputes it.
 *
 * The certificate as a whole is rejected (returns `ok: false` with an `error`,
 * never throws) when its `format`, `merkle.tree_alg`, anchor fixed fields, or
 * `merkle.tree_size` are unsupported / out of range.
 *
 * The returned `anchorClaim` echoes the certificate's *claimed* anchor verbatim.
 * It must be confirmed on a public Cardano explorer; this function does no
 * chain I/O and asserts nothing about the anchor beyond its structural shape.
 */
export function verifyInclusionCertificate(
  cert: InclusionCertificateV1,
): InclusionCertificateVerifyResult {
  const anchorClaim = anchorClaimOf(cert);

  if (cert.format !== INCLUSION_CERTIFICATE_FORMAT_V1) {
    return reject(anchorClaim, `unsupported certificate format '${String(cert.format)}'`);
  }
  if (cert.merkle.tree_alg !== CERTIFICATE_TREE_ALG) {
    return reject(anchorClaim, `unsupported tree_alg '${String(cert.merkle.tree_alg)}'`);
  }

  // The anchor's fixed fields are part of the format, not explorer-asserted
  // facts: a certificate that does not name Cardano / metadata label 309 is not
  // a Label 309 inclusion certificate.
  const anchor = cert.anchor;
  if (anchor === undefined || anchor === null) {
    return reject(anchorClaim, 'missing anchor');
  }
  if (anchor.chain !== 'cardano') {
    return reject(anchorClaim, `unsupported anchor.chain '${String(anchor.chain)}'`);
  }
  if (anchor.metadata_label !== METADATA_LABEL_309) {
    return reject(
      anchorClaim,
      `unsupported anchor.metadata_label '${String(anchor.metadata_label)}'`,
    );
  }

  const treeSize = cert.merkle.tree_size;
  if (!Number.isSafeInteger(treeSize) || treeSize < 1 || treeSize > MAX_TREE_SIZE) {
    return reject(anchorClaim, `merkle.tree_size ${String(treeSize)} out of range`);
  }

  const rootResult = decodeHex(cert.merkle.root);
  if (rootResult.error !== undefined) {
    return reject(anchorClaim, `malformed merkle.root: ${rootResult.error}`);
  }
  const root = rootResult.bytes;

  const items: InclusionCertificateItemVerdict[] = cert.items.map((item) =>
    verifyItem(item, treeSize, root),
  );
  const ok = items.length > 0 && items.every((v) => v.verified);

  return { ok, items, anchorClaim };
}

function reject(anchorClaim: CertificateAnchor, error: string): InclusionCertificateVerifyResult {
  return { ok: false, items: [], anchorClaim, error };
}

function verifyItem(
  item: InclusionCertificateItem,
  treeSize: number,
  root: Uint8Array,
): InclusionCertificateItemVerdict {
  // Carry an item-level error (e.g. a build-time "leaf not found") through to
  // the verdict so a re-verifier sees why a miss is a miss.
  if (item.error !== undefined) {
    return { index: item.index, leaf: item.leaf, verified: false, error: item.error };
  }

  // Pre-validate the per-item index so the primitive's range guard is never
  // reached: an out-of-range index is a non-verifying item, not an exception.
  if (!Number.isSafeInteger(item.index) || item.index < 0 || item.index >= treeSize) {
    return {
      index: item.index,
      leaf: item.leaf,
      verified: false,
      error: `index ${String(item.index)} out of range [0, ${treeSize})`,
    };
  }

  const leaf = decodeHex(item.leaf);
  if (leaf.error !== undefined) {
    return {
      index: item.index,
      leaf: item.leaf,
      verified: false,
      error: `malformed leaf: ${leaf.error}`,
    };
  }

  const proof: Uint8Array[] = [];
  for (let i = 0; i < item.proof.length; i++) {
    const sibling = decodeHex(item.proof[i] as string);
    if (sibling.error !== undefined) {
      return {
        index: item.index,
        leaf: item.leaf,
        verified: false,
        error: `malformed proof[${i}]: ${sibling.error}`,
      };
    }
    proof.push(sibling.bytes);
  }

  const verified = merkleSha2256VerifyInclusion(leaf.bytes, item.index, treeSize, proof, root);
  return { index: item.index, leaf: item.leaf, verified };
}

interface DecodeHexOk {
  readonly bytes: Uint8Array;
  readonly error?: undefined;
}
interface DecodeHexErr {
  readonly bytes: Uint8Array;
  readonly error: string;
}

function decodeHex(hex: unknown): DecodeHexOk | DecodeHexErr {
  if (typeof hex !== 'string') {
    return { bytes: new Uint8Array(0), error: 'value is not a string' };
  }
  try {
    // Producers emit lowercase, but a certificate is valid with either case, so
    // normalise before the strict (lowercase-only) decoder. The decoder still
    // rejects any non-hex character — including whitespace — and odd length, so
    // an uppercase field decodes identically to its lowercase form while a
    // malformed field yields an error rather than a throw.
    return { bytes: hexToBytes(hex.toLowerCase()) };
  } catch (cause) {
    return {
      bytes: new Uint8Array(0),
      error: cause instanceof Error ? cause.message : String(cause),
    };
  }
}

/**
 * Reconstruct the camelCase {@link CertificateAnchor} from the certificate's
 * snake_case anchor block, echoing every present field verbatim. This is a
 * faithful echo of the *claimed* anchor — never a fabrication and never a
 * validation; `verifyInclusionCertificate` validates the fixed fields
 * separately and the byte facts are confirmed on a public explorer.
 */
function anchorClaimOf(cert: InclusionCertificateV1): CertificateAnchor {
  const a = cert.anchor ?? ({} as InclusionCertificateV1['anchor']);
  return {
    // `chain` and `metadataLabel` are echoed as the actual certificate values.
    // The CertificateAnchor type narrows them to the Label 309 literals, so a
    // non-conforming value is surfaced through that type while still being the
    // value the certificate carries (verify rejects it via the fixed-field
    // checks above).
    chain: (typeof a.chain === 'string' ? a.chain : 'cardano') as CertificateAnchor['chain'],
    network: typeof a.network === 'string' ? a.network : '',
    txHash: typeof a.tx_hash === 'string' ? a.tx_hash : '',
    metadataLabel: (typeof a.metadata_label === 'number'
      ? a.metadata_label
      : METADATA_LABEL_309) as CertificateAnchor['metadataLabel'],
    blockTime: typeof a.block_time === 'number' ? a.block_time : 0,
    ...(typeof a.block_height === 'number' ? { blockHeight: a.block_height } : {}),
    ...(typeof a.slot === 'number' ? { slot: a.slot } : {}),
    ...(typeof a.confirmations_at_generation === 'number'
      ? { confirmationsAtGeneration: a.confirmations_at_generation }
      : {}),
    ...(Array.isArray(a.explorer_urls) ? { explorerUrls: [...a.explorer_urls] } : {}),
  };
}
