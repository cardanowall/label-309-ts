// Behavioural coverage for the Label 309 inclusion-certificate module.
//
// These tests exercise the round-trip (build → re-verify), tamper detection,
// the single-leaf and absent-target edge cases, structural-misuse rejection,
// and the COSE/RFC-9162 CBOR shape — asserting state and bytes, never copy.
//
// The fixed known-vector at the bottom is the parity anchor: the Python and
// Rust certificate twins MUST reproduce the same root hex and the same COSE
// CBOR hex byte-for-byte from the same deterministic leaves/anchor inputs.

import fs from 'node:fs';
import nodePath from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { decodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { hexToBytes } from '@cardanowall/crypto-core/util';
import { merkleSha2256Root, sha256 } from '@cardanowall/crypto-core/hash';

import { bytesToHex } from '../hex';

import {
  buildInclusionCertificate,
  encodeCoseInclusionProof,
  encodeIetfInclusionProof,
  verifyInclusionCertificate,
} from './index';
import type {
  CertificateAnchor,
  CertificateMerkle,
  CertificateTarget,
  InclusionCertificateV1,
} from './types';

// Deterministic leaf: sha256 of a single byte. Reused by the parity vector.
function leafOf(i: number): Uint8Array {
  return sha256(new Uint8Array([i]));
}

function makeLeaves(n: number): Uint8Array[] {
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < n; i++) leaves.push(leafOf(i));
  return leaves;
}

function anchorFor(network = 'mainnet'): CertificateAnchor {
  return {
    chain: 'cardano',
    network,
    txHash: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
    metadataLabel: 309,
    blockTime: 1_718_539_200,
    blockHeight: 12_345_678,
    slot: 123_456_789,
  };
}

function merkleFor(leaves: ReadonlyArray<Uint8Array>): CertificateMerkle {
  return {
    treeAlg: 'rfc9162-sha256',
    root: merkleSha2256Root(leaves),
    treeSize: leaves.length,
  };
}

describe('buildInclusionCertificate + verifyInclusionCertificate round-trip', () => {
  it('builds and re-verifies several targets to ok:true', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const targets: CertificateTarget[] = [
      { leaf: leaves[0]!, label: 'first' },
      { leaf: leaves[3]!, leafAlg: 'sha2-256' },
      { leaf: leaves[7]! },
    ];

    const cert = buildInclusionCertificate({ anchor: anchorFor(), merkle, leaves, targets });

    // Every built item verified at generation time.
    expect(cert.items).toHaveLength(3);
    expect(cert.items.every((it) => it.verified)).toBe(true);
    expect(cert.items.map((it) => it.index)).toEqual([0, 3, 7]);
    // Hex is lowercase, 32-byte values.
    expect(cert.merkle.root).toMatch(/^[0-9a-f]{64}$/);
    expect(cert.items[0]!.leaf).toMatch(/^[0-9a-f]{64}$/);

    // anchor camelCase → snake_case mapping with derived ISO time.
    expect(cert.anchor.tx_hash).toBe(anchorFor().txHash);
    expect(cert.anchor.metadata_label).toBe(309);
    expect(cert.anchor.block_time_iso).toBe(new Date(1_718_539_200 * 1000).toISOString());
    expect(cert.anchor.block_height).toBe(12_345_678);

    // Independent re-verification recomputes every proof against the root.
    const result = verifyInclusionCertificate(cert);
    expect(result.ok).toBe(true);
    expect(result.items.map((v) => v.verified)).toEqual([true, true, true]);
    expect(result.items.map((v) => v.index)).toEqual([0, 3, 7]);
    expect(result.anchorClaim.txHash).toBe(anchorFor().txHash);
    expect(result.anchorClaim.blockTime).toBe(1_718_539_200);
  });

  it('omits optional anchor fields that are undefined (no nulls emitted)', () => {
    const leaves = makeLeaves(4);
    const merkle = merkleFor(leaves);
    const anchor: CertificateAnchor = {
      chain: 'cardano',
      network: 'preprod',
      txHash: 'ff'.repeat(32),
      metadataLabel: 309,
      blockTime: 1_700_000_000,
    };
    const cert = buildInclusionCertificate({
      anchor,
      merkle,
      leaves,
      targets: [{ leaf: leaves[1]! }],
    });
    expect('block_height' in cert.anchor).toBe(false);
    expect('slot' in cert.anchor).toBe(false);
    expect('confirmations_at_generation' in cert.anchor).toBe(false);
    expect('explorer_urls' in cert.anchor).toBe(false);
    // No null leaked into the serialised form.
    expect(JSON.stringify(cert.anchor)).not.toContain('null');
  });
});

describe('tamper detection', () => {
  it('flips an item to false when a sibling is corrupted', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[2]! }],
    });

    const sibling = hexToBytes(cert.items[0]!.proof[0]!);
    sibling[0] = (sibling[0]! ^ 0xff) & 0xff;
    const tampered: InclusionCertificateV1 = {
      ...cert,
      items: [
        { ...cert.items[0]!, proof: [bytesToHex(sibling), ...cert.items[0]!.proof.slice(1)] },
      ],
    };

    const result = verifyInclusionCertificate(tampered);
    expect(result.items[0]!.verified).toBe(false);
    expect(result.ok).toBe(false);
  });

  it('flips an item to false when the leaf is corrupted', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[5]! }],
    });

    const badLeaf = hexToBytes(cert.items[0]!.leaf);
    badLeaf[31] = (badLeaf[31]! ^ 0x01) & 0xff;
    const tampered: InclusionCertificateV1 = {
      ...cert,
      items: [{ ...cert.items[0]!, leaf: bytesToHex(badLeaf) }],
    };
    const result = verifyInclusionCertificate(tampered);
    expect(result.items[0]!.verified).toBe(false);
    expect(result.ok).toBe(false);
  });

  it('flips every item to false when the root is corrupted', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[0]! }, { leaf: leaves[1]! }],
    });

    const badRoot = hexToBytes(cert.merkle.root);
    badRoot[0] = (badRoot[0]! ^ 0xff) & 0xff;
    const tampered: InclusionCertificateV1 = {
      ...cert,
      merkle: { ...cert.merkle, root: bytesToHex(badRoot) },
    };
    const result = verifyInclusionCertificate(tampered);
    expect(result.items.every((v) => v.verified === false)).toBe(true);
    expect(result.ok).toBe(false);
  });
});

describe('edge cases', () => {
  it('proves a single-leaf tree with an empty proof', () => {
    const leaves = makeLeaves(1);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[0]! }],
    });
    expect(cert.items[0]!.proof).toEqual([]);
    expect(cert.items[0]!.verified).toBe(true);
    expect(verifyInclusionCertificate(cert).ok).toBe(true);
  });

  it('emits a non-throwing miss for a target absent from the leaf set', () => {
    const leaves = makeLeaves(4);
    const merkle = merkleFor(leaves);
    const stranger = sha256(new Uint8Array([0xaa, 0xbb])); // not any leafOf(i)

    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[1]! }, { leaf: stranger, label: 'missing.pdf' }],
    });

    expect(cert.items).toHaveLength(2);
    expect(cert.items[0]!.verified).toBe(true);

    const miss = cert.items[1]!;
    expect(miss.verified).toBe(false);
    expect(typeof miss.error).toBe('string');
    expect(miss.error!.length).toBeGreaterThan(0);
    expect(miss.label).toBe('missing.pdf');

    // The miss makes the whole certificate not-ok on re-verify, and the error
    // survives into the verdict.
    const result = verifyInclusionCertificate(cert);
    expect(result.ok).toBe(false);
    expect(result.items[1]!.verified).toBe(false);
    expect(result.items[1]!.error).toBe(miss.error);
  });
});

describe('structural misuse throws at build time', () => {
  const leaves = makeLeaves(4);

  it('throws on a root that is not 32 bytes', () => {
    expect(() =>
      buildInclusionCertificate({
        anchor: anchorFor(),
        merkle: { treeAlg: 'rfc9162-sha256', root: new Uint8Array(31), treeSize: 4 },
        leaves,
        targets: [{ leaf: leaves[0]! }],
      }),
    ).toThrow();
  });

  it('throws when treeSize does not equal leaves.length', () => {
    expect(() =>
      buildInclusionCertificate({
        anchor: anchorFor(),
        merkle: { treeAlg: 'rfc9162-sha256', root: merkleSha2256Root(leaves), treeSize: 5 },
        leaves,
        targets: [{ leaf: leaves[0]! }],
      }),
    ).toThrow();
  });

  it('throws on an unsupported tree algorithm', () => {
    expect(() =>
      buildInclusionCertificate({
        anchor: anchorFor(),
        merkle: { treeAlg: 'blake2b-merkle', root: merkleSha2256Root(leaves), treeSize: 4 },
        leaves,
        targets: [{ leaf: leaves[0]! }],
      }),
    ).toThrow();
  });

  it('throws when the declared root does not match the root of the leaves', () => {
    // A correctly-sized, correctly-typed root that simply is not this tree's
    // root — building proofs against it would emit an all-failing certificate.
    const wrongRoot = merkleSha2256Root(makeLeaves(4).reverse());
    expect(() =>
      buildInclusionCertificate({
        anchor: anchorFor(),
        merkle: { treeAlg: 'rfc9162-sha256', root: wrongRoot, treeSize: 4 },
        leaves,
        targets: [{ leaf: leaves[0]! }],
      }),
    ).toThrow();
  });
});

describe('verifyInclusionCertificate rejects unsupported certificates without throwing', () => {
  const leaves = makeLeaves(4);
  const merkle = merkleFor(leaves);
  const base = buildInclusionCertificate({
    anchor: anchorFor(),
    merkle,
    leaves,
    targets: [{ leaf: leaves[0]! }],
  });

  it('rejects an unknown format with ok:false + error, anchor still echoed', () => {
    const result = verifyInclusionCertificate({
      ...base,
      format: 'something-else' as InclusionCertificateV1['format'],
    });
    expect(result.ok).toBe(false);
    expect(typeof result.error).toBe('string');
    expect(result.items).toEqual([]);
    expect(result.anchorClaim.txHash).toBe(anchorFor().txHash);
  });

  it('rejects an unsupported tree_alg with ok:false + error', () => {
    const result = verifyInclusionCertificate({
      ...base,
      merkle: { ...base.merkle, tree_alg: 'rfc9162-blake2b' },
    });
    expect(result.ok).toBe(false);
    expect(typeof result.error).toBe('string');
  });

  it('rejects a forged oversized tree_size with ok:false and never throws', () => {
    // 2^32 is past the 32-bit fold boundary the primitive can verify exactly.
    const forged: InclusionCertificateV1 = {
      ...base,
      merkle: { ...base.merkle, tree_size: 0x1_0000_0000 },
    };
    let result: ReturnType<typeof verifyInclusionCertificate> | undefined;
    expect(() => {
      result = verifyInclusionCertificate(forged);
    }).not.toThrow();
    expect(result!.ok).toBe(false);
    expect(typeof result!.error).toBe('string');
  });

  it('rejects an item whose index is out of range without throwing', () => {
    // base.items[0] is a proven item (no error field); only the index is forged.
    const forged: InclusionCertificateV1 = {
      ...base,
      items: [{ ...base.items[0]!, index: 999 }],
    };
    const result = verifyInclusionCertificate(forged);
    expect(result.ok).toBe(false);
    expect(result.items[0]!.verified).toBe(false);
    expect(typeof result.items[0]!.error).toBe('string');
  });

  it('rejects an anchor that is not Cardano metadata label 309, echoing the claim', () => {
    const wrongChain = verifyInclusionCertificate({
      ...base,
      anchor: { ...base.anchor, chain: 'bitcoin' as InclusionCertificateV1['anchor']['chain'] },
    });
    expect(wrongChain.ok).toBe(false);
    expect(typeof wrongChain.error).toBe('string');
    // The claim is echoed verbatim, not fabricated as 'cardano'.
    expect(wrongChain.anchorClaim.chain).toBe('bitcoin');

    const wrongLabel = verifyInclusionCertificate({
      ...base,
      anchor: {
        ...base.anchor,
        metadata_label: 721 as InclusionCertificateV1['anchor']['metadata_label'],
      },
    });
    expect(wrongLabel.ok).toBe(false);
    expect(typeof wrongLabel.error).toBe('string');
    expect(wrongLabel.anchorClaim.metadataLabel).toBe(721);
  });
});

describe('encodeCoseInclusionProof / encodeIetfInclusionProof CBOR shape', () => {
  it('encodes a decodable IETF inclusion-proof and full COSE map', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const anchor = anchorFor();
    const cert = buildInclusionCertificate({
      anchor,
      merkle,
      leaves,
      targets: [{ leaf: leaves[6]!, leafAlg: 'sha2-256' }],
    });
    const item = cert.items[0]!;

    // The bare IETF inclusion-proof is a `bstr .cbor [...]`: decode it once as a
    // byte string, then decode those bytes as [tree_size, leaf_index, siblings].
    const bstrBytes = encodeIetfInclusionProof(item, merkle);
    const innerArrayBytes = decodeCanonicalCbor(bstrBytes) as Uint8Array;
    expect(innerArrayBytes).toBeInstanceOf(Uint8Array);
    const inner = decodeCanonicalCbor(innerArrayBytes) as CanonicalCborValue[];
    expect(Array.isArray(inner)).toBe(true);
    expect(inner[0]).toBe(merkle.treeSize);
    expect(inner[1]).toBe(item.index);
    const siblings = inner[2] as Uint8Array[];
    expect(siblings.map((s) => bytesToHex(s))).toEqual(item.proof);

    // Full COSE map.
    const coseBytes = encodeCoseInclusionProof(item, merkle, anchor);
    const cose = decodeCanonicalCbor(coseBytes) as Record<string, CanonicalCborValue>;
    expect(cose['vds']).toBe(1);
    expect(bytesToHex(cose['root'] as Uint8Array)).toBe(cert.merkle.root);
    expect(bytesToHex(cose['leaf'] as Uint8Array)).toBe(item.leaf);
    expect(cose['leaf_alg']).toBe('sha2-256');

    const a = cose['anchor'] as Record<string, CanonicalCborValue>;
    expect(a['chain']).toBe('cardano');
    expect(a['network']).toBe('mainnet');
    expect(a['metadata_label']).toBe(309);
    expect(bytesToHex(a['tx_hash'] as Uint8Array)).toBe(anchor.txHash);

    // The map's inclusion_proof field is encoded on the wire as the same bstr
    // the bare IETF helper returns: decoding the map field yields the array
    // bytes, and decoding the bare helper's bstr yields the identical bytes.
    expect(bytesToHex(cose['inclusion_proof'] as Uint8Array)).toBe(bytesToHex(innerArrayBytes));
    // And the on-wire bstr (header + contents) appears verbatim inside the COSE
    // map bytes — byte-identical to the standalone IETF helper output.
    expect(bytesToHex(coseBytes)).toContain(bytesToHex(bstrBytes));
  });

  it('refuses to encode a non-inclusion item (miss / unverified / bad index)', () => {
    const leaves = makeLeaves(4);
    const merkle = merkleFor(leaves);
    const stranger = sha256(new Uint8Array([0x99, 0x88]));
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[0]! }, { leaf: stranger }],
    });
    const proven = cert.items[0]!;
    const miss = cert.items[1]!;

    // A miss has an error and verified:false — both encoders refuse it.
    expect(() => encodeCoseInclusionProof(miss, merkle, anchorFor())).toThrow(TypeError);
    expect(() => encodeIetfInclusionProof(miss, merkle)).toThrow(TypeError);

    // An otherwise-proven item forced to verified:false is also refused.
    expect(() =>
      encodeCoseInclusionProof({ ...proven, verified: false }, merkle, anchorFor()),
    ).toThrow(TypeError);

    // An out-of-range index on a proven-shaped item is refused.
    expect(() => encodeCoseInclusionProof({ ...proven, index: 4 }, merkle, anchorFor())).toThrow(
      TypeError,
    );
  });

  it('omits leaf_alg from the COSE map when the item has none', () => {
    const leaves = makeLeaves(4);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[0]! }],
    });
    const cose = decodeCanonicalCbor(
      encodeCoseInclusionProof(cert.items[0]!, merkle, anchorFor()),
    ) as Record<string, CanonicalCborValue>;
    expect('leaf_alg' in cose).toBe(false);
  });
});

describe('hex case-insensitivity and malformed-hex handling', () => {
  function uppercaseHexFields(cert: InclusionCertificateV1): InclusionCertificateV1 {
    return {
      ...cert,
      merkle: { ...cert.merkle, root: cert.merkle.root.toUpperCase() },
      items: cert.items.map((it) => ({
        ...it,
        leaf: it.leaf.toUpperCase(),
        proof: it.proof.map((s) => s.toUpperCase()),
      })),
    };
  }

  it('verifies an uppercase-hex certificate identically to its lowercase form', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[0]! }, { leaf: leaves[5]! }],
    });

    const lower = verifyInclusionCertificate(cert);
    const upper = verifyInclusionCertificate(uppercaseHexFields(cert));

    expect(upper.ok).toBe(true);
    expect(upper.ok).toBe(lower.ok);
    expect(upper.items.map((v) => v.verified)).toEqual(lower.items.map((v) => v.verified));
    expect(upper.items.map((v) => v.verified)).toEqual([true, true]);
  });

  it('returns ok:false (never throws) when a leaf hex field has an embedded space', () => {
    const leaves = makeLeaves(4);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[1]! }],
    });
    const spaced: InclusionCertificateV1 = {
      ...cert,
      items: [
        {
          ...cert.items[0]!,
          leaf: `${cert.items[0]!.leaf.slice(0, 10)} ${cert.items[0]!.leaf.slice(11)}`,
        },
      ],
    };

    let result: ReturnType<typeof verifyInclusionCertificate> | undefined;
    expect(() => {
      result = verifyInclusionCertificate(spaced);
    }).not.toThrow();
    expect(result!.ok).toBe(false);
    expect(result!.items[0]!.verified).toBe(false);
    expect(typeof result!.items[0]!.error).toBe('string');
  });

  it('returns ok:false (never throws) when a proof sibling has whitespace', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[2]! }],
    });
    const sib = cert.items[0]!.proof[0]!;
    const spaced: InclusionCertificateV1 = {
      ...cert,
      items: [
        {
          ...cert.items[0]!,
          proof: [` ${sib.slice(1)}`, ...cert.items[0]!.proof.slice(1)],
        },
      ],
    };
    let result: ReturnType<typeof verifyInclusionCertificate> | undefined;
    expect(() => {
      result = verifyInclusionCertificate(spaced);
    }).not.toThrow();
    expect(result!.ok).toBe(false);
    expect(result!.items[0]!.verified).toBe(false);
  });

  it('the COSE encoder accepts uppercase hex and emits the same bytes as lowercase', () => {
    const leaves = makeLeaves(4);
    const merkle = merkleFor(leaves);
    const anchor = anchorFor();
    const cert = buildInclusionCertificate({
      anchor,
      merkle,
      leaves,
      targets: [{ leaf: leaves[2]!, leafAlg: 'sha2-256' }],
    });
    const lowerCose = encodeCoseInclusionProof(cert.items[0]!, merkle, anchor);
    const upperItem = {
      ...cert.items[0]!,
      leaf: cert.items[0]!.leaf.toUpperCase(),
      proof: cert.items[0]!.proof.map((s) => s.toUpperCase()),
    };
    const upperAnchor = { ...anchor, txHash: anchor.txHash.toUpperCase() };
    const upperCose = encodeCoseInclusionProof(upperItem, merkle, upperAnchor);
    expect(bytesToHex(upperCose)).toBe(bytesToHex(lowerCose));
  });
});

describe('wrong-length hex fields verify like the canonical TypeScript shape', () => {
  // The verify path decodes hex without a 32-byte gate; a valid-hex-but-wrong-
  // length root/sibling flows into the primitive, which returns false. So a
  // wrong-length field is a non-verifying item, not a cert-level rejection and
  // not an item-level error. The parity twins reproduce this exact result shape.
  it('a wrong-length root keeps items (verified:false), no cert error, ok:false', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[0]! }, { leaf: leaves[3]! }],
    });
    // 31 bytes of valid hex — decodes fine, but is not a 32-byte root.
    const shortRoot = cert.merkle.root.slice(0, 62);
    const forged: InclusionCertificateV1 = {
      ...cert,
      merkle: { ...cert.merkle, root: shortRoot },
    };
    const result = verifyInclusionCertificate(forged);
    expect(result.ok).toBe(false);
    expect(result.error).toBeUndefined();
    expect(result.items).toHaveLength(2);
    expect(result.items.every((v) => v.verified === false)).toBe(true);
    expect(result.items.every((v) => v.error === undefined)).toBe(true);
  });

  it('a wrong-length sibling keeps the item (verified:false), no item error, ok:false', () => {
    const leaves = makeLeaves(8);
    const merkle = merkleFor(leaves);
    const cert = buildInclusionCertificate({
      anchor: anchorFor(),
      merkle,
      leaves,
      targets: [{ leaf: leaves[2]! }],
    });
    const sib = cert.items[0]!.proof[0]!;
    const forged: InclusionCertificateV1 = {
      ...cert,
      items: [{ ...cert.items[0]!, proof: [sib.slice(0, 62), ...cert.items[0]!.proof.slice(1)] }],
    };
    const result = verifyInclusionCertificate(forged);
    expect(result.ok).toBe(false);
    expect(result.error).toBeUndefined();
    expect(result.items).toHaveLength(1);
    expect(result.items[0]!.verified).toBe(false);
    expect(result.items[0]!.error).toBeUndefined();
  });
});

describe('block_time range guard in the builder', () => {
  const leaves = makeLeaves(4);
  const merkle = merkleFor(leaves);

  it('renders the fixed millisecond ISO shape for an in-range epoch', () => {
    const cert = buildInclusionCertificate({
      anchor: { ...anchorFor(), blockTime: 1_718_539_200 },
      merkle,
      leaves,
      targets: [{ leaf: leaves[0]! }],
    });
    expect(cert.anchor.block_time_iso).toBe('2024-06-16T12:00:00.000Z');
  });

  it('throws on a negative block_time', () => {
    expect(() =>
      buildInclusionCertificate({
        anchor: { ...anchorFor(), blockTime: -1 },
        merkle,
        leaves,
        targets: [{ leaf: leaves[0]! }],
      }),
    ).toThrow();
  });

  it('throws on a block_time at or beyond year 10000', () => {
    expect(() =>
      buildInclusionCertificate({
        anchor: { ...anchorFor(), blockTime: 253_402_300_800 },
        merkle,
        leaves,
        targets: [{ leaf: leaves[0]! }],
      }),
    ).toThrow();
  });
});

describe('fixed known vector — cross-language parity anchor', () => {
  // A deterministic 4-leaf tree where leaf_i = SHA-256(<single byte i>), an
  // anchor with tx_hash = "abcdef0123456789" repeated to 64 hex, and the item
  // at index 2 with leaf_alg "sha2-256". The CBOR proofs are the byte-parity
  // anchor: the Python and Rust certificate twins MUST reproduce the root hex,
  // the bare IETF inclusion-proof CBOR, and the COSE CBOR hex byte-for-byte.
  // JSON parity is field/value-level (a serializer's whitespace and number
  // formatting differ across languages), so the twins match field values —
  // including the fixed `generated_at` — not raw JSON bytes.
  //
  // The pinned constants come from the shared cross-language conformance vector
  // so all SDK twins assert against one source of truth.
  interface InclusionCertificateKatVector {
    readonly name: string;
    readonly input: {
      readonly leaves: ReadonlyArray<string>;
      readonly tree_size: number;
      readonly anchor: {
        readonly chain: 'cardano';
        readonly network: string;
        readonly tx_hash: string;
        readonly metadata_label: 309;
        readonly block_time: number;
      };
      readonly target: { readonly index: number; readonly leaf_alg?: string };
    };
    readonly expected: {
      readonly root: string;
      readonly leaf: string;
      readonly inclusion_path: ReadonlyArray<string>;
      readonly ietf_inclusion_proof_cbor_hex: string;
      readonly cose_inclusion_proof_cbor_hex: string;
    };
  }
  interface InclusionCertificateKatCorpus {
    readonly version: number;
    readonly primitive: string;
    readonly tree_alg: string;
    readonly vds: number;
    readonly vectors: ReadonlyArray<InclusionCertificateKatVector>;
  }

  const corpus = JSON.parse(
    fs.readFileSync(
      nodePath.resolve(
        nodePath.dirname(fileURLToPath(import.meta.url)),
        '../../tests/fixtures/certificate/inclusion-certificate-kat.json',
      ),
      'utf8',
    ),
  ) as InclusionCertificateKatCorpus;

  const vector = corpus.vectors[0]!;
  const FIXED_GENERATED_AT = '2026-06-16T12:00:00.000Z';

  const vectorLeaves = vector.input.leaves.map((hex) => hexToBytes(hex));
  const anchor: CertificateAnchor = {
    chain: vector.input.anchor.chain,
    network: vector.input.anchor.network,
    txHash: vector.input.anchor.tx_hash,
    metadataLabel: vector.input.anchor.metadata_label,
    blockTime: vector.input.anchor.block_time,
  };
  const targetIndex = vector.input.target.index;
  const targetLeafAlg = vector.input.target.leaf_alg;

  it('reproduces the expected root and COSE CBOR bytes exactly', () => {
    const merkle = merkleFor(vectorLeaves);
    expect(bytesToHex(merkle.root)).toBe(vector.expected.root);

    const cert = buildInclusionCertificate({
      anchor,
      merkle,
      leaves: vectorLeaves,
      targets: [
        {
          leaf: vectorLeaves[targetIndex]!,
          ...(targetLeafAlg !== undefined ? { leafAlg: targetLeafAlg } : {}),
        },
      ],
      generatedAt: FIXED_GENERATED_AT,
    });
    const item = cert.items[0]!;

    // The bare IETF inclusion proof is the `bstr .cbor` byte string the encoder
    // returns (a CBOR byte string wrapping the `[tree_size, leaf_index,
    // inclusion_path]` array). The shared vector pins that byte string directly.
    const ietfBstr = encodeIetfInclusionProof(item, merkle);
    expect(bytesToHex(ietfBstr)).toBe(vector.expected.ietf_inclusion_proof_cbor_hex);

    // The full COSE map is the byte-identical cross-language anchor.
    expect(bytesToHex(encodeCoseInclusionProof(item, merkle, anchor))).toBe(
      vector.expected.cose_inclusion_proof_cbor_hex,
    );
  });

  it('emits a reproducible certificate with the fixed generated_at and normative item key order', () => {
    const merkle = merkleFor(vectorLeaves);
    const cert = buildInclusionCertificate({
      anchor,
      merkle,
      leaves: vectorLeaves,
      targets: [{ leaf: vectorLeaves[targetIndex]!, leafAlg: 'sha2-256', label: 'contract.pdf' }],
      generatedAt: FIXED_GENERATED_AT,
    });

    expect(cert.generated_at).toBe(FIXED_GENERATED_AT);
    // Field-level JSON parity: item keys appear in the normative order.
    expect(Object.keys(cert.items[0]!)).toEqual([
      'leaf',
      'leaf_alg',
      'index',
      'proof',
      'verified',
      'label',
    ]);
    // A target without leaf_alg/label omits exactly those keys, order intact.
    const certPlain = buildInclusionCertificate({
      anchor,
      merkle,
      leaves: vectorLeaves,
      targets: [{ leaf: vectorLeaves[0]! }],
      generatedAt: FIXED_GENERATED_AT,
    });
    expect(Object.keys(certPlain.items[0]!)).toEqual(['leaf', 'index', 'proof', 'verified']);
  });
});
