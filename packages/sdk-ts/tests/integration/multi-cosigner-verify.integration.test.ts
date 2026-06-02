// Multi-cosigner record-level sigs[] verifier integration test.
//
// Builds the mixed-paths reference record inline from byte-pinned seeds
// (RFC 8032 §7.1 Test 2 for the identity signer, `0x11 × 32` for the wallet
// signer), then exercises `verifyRecordSignatures` in both identity-first
// and wallet-first sigs[] orderings.

import { getPublicKeyEd25519, hexToBytes, signEd25519 } from '@cardanowall/crypto-core';
import {
  buildCip309SigStructure,
  encodeCoseSign1,
  type CoseHeader,
} from '@cardanowall/crypto-core/cose';
import { blake2b224 } from '@cardanowall/crypto-core/hash';
import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type CanonicalCborValue,
} from '@cardanowall/crypto-core/cbor';
import {
  chunkBytes,
  encodePoeRecord,
  encodeRecordBodyForSigning,
  type ChunkedBytesArray,
  type PoeRecord,
  type SigEntry,
} from '@cardanowall/poe-standard';
import { verifyRecordSignatures } from '@cardanowall/sdk-ts/verifier';
import { describe, expect, it } from 'vitest';

// Reference inputs (byte-pinned seeds + pubkeys).
const IDENTITY_SEED_HEX = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
const WALLET_SEED_HEX = '1111111111111111111111111111111111111111111111111111111111111111';
const WALLET_STAKE_ADDR_HEX = 'e02222222222222222222222222222222222222222222222222222222222';
const IDENTITY_PUBKEY_HEX = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
const WALLET_PUBKEY_HEX = 'd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737';
const AR_URI = 'ar://qP3RkY7nBs2Fz9HxV1WuC5oJ4mE6tN8aL0iDXgQrU0K';
const A2_SHA = '97a7881ce48f5bf457261797e06e3387a904f0ee70488d3c03090635800320ee';
const A2_BLAKE = '2d3b9520f17f6be4e26361b18afc8d7bbdbc2cd4209319a77f014f2fd0d409a4';

function chunkText(s: string): readonly string[] {
  // §A.6.7 fixture uses single-chunk text(48) for the ar:// uri (47 bytes
  // ≤ 64-byte chunk size).
  return [s];
}

function buildRecordBody(): PoeRecord {
  return {
    v: 1,
    items: [
      {
        hashes: {
          'sha2-256': hexToBytes(A2_SHA) as Uint8Array<ArrayBuffer>,
          'blake2b-256': hexToBytes(A2_BLAKE) as Uint8Array<ArrayBuffer>,
        },
        uris: [chunkText(AR_URI) as string[]],
      },
    ],
  };
}

function buildIdentitySigEntry(body: PoeRecord): SigEntry {
  const seed = hexToBytes(IDENTITY_SEED_HEX);
  const publicKey = getPublicKeyEd25519({ seed });
  expect(Array.from(publicKey, (x) => x.toString(16).padStart(2, '0')).join('')).toBe(
    IDENTITY_PUBKEY_HEX,
  );
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    [4, publicKey],
  ]);
  const protectedBytes = encodeCanonicalCbor(protectedHeader as CanonicalCborValue);
  const sigStructure = buildCip309SigStructure({
    bodyProtectedBytes: protectedBytes,
    recordBodyCbor: encodeRecordBodyForSigning(body),
  });
  const signature = signEd25519({ seed, message: sigStructure });
  const cose = encodeCoseSign1({
    protectedHeader,
    unprotectedHeader: new Map(),
    payload: null,
    signature,
  });
  return { cose_sign1: chunkBytes(cose) as ChunkedBytesArray };
}

function buildWalletSigEntry(body: PoeRecord): SigEntry {
  const seed = hexToBytes(WALLET_SEED_HEX);
  const publicKey = getPublicKeyEd25519({ seed });
  expect(Array.from(publicKey, (x) => x.toString(16).padStart(2, '0')).join('')).toBe(
    WALLET_PUBKEY_HEX,
  );
  // Compute a REAL stake address that binds to the wallet pubkey via
  // network_header || Blake2b-224(pubkey). The reference vector ships a
  // SYNTHETIC `e0 + 22*28` mock address that fails the verifier's path-2
  // WALLET_ADDRESS_MISMATCH check; this test needs a record that verifies
  // successfully, so we bind to the real Blake2b-224 derivation. This
  // deviates from the spec's byte-pinned CBOR but matches the verifier's
  // semantic expectation.
  const MAINNET_HEADER = 0xe1;
  const pubHash = blake2b224(publicKey);
  const stakeAddr = new Uint8Array(29);
  stakeAddr[0] = MAINNET_HEADER;
  stakeAddr.set(pubHash, 1);
  void WALLET_STAKE_ADDR_HEX;
  // Path-2 protected header carries `{1: -8, "address": <stake addr>}`.
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    ['address', stakeAddr],
  ]);
  const protectedBytes = encodeCanonicalCbor(protectedHeader as CanonicalCborValue);
  const sigStructure = buildCip309SigStructure({
    bodyProtectedBytes: protectedBytes,
    recordBodyCbor: encodeRecordBodyForSigning(body),
  });
  const signature = signEd25519({ seed, message: sigStructure });
  const cose = encodeCoseSign1({
    protectedHeader,
    unprotectedHeader: new Map(),
    payload: null,
    signature,
  });
  // Path-2 COSE_Key blob: `{1: 1, 3: -8, -1: 6, -2: pubkey}` (kty=OKP,
  // alg=Ed25519, crv=Ed25519, x=pubkey). Matches §A.6.7 fixture.
  const coseKey = encodeCanonicalCbor(
    new Map<number, unknown>([
      [1, 1],
      [3, -8],
      [-1, 6],
      [-2, publicKey],
    ]) as unknown as CanonicalCborValue,
  );
  return {
    cose_sign1: chunkBytes(cose) as ChunkedBytesArray,
    cose_key: chunkBytes(coseKey) as ChunkedBytesArray,
  };
}

describe('multi-cosigner verifier integration (§A.6.7 mixed-paths, identity-first)', () => {
  const body = buildRecordBody();
  const identityEntry = buildIdentitySigEntry(body);
  const walletEntry = buildWalletSigEntry(body);
  const record: PoeRecord = {
    ...body,
    sigs: [identityEntry, walletEntry],
  };

  it('verifyRecordSignatures returns 2 per-entry verdicts in insertion order', async () => {
    const out = await verifyRecordSignatures({
      record,
      input: { txHash: '0'.repeat(64) },
    });
    expect(out).toHaveLength(2);
    expect(out[0]!.verdict).toBe('valid');
    expect(out[0]!.signer_type).toBe('in-signature-kid');
    expect(out[1]!.verdict).toBe('valid');
    expect(out[1]!.signer_type).toBe('wallet-inline-key');
  });

  it('preserves sigs[] insertion order in the verdict array (per-entry index)', async () => {
    const out = await verifyRecordSignatures({
      record,
      input: { txHash: '0'.repeat(64) },
    });
    expect(out[0]!.index).toBe(0);
    expect(out[1]!.index).toBe(1);
  });

  it('encodes to canonical CBOR that round-trips byte-identically', () => {
    const cbor = encodePoeRecord(record);
    const decoded = decodeCanonicalCbor(cbor);
    const reencoded = encodeCanonicalCbor(decoded as CanonicalCborValue);
    expect(Array.from(reencoded)).toEqual(Array.from(cbor));
  });
});

describe('multi-cosigner verifier integration (§A.6.7 mixed-paths, wallet-first)', () => {
  const body = buildRecordBody();
  const identityEntry = buildIdentitySigEntry(body);
  const walletEntry = buildWalletSigEntry(body);
  const record: PoeRecord = {
    ...body,
    sigs: [walletEntry, identityEntry],
  };

  it('verifyRecordSignatures returns 2 valid verdicts in the reverse insertion order', async () => {
    const out = await verifyRecordSignatures({
      record,
      input: { txHash: '0'.repeat(64) },
    });
    expect(out).toHaveLength(2);
    expect(out[0]!.verdict).toBe('valid');
    expect(out[0]!.signer_type).toBe('wallet-inline-key');
    expect(out[1]!.verdict).toBe('valid');
    expect(out[1]!.signer_type).toBe('in-signature-kid');
  });
});
