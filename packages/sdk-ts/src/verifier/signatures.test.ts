// Record-level signature verification tests for the v1 wire format. Covers:
//   * Path 1 (in-signature 32-byte protected kid) happy path
//   * Tampered signature → SIGNATURE_INVALID
//   * Detached-payload mandate (attached payload → MALFORMED_SIG_COSE_SIGN1)
//   * Path 2 (wallet inline COSE_Key) → WALLET_ADDRESS_MISMATCH when the
//     protected-header `address` does not match Blake2b-224(pubkey)

import { describe, expect, it } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import {
  buildSigStructure,
  coseSign1Label309Build,
  encodeCoseSign1,
  type CoseHeader,
} from '@cardanowall/crypto-core/cose';
import { blake2b224 } from '@cardanowall/crypto-core/hash';
import { getPublicKeyEd25519, signEd25519 } from '@cardanowall/crypto-core/sig';
import {
  encodeRecordBodyForSigning,
  PoeRecordSchema,
  type PoeRecord,
} from '@cardanowall/poe-standard';

import { IssueSink } from './issues';
import { verifyRecordSignatures } from './signatures';

const MAINNET_STAKE_NETWORK_BYTE = 0xe1;

function makeSeed(byte: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function buildEd25519CoseKey(pub: Uint8Array): Uint8Array {
  // RFC 9053 §7.2 OKP / Ed25519 COSE_Key.
  return encodeCanonicalCbor(
    new Map<number, unknown>([
      [1, 1],
      [3, -8],
      [-1, 6],
      [-2, pub],
    ]) as unknown as CanonicalCborValue,
  );
}

interface BuiltRecord {
  readonly record: PoeRecord;
  readonly pub: Uint8Array;
}

function buildPath1Record(opts: { seed?: Uint8Array; tamper?: boolean } = {}): BuiltRecord {
  const seed = opts.seed ?? makeSeed(11);
  const pub = getPublicKeyEd25519({ seed });
  const recordBase = PoeRecordSchema.parse({
    v: 1,
    items: [{ hashes: { 'sha2-256': new Uint8Array(32).fill(0x77) } }],
  });
  const bodyCbor = encodeRecordBodyForSigning(recordBase);
  const protectedHeader: CoseHeader = new Map<number, unknown>([
    [1, -8],
    [4, pub],
  ]);
  let cose = coseSign1Label309Build({
    protectedHeader,
    unprotectedHeader: new Map(),
    recordBodyCbor: bodyCbor,
    signerSecretKey: seed,
  });
  if (opts.tamper) {
    cose = new Uint8Array(cose);
    cose[cose.length - 30] = (cose[cose.length - 30]! + 1) & 0xff;
  }
  return {
    record: {
      ...recordBase,
      sigs: [{ cose_sign1: cose }],
    } as PoeRecord,
    pub,
  };
}

function buildPath2Record(
  opts: {
    seed?: Uint8Array;
    mainnetAddress?: boolean;
    badAddress?: boolean;
  } = {},
): BuiltRecord {
  const seed = opts.seed ?? makeSeed(20);
  const pub = getPublicKeyEd25519({ seed });
  const recordBase = PoeRecordSchema.parse({
    v: 1,
    items: [{ hashes: { 'sha2-256': new Uint8Array(32).fill(0x88) } }],
  });
  const bodyCbor = encodeRecordBodyForSigning(recordBase);
  const stakeKeyHash = blake2b224(pub);
  const address = new Uint8Array(29);
  if (opts.mainnetAddress !== false) {
    address[0] = MAINNET_STAKE_NETWORK_BYTE;
  } else {
    address[0] = 0x12; // bogus network byte
  }
  if (opts.badAddress) {
    // overwrite the stake-hash with garbage so the binding fails
    address.set(new Uint8Array(28).fill(0x55), 1);
  } else {
    address.set(stakeKeyHash, 1);
  }
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    ['address', address],
  ]);
  const cose = coseSign1Label309Build({
    protectedHeader,
    unprotectedHeader: new Map(),
    recordBodyCbor: bodyCbor,
    signerSecretKey: seed,
  });
  const coseKey = buildEd25519CoseKey(pub);
  return {
    record: {
      ...recordBase,
      sigs: [{ cose_sign1: cose, cose_key: coseKey }],
    } as PoeRecord,
    pub,
  };
}

describe('verifyRecordSignatures — path 1 (in-signature kid)', () => {
  it('happy path: 32-byte protected kid → verdict valid', () => {
    const built = buildPath1Record();
    const out = verifyRecordSignatures({
      record: built.record,
      cardanoNetwork: 'mainnet',
      issues: new IssueSink(),
    });
    expect(out).toEqual([
      {
        index: 0,
        verdict: 'valid',
        signerType: 'in-signature-kid',
        signerPub: bytesToHex(built.pub),
      },
    ]);
  });

  it('tampered signature byte → verdict invalid, reason SIGNATURE_INVALID', () => {
    const built = buildPath1Record({ tamper: true });
    const out = verifyRecordSignatures({
      record: built.record,
      cardanoNetwork: 'mainnet',
      issues: new IssueSink(),
    });
    expect(out[0]!.verdict).toBe('invalid');
    expect(out[0]!.reason).toBe('SIGNATURE_INVALID');
  });

  it('attached payload → MALFORMED_SIG_COSE_SIGN1', () => {
    // Build a COSE_Sign1 with an ATTACHED (non-null) payload. Label 309 mandates
    // a detached payload, so the verifier must reject this as malformed.
    const seed = makeSeed(30);
    const pub = getPublicKeyEd25519({ seed });
    const recordBase = PoeRecordSchema.parse({
      v: 1,
      items: [{ hashes: { 'sha2-256': new Uint8Array(32) } }],
    });
    const bodyCbor = encodeRecordBodyForSigning(recordBase);
    const protectedHeader: CoseHeader = new Map<number, unknown>([
      [1, -8],
      [4, pub],
    ]);
    const protectedBytes = encodeCanonicalCbor(protectedHeader as CanonicalCborValue);
    const sigStructure = buildSigStructure({
      context: 'Signature1',
      bodyProtectedBytes: protectedBytes,
      externalAad: new Uint8Array(0),
      payload: bodyCbor,
    });
    const signature = signEd25519({ seed, message: sigStructure });
    const cose = encodeCoseSign1({
      protectedHeader,
      unprotectedHeader: new Map(),
      payload: bodyCbor, // attached (non-null) → Label 309-non-conformant
      signature,
    });
    const record = {
      ...recordBase,
      sigs: [{ cose_sign1: cose }],
    } as PoeRecord;
    const out = verifyRecordSignatures({
      record,
      cardanoNetwork: 'mainnet',
      issues: new IssueSink(),
    });
    expect(out[0]!.verdict).toBe('invalid');
    expect(out[0]!.reason).toBe('MALFORMED_SIG_COSE_SIGN1');
  });
});

describe('verifyRecordSignatures — path 2 (wallet inline cose_key)', () => {
  it('correct address binding → verdict valid', () => {
    const built = buildPath2Record();
    const out = verifyRecordSignatures({
      record: built.record,
      cardanoNetwork: 'mainnet',
      issues: new IssueSink(),
    });
    expect(out[0]!.verdict).toBe('valid');
    expect(out[0]!.signerType).toBe('wallet-inline-key');
    expect(out[0]!.signerPub).toBe(bytesToHex(built.pub));
  });

  it('mismatched address bytes → WALLET_ADDRESS_MISMATCH', () => {
    const built = buildPath2Record({ badAddress: true });
    const out = verifyRecordSignatures({
      record: built.record,
      cardanoNetwork: 'mainnet',
      issues: new IssueSink(),
    });
    expect(out[0]!.verdict).toBe('invalid');
    expect(out[0]!.reason).toBe('WALLET_ADDRESS_MISMATCH');
  });

  it('wrong network header → WALLET_ADDRESS_MISMATCH', () => {
    const built = buildPath2Record({ mainnetAddress: false });
    const out = verifyRecordSignatures({
      record: built.record,
      cardanoNetwork: 'mainnet',
      issues: new IssueSink(),
    });
    expect(out[0]!.verdict).toBe('invalid');
    expect(out[0]!.reason).toBe('WALLET_ADDRESS_MISMATCH');
  });
});
