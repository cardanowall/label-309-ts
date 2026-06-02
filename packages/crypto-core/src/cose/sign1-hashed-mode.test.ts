// Crypto-core verifier hashed-mode dedicated test.
//
// Covers `coseSign1Cip309Verify`'s branching on the unprotected
// `"hashed": true` flag in isolation (independent of the SDK-level helper).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '../cbor/canonical';
import { blake2b224 } from '../hash/blake2b-256';
import { signEd25519 } from '../sig/ed25519';

import {
  CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES,
  buildCip309SigStructure,
  buildSigStructure,
  coseSign1Cip309Verify,
  encodeCoseSign1,
  type CoseHeader,
} from './sign1';

interface CardanoPoeBuildVector {
  name: string;
  signer_secret_key_hex: string;
  signer_public_key_hex: string;
  record_body_cbor_hex: string;
}

interface Sign1BuildCorpus {
  cardano_poe_vectors: CardanoPoeBuildVector[];
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, '../../tests/fixtures/cose/sign1-build.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as Sign1BuildCorpus;

const EMPTY_BYTES = new Uint8Array(0);

function buildHashedModeCoseSign1(args: {
  signerPubkey: Uint8Array;
  seed: Uint8Array;
  recordBodyCbor: Uint8Array;
}): { coseBytes: Uint8Array; sigStructureBytes: Uint8Array } {
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    [4, args.signerPubkey],
  ]);
  const protectedHeaderBytes = encodeCanonicalCbor(protectedHeader as CanonicalCborValue);
  const toSign = new Uint8Array(
    CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length + args.recordBodyCbor.length,
  );
  toSign.set(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES, 0);
  toSign.set(args.recordBodyCbor, CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length);
  const hashed = blake2b224(toSign);
  const sigStructureBytes = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: protectedHeaderBytes,
    externalAad: EMPTY_BYTES,
    payload: hashed,
  });
  const signature = signEd25519({ seed: args.seed, message: sigStructureBytes });
  const coseBytes = encodeCoseSign1({
    protectedHeader,
    unprotectedHeader: new Map<number | string, unknown>([['hashed', true]]),
    payload: null,
    signature,
  });
  return { coseBytes, sigStructureBytes };
}

describe('coseSign1Cip309Verify — hashed-mode (CIP-8)', () => {
  for (const vector of corpus.cardano_poe_vectors) {
    it(`accepts a valid hashed-mode COSE_Sign1 for ${vector.name}`, () => {
      const recordBodyCbor = hexToBytes(vector.record_body_cbor_hex);
      const { coseBytes } = buildHashedModeCoseSign1({
        signerPubkey: hexToBytes(vector.signer_public_key_hex),
        seed: hexToBytes(vector.signer_secret_key_hex),
        recordBodyCbor,
      });
      const result = coseSign1Cip309Verify({
        message: coseBytes,
        detachedRecordBodyCbor: recordBodyCbor,
      });
      expect(result.ok).toBe(true);
    });

    it(`rejects a hashed-mode COSE_Sign1 with the "hashed" flag removed for ${vector.name}`, () => {
      const recordBodyCbor = hexToBytes(vector.record_body_cbor_hex);
      const signerPubkey = hexToBytes(vector.signer_public_key_hex);
      const seed = hexToBytes(vector.signer_secret_key_hex);
      const { sigStructureBytes } = buildHashedModeCoseSign1({
        signerPubkey,
        seed,
        recordBodyCbor,
      });
      const signature = signEd25519({ seed, message: sigStructureBytes });
      const protectedHeader: CoseHeader = new Map<number | string, unknown>([
        [1, -8],
        [4, signerPubkey],
      ]);
      const strippedCose = encodeCoseSign1({
        protectedHeader,
        unprotectedHeader: new Map(),
        payload: null,
        signature,
      });
      const result = coseSign1Cip309Verify({
        message: strippedCose,
        detachedRecordBodyCbor: recordBodyCbor,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('SIGNATURE_INVALID');
    });

    it(`rejects a wrong signature for ${vector.name}`, () => {
      const recordBodyCbor = hexToBytes(vector.record_body_cbor_hex);
      const signerPubkey = hexToBytes(vector.signer_public_key_hex);
      const protectedHeader: CoseHeader = new Map<number | string, unknown>([
        [1, -8],
        [4, signerPubkey],
      ]);
      const bogusSignature = new Uint8Array(64);
      bogusSignature.fill(0xab);
      const coseBytes = encodeCoseSign1({
        protectedHeader,
        unprotectedHeader: new Map<number | string, unknown>([['hashed', true]]),
        payload: null,
        signature: bogusSignature,
      });
      const result = coseSign1Cip309Verify({
        message: coseBytes,
        detachedRecordBodyCbor: recordBodyCbor,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('SIGNATURE_INVALID');
    });

    it(`continues to accept non-hashed COSE_Sign1 unchanged for ${vector.name}`, () => {
      // Regression: when the flag is absent, behaviour must match the
      // existing KAT path. Build a NON-hashed COSE_Sign1 inline and verify.
      const recordBodyCbor = hexToBytes(vector.record_body_cbor_hex);
      const signerPubkey = hexToBytes(vector.signer_public_key_hex);
      const seed = hexToBytes(vector.signer_secret_key_hex);
      const protectedHeader: CoseHeader = new Map<number | string, unknown>([
        [1, -8],
        [4, signerPubkey],
      ]);
      const protectedHeaderBytes = encodeCanonicalCbor(protectedHeader as CanonicalCborValue);
      const sigStructureBytes = buildCip309SigStructure({
        bodyProtectedBytes: protectedHeaderBytes,
        recordBodyCbor,
      });
      const signature = signEd25519({ seed, message: sigStructureBytes });
      const coseBytes = encodeCoseSign1({
        protectedHeader,
        unprotectedHeader: new Map(),
        payload: null,
        signature,
      });
      const result = coseSign1Cip309Verify({
        message: coseBytes,
        detachedRecordBodyCbor: recordBodyCbor,
      });
      expect(result.ok).toBe(true);
    });
  }
});
