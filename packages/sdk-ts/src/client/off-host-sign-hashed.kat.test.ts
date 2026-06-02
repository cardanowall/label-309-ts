// Off-host signing helper hashed-mode KAT test.
//
// 1. prepareSigStructureHashed returns toSignHashBytes = Blake2b-224(to_sign).
// 2. sigStructureBytes = canonical_cbor([ "Signature1", protected_bytes, h'',
//    toSignHashBytes ]).
// 3. assembleCoseSign1Hashed sets unprotected `"hashed": true`.
// 4. Splice the entry → verifyRecordSignatures returns valid.
// 5. Non-hashed signature ≠ hashed signature for the same seed + record.
// 6. Negative cross-checks: attacker setting `"hashed": true` over a non-hashed
//    signature fails with SIGNATURE_INVALID; hashed signature with the flag
//    removed also fails.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { decodeCanonicalCbor } from '@cardanowall/crypto-core/cbor';
import {
  buildSigStructure,
  decodeCoseSign1,
  encodeCoseSign1,
  type CoseHeader,
} from '@cardanowall/crypto-core/cose';
import { blake2b224 } from '@cardanowall/crypto-core/hash';
import { signEd25519 } from '@cardanowall/crypto-core/sig';
import type { PoeRecord, SigEntry } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { verifyRecordSignatures } from '../verifier/signatures';

import {
  assembleCoseSign1Hashed,
  buildToSign,
  prepareSigStructure,
  prepareSigStructureHashed,
} from './off-host-sign';

interface CardanoPoeBuildVector {
  name: string;
  signer_secret_key_hex: string;
  signer_public_key_hex: string;
  record_body_cbor_hex: string;
  expected_signature_hex: string;
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

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, '../../tests/fixtures/cose/sign1-build.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as Sign1BuildCorpus;

const EMPTY_BYTES = new Uint8Array(0);

describe.each(corpus.cardano_poe_vectors)(
  'off-host-sign hashed-mode KAT — $name',
  (vector: CardanoPoeBuildVector) => {
    const record = decodeCanonicalCbor(hexToBytes(vector.record_body_cbor_hex)) as PoeRecord;
    const signerPubkey = hexToBytes(vector.signer_public_key_hex);
    const seed = hexToBytes(vector.signer_secret_key_hex);

    it('toSignHashBytes equals Blake2b-224(buildToSign(record))', () => {
      const toSign = buildToSign(record);
      const expectedHash = blake2b224(toSign);
      const { toSignHashBytes } = prepareSigStructureHashed({ record, signerPubkey });
      expect(toSignHashBytes.length).toBe(28);
      expect(bytesToHex(toSignHashBytes)).toBe(bytesToHex(expectedHash));
    });

    it('sigStructureBytes is the canonical Sig_structure over the 28-byte hash', () => {
      const toSign = buildToSign(record);
      const expectedHash = blake2b224(toSign);
      const protectedHex = `a2012704582 0${vector.signer_public_key_hex}`.replace(/\s+/g, '');
      const expectedSigStructure = buildSigStructure({
        context: 'Signature1',
        bodyProtectedBytes: hexToBytes(protectedHex),
        externalAad: EMPTY_BYTES,
        payload: expectedHash,
      });
      const { sigStructureBytes } = prepareSigStructureHashed({ record, signerPubkey });
      expect(bytesToHex(sigStructureBytes)).toBe(bytesToHex(expectedSigStructure));
    });

    it('protected header is identical to the non-hashed path (38 bytes)', () => {
      const nonHashed = prepareSigStructure({ record, signerPubkey });
      const hashed = prepareSigStructureHashed({ record, signerPubkey });
      expect(bytesToHex(hashed.protectedHeaderBytes)).toBe(
        bytesToHex(nonHashed.protectedHeaderBytes),
      );
    });

    it('assembleCoseSign1Hashed sets unprotected "hashed": true', () => {
      const { sigStructureBytes } = prepareSigStructureHashed({ record, signerPubkey });
      const signature = signEd25519({ seed, message: sigStructureBytes });
      const { coseSign1Bytes } = assembleCoseSign1Hashed({
        record,
        signerPubkey,
        signature,
      });
      const decoded = decodeCoseSign1(coseSign1Bytes);
      expect(decoded.unprotectedHeader.get('hashed')).toBe(true);
      expect(decoded.payload).toBeNull();
      expect(decoded.signature.length).toBe(64);
    });

    it('hashed-mode signature is NOT byte-equal to non-hashed signature', () => {
      const nonHashed = prepareSigStructure({ record, signerPubkey });
      const sigNonHashed = signEd25519({ seed, message: nonHashed.sigStructureBytes });
      const hashed = prepareSigStructureHashed({ record, signerPubkey });
      const sigHashed = signEd25519({ seed, message: hashed.sigStructureBytes });
      expect(bytesToHex(sigHashed)).not.toBe(bytesToHex(sigNonHashed));
      expect(bytesToHex(sigNonHashed)).toBe(vector.expected_signature_hex);
    });

    it('round-trips through verifyRecordSignatures with verdict=valid', async () => {
      const { sigStructureBytes } = prepareSigStructureHashed({ record, signerPubkey });
      const signature = signEd25519({ seed, message: sigStructureBytes });
      const { sigEntry } = assembleCoseSign1Hashed({ record, signerPubkey, signature });
      const completedRecord: PoeRecord = { ...record, sigs: [sigEntry] };
      const out = await verifyRecordSignatures({
        record: completedRecord,
        input: { txHash: '0'.repeat(64), cardanoNetwork: 'mainnet' },
      });
      expect(out[0]).toMatchObject({
        index: 0,
        verdict: 'valid',
        signer_type: 'in-signature-kid',
        signer_pub: vector.signer_public_key_hex,
      });
    });

    it('negative — "hashed": true with non-hashed signature fails verification', async () => {
      // Attacker: builds COSE_Sign1 with unprotected `"hashed": true` but
      // signs over the NON-hashed Sig_structure. Verifier substitutes
      // `Blake2b-224(to_sign)` in Sig_structure[3] before strict Ed25519 →
      // signature won't match → SIGNATURE_INVALID.
      const nonHashed = prepareSigStructure({ record, signerPubkey });
      const sigNonHashed = signEd25519({ seed, message: nonHashed.sigStructureBytes });
      const protectedHeader: CoseHeader = new Map<number | string, unknown>([
        [1, -8],
        [4, signerPubkey],
      ]);
      const unprotectedHeader: CoseHeader = new Map<number | string, unknown>([['hashed', true]]);
      const tamperedCose = encodeCoseSign1({
        protectedHeader,
        unprotectedHeader,
        payload: null,
        signature: sigNonHashed,
      });
      const tamperedEntry = { cose_sign1: [tamperedCose] } as unknown as SigEntry;
      const out = await verifyRecordSignatures({
        record: { ...record, sigs: [tamperedEntry] } as PoeRecord,
        input: { txHash: '0'.repeat(64), cardanoNetwork: 'mainnet' },
      });
      expect(out[0]?.verdict).toBe('invalid');
      expect(out[0]?.reason).toBe('SIGNATURE_INVALID');
    });

    it('negative — hashed signature with "hashed" flag removed fails verification', async () => {
      // Defender flow: a HASHED-MODE-built signature; attacker strips the
      // unprotected `"hashed": true` flag. Verifier sees no flag → skips
      // hash substitution → verifies over the unhashed Sig_structure →
      // signature mismatch → SIGNATURE_INVALID.
      const hashed = prepareSigStructureHashed({ record, signerPubkey });
      const sigHashed = signEd25519({ seed, message: hashed.sigStructureBytes });
      const protectedHeader: CoseHeader = new Map<number | string, unknown>([
        [1, -8],
        [4, signerPubkey],
      ]);
      const flagStrippedCose = encodeCoseSign1({
        protectedHeader,
        unprotectedHeader: new Map(),
        payload: null,
        signature: sigHashed,
      });
      const strippedEntry = { cose_sign1: [flagStrippedCose] } as unknown as SigEntry;
      const out = await verifyRecordSignatures({
        record: { ...record, sigs: [strippedEntry] } as PoeRecord,
        input: { txHash: '0'.repeat(64), cardanoNetwork: 'mainnet' },
      });
      expect(out[0]?.verdict).toBe('invalid');
      expect(out[0]?.reason).toBe('SIGNATURE_INVALID');
    });
  },
);
