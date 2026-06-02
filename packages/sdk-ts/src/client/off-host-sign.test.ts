// Off-host signing helper unit + round-trip tests.
//
// 1. Splice the helper's `sigs[i]` entry into the record → verify round-trips
//    through `verifyRecordSignatures` with `verdict: 'valid'` and
//    `signerType: 'in-signature-kid'` for every vector.
// 2. For the same record + seed, the off-host helper's chunk array
//    byte-matches an inline reconstruction of the in-process
//    `coseSign1Cip309Build` chunk array (the reconstruction is inlined here so
//    the SDK package tree stays free of any application-layer dependency).
// 3. Input-validation boundary raises `OffHostSignError` with `code`
//    discriminator for 31-byte pubkey / 63-byte signature.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  encodeCanonicalCbor,
  decodeCanonicalCbor,
  type CanonicalCborValue,
} from '@cardanowall/crypto-core/cbor';
import { coseSign1Cip309Build } from '@cardanowall/crypto-core/cose';
import { signEd25519, getPublicKeyEd25519 } from '@cardanowall/crypto-core/sig';
import { chunkBytes, encodeRecordBodyForSigning, type PoeRecord } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { verifyRecordSignatures } from '../verifier/signatures';

import { OffHostSignError, assembleCoseSign1, prepareSigStructure } from './off-host-sign';

interface CardanoPoeBuildVector {
  name: string;
  signer_secret_key_hex: string;
  signer_public_key_hex: string;
  record_body_cbor_hex: string;
  expected_sig_structure_hex: string;
  expected_signature_hex: string;
  expected_cose_sign1_hex: string;
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

describe.each(corpus.cardano_poe_vectors)(
  'off-host-sign — round-trip $name',
  (vector: CardanoPoeBuildVector) => {
    const record = decodeCanonicalCbor(hexToBytes(vector.record_body_cbor_hex)) as PoeRecord;
    const signerPubkey = hexToBytes(vector.signer_public_key_hex);
    const seed = hexToBytes(vector.signer_secret_key_hex);

    it('off-host-built sigs[] round-trips through verifyRecordSignatures as valid', async () => {
      const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
      const signature = signEd25519({ seed, message: sigStructureBytes });
      const { sigEntry } = assembleCoseSign1({ record, signerPubkey, signature });
      const completedRecord: PoeRecord = { ...record, sigs: [sigEntry] };
      const out = await verifyRecordSignatures({
        record: completedRecord,
        input: { txHash: '0'.repeat(64), cardanoNetwork: 'mainnet' },
      });
      expect(out).toHaveLength(1);
      expect(out[0]).toMatchObject({
        index: 0,
        verdict: 'valid',
        signer_type: 'in-signature-kid',
        signer_pub: vector.signer_public_key_hex,
      });
      expect(out[0]?.reason).toBeUndefined();
    });

    it('chunk array byte-matches the in-process signer', () => {
      // Inline reconstruction of the in-process path (no application-layer
      // import; preserves package-tree purity). The signer feeds
      // protectedHeader = {1:-8, 4:pub} + unprotectedHeader = {} + record body
      // through `coseSign1Cip309Build` with the seed; the off-host helper
      // computes the SAME inputs and feeds them through `encodeCoseSign1` with
      // an externally-produced signature. Ed25519 is deterministic per
      // RFC 8032 §5.1.6, canonical-CBOR is byte-deterministic per RFC 8949
      // §4.2.1, and `chunkBytes` is a pure 64-byte slicer — so the chunk
      // arrays MUST byte-match.
      const pub = getPublicKeyEd25519({ seed });
      expect(bytesToHex(pub)).toBe(vector.signer_public_key_hex);
      const recordBodyCbor = encodeRecordBodyForSigning(record);
      const coseInProc = coseSign1Cip309Build({
        protectedHeader: new Map<number | string, unknown>([
          [1, -8],
          [4, pub],
        ]),
        unprotectedHeader: new Map(),
        recordBodyCbor,
        signerSecretKey: seed,
      });
      const chunksInProc = chunkBytes(coseInProc);

      const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
      const signature = signEd25519({ seed, message: sigStructureBytes });
      const { sigEntry } = assembleCoseSign1({ record, signerPubkey, signature });

      const inProcCborHex = chunksInProc.map((c) => bytesToHex(c));
      const offHostCborHex = sigEntry.cose_sign1.map((c) => bytesToHex(c));
      expect(offHostCborHex).toEqual(inProcCborHex);

      // Encoded sig entries are byte-identical too.
      const offHostEntryCbor = encodeCanonicalCbor(sigEntry as unknown as CanonicalCborValue);
      const inProcEntryCbor = encodeCanonicalCbor({
        cose_sign1: chunksInProc,
      } as unknown as CanonicalCborValue);
      expect(bytesToHex(offHostEntryCbor)).toBe(bytesToHex(inProcEntryCbor));
    });
  },
);

describe('off-host-sign — input validation', () => {
  const vector = corpus.cardano_poe_vectors[0]!;
  const record = decodeCanonicalCbor(hexToBytes(vector.record_body_cbor_hex)) as PoeRecord;
  const signerPubkey32 = hexToBytes(vector.signer_public_key_hex);
  const validSig64 = new Uint8Array(64);

  it('prepareSigStructure rejects 31-byte pubkey with INVALID_PUBKEY_LENGTH', () => {
    expect(() => prepareSigStructure({ record, signerPubkey: new Uint8Array(31) })).toThrowError(
      expect.objectContaining({ name: 'OffHostSignError', code: 'INVALID_PUBKEY_LENGTH' }),
    );
  });

  it('assembleCoseSign1 rejects 31-byte pubkey with INVALID_PUBKEY_LENGTH', () => {
    expect(() =>
      assembleCoseSign1({
        record,
        signerPubkey: new Uint8Array(31),
        signature: validSig64,
      }),
    ).toThrowError(
      expect.objectContaining({ name: 'OffHostSignError', code: 'INVALID_PUBKEY_LENGTH' }),
    );
  });

  it('assembleCoseSign1 rejects 63-byte signature with INVALID_SIGNATURE_LENGTH', () => {
    expect(() =>
      assembleCoseSign1({
        record,
        signerPubkey: signerPubkey32,
        signature: new Uint8Array(63),
      }),
    ).toThrowError(
      expect.objectContaining({ name: 'OffHostSignError', code: 'INVALID_SIGNATURE_LENGTH' }),
    );
  });

  it('OffHostSignError is instanceof Error with code attribute', () => {
    try {
      prepareSigStructure({ record, signerPubkey: new Uint8Array(31) });
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(OffHostSignError);
      expect(e).toBeInstanceOf(Error);
      expect((e as OffHostSignError).code).toBe('INVALID_PUBKEY_LENGTH');
      expect((e as OffHostSignError).name).toBe('OffHostSignError');
    }
  });
});
