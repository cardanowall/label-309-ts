// Off-host signing helper known-answer test — byte-pins each shared COSE_Sign1
// build vector through the off-host helper surface: prefix-prefixed `to_sign`,
// canonical Sig_structure, canonical 38-byte protected header, KAT signature,
// COSE_Sign1, and chunked `sigs[]` entry CBOR (last guarded — the baseline
// vector omits it).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  encodeCanonicalCbor,
  decodeCanonicalCbor,
  type CanonicalCborValue,
} from '@cardanowall/crypto-core/cbor';
import { signEd25519 } from '@cardanowall/crypto-core/sig';
import type { PoeRecord } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { assembleCoseSign1, buildToSign, prepareSigStructure } from './off-host-sign';

interface CardanoPoeBuildVector {
  name: string;
  source: string;
  signer_secret_key_hex: string;
  signer_public_key_hex: string;
  record_body_cbor_hex: string;
  expected_sig_structure_hex: string;
  expected_signature_hex: string;
  expected_cose_sign1_hex: string;
  expected_cose_sign1_chunks_hex?: string[];
  expected_sigs_entry_cbor_hex?: string;
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
const fixturePath = path.resolve(here, '../../../crypto-core/tests/fixtures/cose/sign1-build.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as Sign1BuildCorpus;

const DOMAIN_PREFIX_HEX = '63617264616e6f2d706f652d7265636f72642d7369672d7631';

describe.each(corpus.cardano_poe_vectors)(
  'off-host-sign KAT — $name',
  (vector: CardanoPoeBuildVector) => {
    // Reconstruct PoeRecord from the canonical-CBOR body. The body is
    // record-minus-sigs; the helpers re-encode via encodeRecordBodyForSigning
    // which strips sigs again, so adding empty sigs would not affect output.
    const record = decodeCanonicalCbor(hexToBytes(vector.record_body_cbor_hex)) as PoeRecord;
    const signerPubkey = hexToBytes(vector.signer_public_key_hex);
    const signerSeed = hexToBytes(vector.signer_secret_key_hex);

    it('buildToSign emits prefix || record_body_cbor', () => {
      const toSign = buildToSign(record);
      expect(bytesToHex(toSign)).toBe(DOMAIN_PREFIX_HEX + vector.record_body_cbor_hex);
      // 25-byte prefix invariant (independent byte-by-byte check).
      expect(bytesToHex(toSign.subarray(0, 25))).toBe(DOMAIN_PREFIX_HEX);
    });

    it('prepareSigStructure returns byte-pinned Sig_structure', () => {
      const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
      expect(bytesToHex(sigStructureBytes)).toBe(vector.expected_sig_structure_hex);
    });

    it('prepareSigStructure returns the canonical 38-byte protected header', () => {
      const { protectedHeaderBytes } = prepareSigStructure({ record, signerPubkey });
      const expectedProtectedHex = `a2012704582 0${vector.signer_public_key_hex}`.replace(
        /\s+/g,
        '',
      );
      expect(bytesToHex(protectedHeaderBytes)).toBe(expectedProtectedHex);
      expect(protectedHeaderBytes.length).toBe(38);
    });

    it('Ed25519-signing the Sig_structure matches the KAT signature', () => {
      const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
      const sig = signEd25519({ seed: signerSeed, message: sigStructureBytes });
      expect(bytesToHex(sig)).toBe(vector.expected_signature_hex);
    });

    it('assembleCoseSign1 emits byte-pinned COSE_Sign1', () => {
      const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
      const sig = signEd25519({ seed: signerSeed, message: sigStructureBytes });
      const { coseSign1Bytes } = assembleCoseSign1({
        record,
        signerPubkey,
        signature: sig,
      });
      expect(bytesToHex(coseSign1Bytes)).toBe(vector.expected_cose_sign1_hex);
    });

    it('assembleCoseSign1 emits the byte-pinned single-bstr sigs[] entry', () => {
      const { sigStructureBytes } = prepareSigStructure({ record, signerPubkey });
      const sig = signEd25519({ seed: signerSeed, message: sigStructureBytes });
      const { sigEntry } = assembleCoseSign1({ record, signerPubkey, signature: sig });
      expect(bytesToHex(sigEntry.cose_sign1)).toBe(vector.expected_cose_sign1_hex);
      if (vector.expected_sigs_entry_cbor_hex !== undefined) {
        const sigEntryCbor = encodeCanonicalCbor(sigEntry as unknown as CanonicalCborValue);
        expect(bytesToHex(sigEntryCbor)).toBe(vector.expected_sigs_entry_cbor_hex);
      }
    });
  },
);
