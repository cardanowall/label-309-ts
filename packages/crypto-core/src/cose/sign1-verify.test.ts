import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { coseSign1Label309Verify } from './sign1';

interface CardanoPoeVerifyVector {
  name: string;
  source?: string;
  message_hex: string;
  detached_record_body_cbor_hex: string;
  expected_signer_key_hex?: string;
  expected_result: {
    ok: boolean;
    signer_key_hex?: string;
    alg?: number;
    error_code?: string;
  };
}

interface VerifyCorpus {
  version: number;
  primitive: string;
  source: string;
  cardano_poe_vectors: CardanoPoeVerifyVector[];
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
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, '../../tests/fixtures/cose/sign1-verify.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as VerifyCorpus;

describe('cose-sign1 — Label 309 verify vectors', () => {
  for (const vector of corpus.cardano_poe_vectors) {
    it(`verifies ${vector.name}`, () => {
      const result = coseSign1Label309Verify({
        message: hexToBytes(vector.message_hex),
        detachedRecordBodyCbor: hexToBytes(vector.detached_record_body_cbor_hex),
        ...(vector.expected_signer_key_hex !== undefined
          ? { expectedSignerKey: hexToBytes(vector.expected_signer_key_hex) }
          : {}),
      });
      if (vector.expected_result.ok) {
        expect(result.ok).toBe(true);
        if (result.ok && vector.expected_result.signer_key_hex !== undefined) {
          expect(bytesToHex(result.signerKey)).toBe(vector.expected_result.signer_key_hex);
        }
        if (result.ok && vector.expected_result.alg !== undefined) {
          expect(result.alg).toBe(vector.expected_result.alg);
        }
      } else {
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe(vector.expected_result.error_code);
        }
      }
    });
  }
});
