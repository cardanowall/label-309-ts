import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { verifyEd25519 } from './ed25519';

interface Ed25519Zip215Vector {
  name: string;
  public_key_hex: string;
  message_hex: string;
  signature_hex: string;
  expected_valid: boolean;
  rejection_category?: string;
  notes?: string;
}

interface Ed25519Zip215Corpus {
  version: number;
  primitive: string;
  source: string;
  vectors: Ed25519Zip215Vector[];
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
const fixturePath = path.resolve(here, '../../tests/fixtures/sig/ed25519-zip215.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as Ed25519Zip215Corpus;

describe('verifyEd25519 — strict-mode rejection (zip215: false)', () => {
  for (const vector of corpus.vectors) {
    it(`returns ${vector.expected_valid} for ${vector.name}`, () => {
      const result = verifyEd25519({
        publicKey: hexToBytes(vector.public_key_hex),
        message: hexToBytes(vector.message_hex),
        signature: hexToBytes(vector.signature_hex),
      });
      expect(result).toBe(vector.expected_valid);
    });
  }
});

// Shared cross-SDK Ed25519 torsion KAT (C2SP/CCTV ed25519vectors): 914 vectors
// spanning every small-order / torsion-component edge case. `expected_valid` is
// the strict (non-cofactored, RFC 8032 §5.1.7) consensus shared by
// libsodium/PyNaCl and ed25519-dalek `verify_strict`. Our strict verify MUST
// agree with all 914 (43 of which accept), proving it is genuinely
// non-cofactored rather than merely `{ zip215: false }`.
const torsionFixturePath = path.resolve(here, '../../tests/fixtures/sig/ed25519-torsion-cctv.json');
const torsionCorpus = JSON.parse(
  fs.readFileSync(torsionFixturePath, 'utf8'),
) as Ed25519Zip215Corpus;

describe('verifyEd25519 — shared cross-SDK torsion KAT (C2SP/CCTV, strict consensus)', () => {
  it('matches the strict-verification verdict for all 914 vectors', () => {
    expect(torsionCorpus.vectors.length).toBe(914);
    let accepts = 0;
    const mismatches: string[] = [];
    for (const vector of torsionCorpus.vectors) {
      const result = verifyEd25519({
        publicKey: hexToBytes(vector.public_key_hex),
        message: hexToBytes(vector.message_hex),
        signature: hexToBytes(vector.signature_hex),
      });
      if (vector.expected_valid) accepts++;
      if (result !== vector.expected_valid) mismatches.push(vector.name);
    }
    expect(mismatches).toEqual([]);
    // Pin the accept count so a regression that silently accepts everything (or
    // rejects everything) is caught even if the per-vector loop short-circuits.
    expect(accepts).toBe(43);
  });
});
