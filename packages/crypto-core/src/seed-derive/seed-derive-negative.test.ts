import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { deriveEd25519KeypairFromSeed, deriveX25519KeypairFromSeed } from './derive';
import { SeedDeriveError } from './errors';

interface NegativeVector {
  name: string;
  seed_hex: string;
  expected_error_code: 'INVALID_SEED_LENGTH';
}

interface NegativeCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: NegativeVector[];
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
const fixturePath = path.resolve(
  here,
  '../../tests/fixtures/seed-derive/seed-derive-negative.json',
);
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as NegativeCorpus;

describe('seed-derive — INVALID_SEED_LENGTH rejection', () => {
  for (const vector of corpus.vectors) {
    it(`rejects ed25519 derivation for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      try {
        deriveEd25519KeypairFromSeed(seed);
        expect.fail('expected throw');
      } catch (e) {
        expect(e).toBeInstanceOf(SeedDeriveError);
        if (e instanceof SeedDeriveError) {
          expect(e.code).toBe(vector.expected_error_code);
        }
      }
    });

    it(`rejects x25519 derivation for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      try {
        deriveX25519KeypairFromSeed(seed);
        expect.fail('expected throw');
      } catch (e) {
        expect(e).toBeInstanceOf(SeedDeriveError);
        if (e instanceof SeedDeriveError) {
          expect(e.code).toBe(vector.expected_error_code);
        }
      }
    });
  }
});
