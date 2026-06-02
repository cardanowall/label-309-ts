import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  deriveEd25519KeypairFromSeed,
  deriveMlKem768X25519KeypairFromSeed,
  deriveX25519KeypairFromSeed,
} from './derive';

interface SeedDeriveVector {
  name: string;
  seed_hex: string;
  expected_ed25519_secret_hex: string;
  expected_ed25519_public_hex: string;
  expected_x25519_secret_hex: string;
  expected_x25519_public_hex: string;
  expected_mlkem768x25519_secret_seed_hex: string;
  expected_mlkem768x25519_public_key_hex: string;
}

interface SeedDeriveCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: SeedDeriveVector[];
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

function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) throw new Error('hamming length mismatch');
  let bits = 0;
  for (let i = 0; i < a.length; i++) {
    let x = (a[i] as number) ^ (b[i] as number);
    while (x !== 0) {
      bits += x & 1;
      x >>>= 1;
    }
  }
  return bits;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/seed-derive');

const seedFromZero = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'seed-from-zero.json'), 'utf8'),
) as SeedDeriveCorpus;
const seedFromFF = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'seed-from-ff.json'), 'utf8'),
) as SeedDeriveCorpus;
const seedFromDeadbeef = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'seed-from-deadbeef.json'), 'utf8'),
) as SeedDeriveCorpus;

const seedDeriveCorpora: SeedDeriveCorpus[] = [seedFromZero, seedFromFF, seedFromDeadbeef];

describe('seed-derive — known-answer vectors', () => {
  for (const corpus of seedDeriveCorpora) {
    for (const vector of corpus.vectors) {
      it(`derives Ed25519 + X25519 + X-Wing from ${vector.name}`, () => {
        const seed = hexToBytes(vector.seed_hex);

        const ed25519 = deriveEd25519KeypairFromSeed(seed);
        expect(bytesToHex(ed25519.secretKey)).toBe(vector.expected_ed25519_secret_hex);
        expect(bytesToHex(ed25519.publicKey)).toBe(vector.expected_ed25519_public_hex);

        const x25519 = deriveX25519KeypairFromSeed(seed);
        expect(bytesToHex(x25519.secretKey)).toBe(vector.expected_x25519_secret_hex);
        expect(bytesToHex(x25519.publicKey)).toBe(vector.expected_x25519_public_hex);

        const mlkem = deriveMlKem768X25519KeypairFromSeed(seed);
        expect(bytesToHex(mlkem.secretSeed)).toBe(vector.expected_mlkem768x25519_secret_seed_hex);
        expect(bytesToHex(mlkem.publicKey)).toBe(vector.expected_mlkem768x25519_public_key_hex);
      });
    }
  }
});

describe('seed-derive — avalanche property (single bit-flip propagates to ~50% bits)', () => {
  for (const corpus of seedDeriveCorpora) {
    for (const vector of corpus.vectors) {
      it(`exhibits avalanche on bit-flip of byte 0 for ${vector.name}`, () => {
        const seed = hexToBytes(vector.seed_hex);
        const seedFlipped = new Uint8Array(seed);
        seedFlipped[0] = (seedFlipped[0] as number) ^ 0x01;

        const ed25519A = deriveEd25519KeypairFromSeed(seed);
        const ed25519B = deriveEd25519KeypairFromSeed(seedFlipped);
        const x25519A = deriveX25519KeypairFromSeed(seed);
        const x25519B = deriveX25519KeypairFromSeed(seedFlipped);

        const pairs: Array<[Uint8Array, Uint8Array]> = [
          [ed25519A.secretKey, ed25519B.secretKey],
          [ed25519A.publicKey, ed25519B.publicKey],
          [x25519A.secretKey, x25519B.secretKey],
          [x25519A.publicKey, x25519B.publicKey],
        ];

        for (const [a, b] of pairs) {
          const distance = hammingDistance(a, b);
          expect(distance).toBeGreaterThanOrEqual(96);
          expect(distance).toBeLessThanOrEqual(160);
        }
      });
    }
  }
});
