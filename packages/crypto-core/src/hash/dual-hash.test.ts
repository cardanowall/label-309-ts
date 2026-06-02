import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { dualHash, dualHashStream } from './dual-hash';

interface EquivalenceVector {
  name: string;
  input_hex: string;
  expected_sha256_hex: string;
  expected_blake2b256_hex: string;
}

interface EquivalenceCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: EquivalenceVector[];
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

async function* chunkifyAsync(bytes: Uint8Array, chunkSize: number): AsyncIterable<Uint8Array> {
  for (let off = 0; off < bytes.length; off += chunkSize) {
    yield bytes.slice(off, Math.min(off + chunkSize, bytes.length));
  }
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, '../../tests/fixtures/hash/dual-hash-equivalence.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as EquivalenceCorpus;

describe('dualHash — in-memory parity with fixture corpus', () => {
  for (const vector of corpus.vectors) {
    it(`produces expected digests for ${vector.name}`, () => {
      const input = hexToBytes(vector.input_hex);
      const result = dualHash(input);
      expect(bytesToHex(result.sha256)).toBe(vector.expected_sha256_hex);
      expect(bytesToHex(result.blake2b256)).toBe(vector.expected_blake2b256_hex);
    });
  }
});

describe('dualHashStream — streaming parity with in-memory output', () => {
  for (const vector of corpus.vectors) {
    it(`produces identical digests for ${vector.name} when fed in 64-byte chunks`, async () => {
      const input = hexToBytes(vector.input_hex);
      const streamed = await dualHashStream(chunkifyAsync(input, 64));
      expect(bytesToHex(streamed.sha256)).toBe(vector.expected_sha256_hex);
      expect(bytesToHex(streamed.blake2b256)).toBe(vector.expected_blake2b256_hex);
    });
  }
});
