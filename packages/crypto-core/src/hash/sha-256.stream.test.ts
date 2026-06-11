import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { sha256, sha256Stream } from './sha-256';

interface EquivalenceVector {
  name: string;
  input_hex: string;
  expected_sha256_hex: string;
}

interface EquivalenceCorpus {
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

describe('sha256Stream — streaming parity with one-shot sha256', () => {
  for (const vector of corpus.vectors) {
    it(`streamed digest equals one-shot for ${vector.name}`, async () => {
      const input = hexToBytes(vector.input_hex);
      const streamed = await sha256Stream(chunkifyAsync(input, 64));
      expect(bytesToHex(streamed)).toBe(vector.expected_sha256_hex);
      // The streaming path is byte-identical to feeding the whole input at once.
      expect(bytesToHex(streamed)).toBe(bytesToHex(sha256(input)));
    });
  }

  it('handles an empty source', async () => {
    const empty = (async function* (): AsyncIterable<Uint8Array> {})();
    const streamed = await sha256Stream(empty);
    expect(bytesToHex(streamed)).toBe(bytesToHex(sha256(new Uint8Array(0))));
  });
});
