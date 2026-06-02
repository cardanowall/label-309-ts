import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { sha256 } from './sha-256';

interface KatVector {
  name: string;
  input_hex: string;
  expected_hex: string;
}

interface KatCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: KatVector[];
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
const fixturePath = path.resolve(here, '../../tests/fixtures/hash/sha256-kat.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as KatCorpus;

describe('sha256 — KAT vectors', () => {
  for (const vector of corpus.vectors) {
    it(`matches expected output for ${vector.name}`, () => {
      const input = hexToBytes(vector.input_hex);
      const actual = bytesToHex(sha256(input));
      expect(actual).toBe(vector.expected_hex);
    });
  }
});
