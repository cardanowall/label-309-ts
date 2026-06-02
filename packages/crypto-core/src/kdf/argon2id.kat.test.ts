import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { argon2idV13 } from './argon2id';

interface Argon2idKatVector {
  name: string;
  password_hex: string;
  salt_hex: string;
  mem_size_kb: number;
  iterations: number;
  parallelism: number;
  out_bytes: number;
  expected_hex: string;
}

interface Argon2idKatCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: Argon2idKatVector[];
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
const fixturePath = path.resolve(here, '../../tests/fixtures/kdf/argon2id-v13-kat.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as Argon2idKatCorpus;

describe('argon2idV13 — KAT vectors', () => {
  for (const vector of corpus.vectors) {
    it(`matches expected output for ${vector.name}`, async () => {
      const actual = bytesToHex(
        await argon2idV13({
          password: hexToBytes(vector.password_hex),
          salt: hexToBytes(vector.salt_hex),
          memSizeKB: vector.mem_size_kb,
          iterations: vector.iterations,
          parallelism: vector.parallelism,
          outBytes: vector.out_bytes,
        }),
      );
      expect(actual).toBe(vector.expected_hex);
    });
  }
});
