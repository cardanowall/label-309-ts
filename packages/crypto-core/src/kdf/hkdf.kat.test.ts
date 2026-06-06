import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { hkdfSha256 } from './hkdf';

interface HkdfKatVector {
  name: string;
  ikm_hex: string;
  salt_hex: string;
  info_hex: string;
  length: number;
  expected_hex: string;
}

interface HkdfKatCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: HkdfKatVector[];
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
const fixturesDir = path.resolve(here, '../../tests/fixtures/kdf');
const corpus = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'hkdf-sha256-kat.json'), 'utf8'),
) as HkdfKatCorpus;

describe('hkdfSha256 — KAT vectors', () => {
  for (const vector of corpus.vectors) {
    it(`matches expected output for ${vector.name}`, () => {
      const actual = bytesToHex(
        hkdfSha256({
          ikm: hexToBytes(vector.ikm_hex),
          salt: hexToBytes(vector.salt_hex),
          info: hexToBytes(vector.info_hex),
          length: vector.length,
        }),
      );
      expect(actual).toBe(vector.expected_hex);
    });
  }
});

// Zero-length HKDF salt (RFC 5869 §2.2 absent-salt extract). When the salt is
// the empty octet string, HKDF-Extract substitutes HashLen zero bytes. This is
// the exact shape the sealed-PoE slots_mac HKDF uses (salt="" with a non-empty
// info label), so the construction's absent-salt behaviour is pinned by a
// byte-exact vector rather than left to the library.
const emptySaltCorpus = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'hkdf-sha256-empty-salt-kat.json'), 'utf8'),
) as HkdfKatCorpus;

describe('hkdfSha256 — zero-length salt KAT', () => {
  for (const vector of emptySaltCorpus.vectors) {
    it(`derives the pinned bytes for ${vector.name} (salt="" extract)`, () => {
      expect(vector.salt_hex).toBe('');
      const actual = bytesToHex(
        hkdfSha256({
          ikm: hexToBytes(vector.ikm_hex),
          salt: hexToBytes(vector.salt_hex),
          info: hexToBytes(vector.info_hex),
          length: vector.length,
        }),
      );
      expect(actual).toBe(vector.expected_hex);
    });
  }
});
