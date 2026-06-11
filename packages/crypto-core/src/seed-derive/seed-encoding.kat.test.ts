// Byte-exact known-answer test for the identity-seed codec, driven by the
// shared conformance fixture `seed-derive/seed-encoding-kat.json`.
//
// The fixture pins, for each seed, the exact UPPERCASE display string encode
// must emit and the lowercase form parse must equally accept; hex-tolerance
// inputs (0x prefix, whitespace, uppercase digits) that must parse to the same
// seed; and rejected inputs with the exact error code. The target strings are
// frozen anchors: a codec change that drifts away from the published form is
// caught even if encode and parse still agree with each other.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { encodeIdentitySeed, parseIdentitySeed } from './encoding';
import { SeedEncodingError } from './errors';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

interface EncodeVector {
  name: string;
  seed_hex: string;
  encoded: string;
  encoded_lowercase: string;
}

interface ParseVector {
  name: string;
  input: string;
  expected_seed_hex: string;
}

interface NegativeVector {
  name: string;
  input: string;
  expected_error_code: string;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, '../../tests/fixtures/seed-derive/seed-encoding-kat.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as {
  vectors: EncodeVector[];
  parse_vectors: ParseVector[];
  negative_vectors: NegativeVector[];
};

describe('identity-seed codec — byte-exact KAT', () => {
  for (const vector of corpus.vectors) {
    it(`encodes the pinned seed to the exact uppercase string for ${vector.name}`, () => {
      expect(encodeIdentitySeed(hexToBytes(vector.seed_hex))).toBe(vector.encoded);
    });

    it(`parses both single-case forms back to the seed for ${vector.name}`, () => {
      // The two pinned forms are the same string in the two valid cases.
      expect(vector.encoded_lowercase).toBe(vector.encoded.toLowerCase());
      expect(bytesToHex(parseIdentitySeed(vector.encoded))).toBe(vector.seed_hex);
      expect(bytesToHex(parseIdentitySeed(vector.encoded_lowercase))).toBe(vector.seed_hex);
    });

    it(`parses the raw hex form for ${vector.name}`, () => {
      expect(bytesToHex(parseIdentitySeed(vector.seed_hex))).toBe(vector.seed_hex);
    });
  }

  for (const vector of corpus.parse_vectors) {
    it(`accepts tolerated hex input for ${vector.name}`, () => {
      expect(bytesToHex(parseIdentitySeed(vector.input))).toBe(vector.expected_seed_hex);
    });
  }

  for (const vector of corpus.negative_vectors) {
    it(`rejects ${vector.name} with ${vector.expected_error_code}`, () => {
      let observed: unknown;
      try {
        parseIdentitySeed(vector.input);
      } catch (error) {
        observed = error;
      }
      expect(observed).toBeInstanceOf(SeedEncodingError);
      expect((observed as SeedEncodingError).code).toBe(vector.expected_error_code);
    });
  }

  it('rejects a wrong-length seed on encode with INVALID_SEED_LENGTH', () => {
    for (const length of [0, 31, 33]) {
      let observed: unknown;
      try {
        encodeIdentitySeed(new Uint8Array(length));
      } catch (error) {
        observed = error;
      }
      expect(observed).toBeInstanceOf(SeedEncodingError);
      expect((observed as SeedEncodingError).code).toBe('INVALID_SEED_LENGTH');
    }
  });
});
