import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { decodeCanonicalCbor } from './canonical';
import { CanonicalCborError } from './errors';

interface NegativeVector {
  name: string;
  cbor_hex: string;
  expected_error_code: 'MALFORMED_CBOR';
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
const negativeFixturePath = path.resolve(
  here,
  '../../tests/fixtures/cbor/canonical-decode-negative.json',
);
const negativeCorpus = JSON.parse(fs.readFileSync(negativeFixturePath, 'utf8')) as NegativeCorpus;

describe('decodeCanonicalCbor — rejects malformed inputs', () => {
  const malformedVectors = negativeCorpus.vectors.filter(
    (v) => v.expected_error_code === 'MALFORMED_CBOR',
  );
  expect(malformedVectors.length).toBeGreaterThanOrEqual(1);
  for (const vector of malformedVectors) {
    it(`rejects ${vector.name} with code MALFORMED_CBOR`, () => {
      const bytes = hexToBytes(vector.cbor_hex);
      try {
        decodeCanonicalCbor(bytes);
        expect.fail('expected throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CanonicalCborError);
        expect((err as CanonicalCborError).code).toBe('MALFORMED_CBOR');
      }
    });
  }
});
