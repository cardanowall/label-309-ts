import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { decodeCanonicalCbor } from './canonical';
import { CanonicalCborError } from './errors';

// Map-canonicality: a canonical decoder MUST reject BOTH duplicate map keys
// AND non-canonical (distinct-but-unsorted) key ordering (RFC 8949 §4.2.1).
// cbor2 surfaces both with the same "Duplicate or out of order key" message,
// and the CIP-309 taxonomy folds both into a single MALFORMED_CBOR code (there
// is no separate duplicate-key code). This suite locks in that both vector
// families — including the previously-untested unsorted-distinct case — reject
// as MALFORMED_CBOR.

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

describe('decodeCanonicalCbor — rejects non-canonical maps (duplicate or unsorted keys)', () => {
  const mapVectors = negativeCorpus.vectors.filter(
    (v) =>
      v.expected_error_code === 'MALFORMED_CBOR' &&
      (v.name.startsWith('duplicate-keys') || v.name.startsWith('unsorted-distinct-keys')),
  );
  // At least three duplicate vectors and two unsorted-distinct vectors.
  expect(
    mapVectors.filter((v) => v.name.startsWith('duplicate-keys')).length,
  ).toBeGreaterThanOrEqual(3);
  expect(
    mapVectors.filter((v) => v.name.startsWith('unsorted-distinct-keys')).length,
  ).toBeGreaterThanOrEqual(2);

  for (const vector of mapVectors) {
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
