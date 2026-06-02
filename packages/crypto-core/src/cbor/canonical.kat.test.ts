import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { decodeCanonicalCbor, encodeCanonicalCbor, type CanonicalCborValue } from './canonical';

interface CanonicalCborKatVector {
  name: string;
  input_json: string;
  input_value_spec?: { type: 'bytes'; hex: string } | { type: 'bigint'; decimal: string };
  expected_cbor_hex: string;
}

interface CanonicalCborKatCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: CanonicalCborKatVector[];
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

function reifyValue(vector: CanonicalCborKatVector): CanonicalCborValue {
  if (vector.input_value_spec) {
    if (vector.input_value_spec.type === 'bytes') {
      return hexToBytes(vector.input_value_spec.hex);
    }
    if (vector.input_value_spec.type === 'bigint') {
      return BigInt(vector.input_value_spec.decimal);
    }
  }
  return JSON.parse(vector.input_json) as CanonicalCborValue;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const katFixturePath = path.resolve(
  here,
  '../../tests/fixtures/cbor/canonical-encode-rfc8949-kat.json',
);
const roundtripFixturePath = path.resolve(
  here,
  '../../tests/fixtures/cbor/canonical-encode-roundtrip.json',
);
const katCorpus = JSON.parse(fs.readFileSync(katFixturePath, 'utf8')) as CanonicalCborKatCorpus;
const roundtripCorpus = JSON.parse(
  fs.readFileSync(roundtripFixturePath, 'utf8'),
) as CanonicalCborKatCorpus;

describe('encodeCanonicalCbor — KAT vectors (RFC 8949 §A)', () => {
  for (const vector of katCorpus.vectors) {
    it(`encodes canonically for ${vector.name}`, () => {
      const value = reifyValue(vector);
      const encoded = encodeCanonicalCbor(value);
      expect(bytesToHex(encoded)).toBe(vector.expected_cbor_hex);
    });
  }
});

describe('encodeCanonicalCbor — roundtrip parity vectors (project-internal)', () => {
  for (const vector of roundtripCorpus.vectors) {
    it(`encodes canonically + roundtrips for ${vector.name}`, () => {
      const value = reifyValue(vector);
      const encoded = encodeCanonicalCbor(value);
      expect(bytesToHex(encoded)).toBe(vector.expected_cbor_hex);
      const recovered = decodeCanonicalCbor(hexToBytes(vector.expected_cbor_hex));
      expect(bytesToHex(encodeCanonicalCbor(recovered as CanonicalCborValue))).toBe(
        vector.expected_cbor_hex,
      );
    });
  }
});
