// Metadata-label-309 chunk-array transport — producer split, reassembly, and
// the carriage-error taxonomy, including replay of the shared carriage
// conformance corpora (chunk-array-positive / chunk-array-negative).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { decodeCanonicalCbor } from '@cardanowall/crypto-core/cbor';
import { describe, expect, it } from 'vitest';

import {
  chunkRecordBody,
  encodeLabel309Value,
  reassembleLabel309Value,
  TRANSPORT_CHUNK_MAX_BYTES,
} from './carriage';
import { validatePoeRecord } from './validator';

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../crypto-core/tests/fixtures',
);

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

interface CarriagePositiveVector {
  readonly name: string;
  readonly label_309_value_cbor_hex: string;
  readonly expected_record_body_hex: string;
}

interface CarriageNegativeVector {
  readonly name: string;
  readonly label_309_value_cbor_hex: string;
  readonly expected_error_code: string;
}

const positives = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'carriage/chunk-array-positive.json'), 'utf8'),
) as { vectors: CarriagePositiveVector[] };

const negatives = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'carriage/chunk-array-negative.json'), 'utf8'),
) as { vectors: CarriageNegativeVector[] };

describe('chunk-array-positive corpus', () => {
  for (const vector of positives.vectors) {
    it(`${vector.name} reassembles to the pinned body`, () => {
      const result = reassembleLabel309Value(hexToBytes(vector.label_309_value_cbor_hex));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(bytesToHex(result.body)).toBe(vector.expected_record_body_hex);
    });
  }
});

describe('chunk-array-negative corpus (carriage-error taxonomy)', () => {
  // The pinned code may surface at either layer: the transport step rejects
  // non-chunk-array shapes and oversized chunks, while a transport array that
  // reassembles to zero bytes fails in the canonical decode of the empty
  // record body. The corpus pins the end-to-end disposition.
  for (const vector of negatives.vectors) {
    it(`${vector.name} → ${vector.expected_error_code}`, () => {
      const reassembly = reassembleLabel309Value(hexToBytes(vector.label_309_value_cbor_hex));
      if (!reassembly.ok) {
        expect(reassembly.issue.code).toBe(vector.expected_error_code);
        expect(reassembly.issue.severity).toBe('error');
        return;
      }
      const result = validatePoeRecord(reassembly.body);
      expect(result.valid).toBe(false);
      if (result.valid) return;
      expect(result.issues.map((issue) => issue.code)).toContain(vector.expected_error_code);
    });
  }
});

describe('chunkRecordBody (producer split)', () => {
  it('emits the minimal split: every chunk except the last exactly 64 bytes', () => {
    const body = new Uint8Array(64 * 3 + 7).fill(0x42);
    const chunks = chunkRecordBody(body);
    expect(chunks.map((c) => c.length)).toEqual([64, 64, 64, 7]);
  });

  it('emits a one-element array for a body of 64 bytes or fewer', () => {
    expect(chunkRecordBody(new Uint8Array(64).fill(1)).map((c) => c.length)).toEqual([64]);
    expect(chunkRecordBody(new Uint8Array(1).fill(1)).map((c) => c.length)).toEqual([1]);
  });

  it('rejects an empty body (the 1*bstr transport grammar cannot carry it)', () => {
    expect(() => chunkRecordBody(new Uint8Array(0))).toThrow(RangeError);
  });

  it('copies the input: mutating the body afterwards does not corrupt chunks', () => {
    const body = new Uint8Array(10).fill(7);
    const [chunk] = chunkRecordBody(body);
    body.fill(0);
    expect(chunk![0]).toBe(7);
  });
});

describe('encodeLabel309Value ↔ reassembleLabel309Value round-trip', () => {
  it('round-trips an arbitrary body through the byte-level transport value', () => {
    const body = new Uint8Array(200);
    for (let i = 0; i < body.length; i++) body[i] = i & 0xff;
    const value = encodeLabel309Value(body);
    // The encoded value is a definite-length CBOR array of <=64-byte bstrs.
    const decoded = decodeCanonicalCbor(value) as Uint8Array[];
    expect(Array.isArray(decoded)).toBe(true);
    for (const chunk of decoded) {
      expect(chunk.length).toBeLessThanOrEqual(TRANSPORT_CHUNK_MAX_BYTES);
    }
    const result = reassembleLabel309Value(value);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(bytesToHex(result.body)).toBe(bytesToHex(body));
  });
});
