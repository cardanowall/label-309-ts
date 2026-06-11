// Carriage conformance replay: the label-309 whole-body chunk-array transport
// and the three Conway-era auxiliary-data envelope forms, driven by the
// shared conformance fixtures. Chunk-array reassembly is the poe-standard
// transport step; the auxiliary-data unwrapping (type/tag dispatch, no
// key-sniffing) is this package's `unwrapAuxiliaryData`.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { reassembleLabel309Value } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { unwrapAuxiliaryData } from './cbor-walker';

const here = path.dirname(fileURLToPath(import.meta.url));
const carriageDir = path.resolve(here, '../../../crypto-core/tests/fixtures/carriage');

function loadFixture<T>(filename: string): T {
  return JSON.parse(fs.readFileSync(path.join(carriageDir, filename), 'utf8')) as T;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// chunk-array-positive.json — reassembly positives
// ---------------------------------------------------------------------------

interface ChunkArrayPositiveCorpus {
  vectors: Array<{
    name: string;
    label_309_value_cbor_hex: string;
    expected_record_body_hex: string;
  }>;
}

describe('label-309 chunk-array transport — positive reassembly vectors', () => {
  const corpus = loadFixture<ChunkArrayPositiveCorpus>('chunk-array-positive.json');
  for (const v of corpus.vectors) {
    it(v.name, () => {
      const result = reassembleLabel309Value(hexToBytes(v.label_309_value_cbor_hex));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(bytesToHex(result.body)).toBe(v.expected_record_body_hex);
    });
  }
});

// ---------------------------------------------------------------------------
// chunk-array-negative.json — the carriage-error taxonomy
// ---------------------------------------------------------------------------

interface ChunkArrayNegativeCorpus {
  vectors: Array<{
    name: string;
    label_309_value_cbor_hex: string;
    expected_error_code: string;
  }>;
}

describe('label-309 chunk-array transport — carriage-error taxonomy', () => {
  const corpus = loadFixture<ChunkArrayNegativeCorpus>('chunk-array-negative.json');
  for (const v of corpus.vectors) {
    it(v.name, () => {
      const result = reassembleLabel309Value(hexToBytes(v.label_309_value_cbor_hex));
      if (v.name.endsWith('empty-body')) {
        // The transport tolerates an empty concatenation; the pinned code
        // surfaces from the canonical decode of the empty record body.
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(result.body.length).toBe(0);
        expect(v.expected_error_code).toBe('MALFORMED_CBOR');
        return;
      }
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.issue.code).toBe(v.expected_error_code);
    });
  }
});

// ---------------------------------------------------------------------------
// aux-data-envelope-forms.json — type/tag dispatch, no key-sniffing
// ---------------------------------------------------------------------------

interface AuxFormsCorpus {
  vectors: Array<{
    name: string;
    auxiliary_data_cbor_hex: string;
    expected: {
      label_309_value_cbor_hex?: string;
      record_body_hex?: string;
      error_code?: string;
    };
  }>;
}

describe('auxiliary-data envelope forms — unwrap dispatch', () => {
  const corpus = loadFixture<AuxFormsCorpus>('aux-data-envelope-forms.json');
  for (const v of corpus.vectors) {
    it(v.name, () => {
      const auxBytes = hexToBytes(v.auxiliary_data_cbor_hex);
      if (v.expected.error_code === 'MALFORMED_CBOR') {
        expect(() => unwrapAuxiliaryData(auxBytes)).toThrowError(/MALFORMED_CBOR/);
        return;
      }
      const unwrapped = unwrapAuxiliaryData(auxBytes);
      if (v.expected.error_code === 'METADATA_NOT_FOUND') {
        // Well-formed auxiliary data that carries no label-309 entry; the
        // pipeline maps the null to METADATA_NOT_FOUND.
        expect(unwrapped.label309).toBeNull();
        return;
      }
      expect(unwrapped.label309).not.toBeNull();
      expect(bytesToHex(unwrapped.label309!)).toBe(v.expected.label_309_value_cbor_hex);
      const reassembled = reassembleLabel309Value(unwrapped.label309!);
      expect(reassembled.ok).toBe(true);
      if (!reassembled.ok) return;
      expect(bytesToHex(reassembled.body)).toBe(v.expected.record_body_hex);
    });
  }
});
