// Conformance replay — validator acceptance vectors.
//
// Replays the shared validator-positive corpus: byte-pinned record bodies
// that a conformant structural validator MUST accept, together with the
// exact info-severity codes (if any) it tags on them. The corpus is the
// cross-language oracle — the TypeScript, Python, and Rust validators replay
// the same bytes and must agree verdict-for-verdict.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { validatePoeRecord } from './validator';

interface PositiveVector {
  readonly name: string;
  readonly cbor_hex: string;
  readonly expected_error_codes: ReadonlyArray<string>;
  readonly expected_info_codes?: ReadonlyArray<string>;
  readonly note?: string;
}

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../crypto-core/tests/fixtures',
);

const corpus = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'validator/validator-positive.json'), 'utf8'),
) as { vectors: PositiveVector[] };

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('validator-positive corpus', () => {
  for (const vector of corpus.vectors) {
    it(`${vector.name} is accepted`, () => {
      const result = validatePoeRecord(hexToBytes(vector.cbor_hex));
      expect(vector.expected_error_codes).toEqual([]);
      expect(result.valid).toBe(true);
      if (!result.valid) return;
      const expectedInfo = [...(vector.expected_info_codes ?? [])].sort();
      const actualInfo = [...new Set((result.info ?? []).map((issue) => issue.code))].sort();
      expect(actualInfo).toEqual(expectedInfo);
      expect(result.warnings ?? []).toEqual([]);
    });
  }
});
