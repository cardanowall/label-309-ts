// Conformance replay — validator rejection vectors.
//
// Replays the shared validator-negative and validator-bounds-negative
// corpora: byte-pinned record bodies, each with the exact set of
// error-severity codes a conformant structural validator emits (an empty
// expected set pins an accepted record). The corpora are the cross-language
// oracle — the TypeScript, Python, and Rust validators replay the same bytes
// and must agree code-for-code.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { validatePoeRecord, type ValidatorOptions } from './validator';

interface NegativeVector {
  readonly name: string;
  readonly cbor_hex: string;
  readonly expected_error_codes: ReadonlyArray<string>;
  readonly validator_options?: FixtureValidatorOptions;
  readonly note?: string;
}

interface FixtureValidatorOptions {
  readonly supportedCriticalExtensions?: ReadonlyArray<string>;
  readonly maxSlots?: number;
  readonly maxEncEnvelopeBytes?: number;
  readonly passphraseParamsCeiling?: { m: number; t: number; p: number } | null;
}

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../crypto-core/tests/fixtures',
);

function loadVectors(file: string): NegativeVector[] {
  const corpus = JSON.parse(fs.readFileSync(path.join(fixturesDir, file), 'utf8')) as {
    vectors: NegativeVector[];
  };
  return corpus.vectors;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toValidatorOptions(fixture?: FixtureValidatorOptions): ValidatorOptions | undefined {
  if (fixture === undefined) return undefined;
  const options: {
    supportedCriticalExtensions?: ReadonlySet<string>;
    maxSlots?: number;
    maxEncEnvelopeBytes?: number;
    passphraseParamsCeiling?: { m: number; t: number; p: number } | null;
  } = {};
  if (fixture.supportedCriticalExtensions !== undefined) {
    options.supportedCriticalExtensions = new Set(fixture.supportedCriticalExtensions);
  }
  if (fixture.maxSlots !== undefined) options.maxSlots = fixture.maxSlots;
  if (fixture.maxEncEnvelopeBytes !== undefined) {
    options.maxEncEnvelopeBytes = fixture.maxEncEnvelopeBytes;
  }
  if (fixture.passphraseParamsCeiling !== undefined) {
    options.passphraseParamsCeiling = fixture.passphraseParamsCeiling;
  }
  return options;
}

function distinctErrorCodes(bytes: Uint8Array, options?: ValidatorOptions): string[] {
  const result = validatePoeRecord(bytes, options);
  if (result.valid) return [];
  const codes = result.issues
    .filter((issue) => issue.severity === 'error')
    .map((issue) => issue.code);
  return [...new Set(codes)].sort();
}

function replay(file: string): void {
  for (const vector of loadVectors(file)) {
    const expected = [...vector.expected_error_codes].sort();
    if (expected.length === 0) {
      it(`${vector.name} is accepted`, () => {
        const result = validatePoeRecord(
          hexToBytes(vector.cbor_hex),
          toValidatorOptions(vector.validator_options),
        );
        expect(result.valid).toBe(true);
      });
      continue;
    }
    it(`${vector.name} → ${expected.join(' + ')}`, () => {
      const actual = distinctErrorCodes(
        hexToBytes(vector.cbor_hex),
        toValidatorOptions(vector.validator_options),
      );
      expect(actual).toEqual(expected);
    });
  }
}

describe('validator-negative corpus', () => {
  replay('validator/validator-negative.json');
});

describe('validator-bounds-negative corpus (resource bounds)', () => {
  replay('validator/validator-bounds-negative.json');
});
