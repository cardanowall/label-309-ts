// Conformance replay of the cardano-poe-pw-norm-v1 passphrase-normalization
// byte-pin corpus: every positive case must normalize to the pinned UTF-8
// bytes AND derive the pinned 32-byte CEK through Argon2id v19 under the
// corpus's fixed salt/params, proving the embedded Unicode 16.0 tables and
// the Argon2id engine byte-exact end-to-end. Error cases must surface the
// pinned typed rejections.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { argon2idV13 } from '../../src/kdf/argon2id';
import {
  MAX_PASSPHRASE_INPUT_BYTES,
  normalizePassphrase,
} from '../../src/sealed-poe/passphrase-normalize';

interface PassphraseNormalizationVector {
  name: string;
  passphrase: string;
  expected_normalized: string;
  expected_normalized_utf8_hex: string;
  expected_cek_hex: string;
}

interface PassphraseNormalizationErrorVector {
  name: string;
  passphrase: string;
  expected_error_code: string;
}

interface PassphraseNormalizationCorpus {
  version: number;
  primitive: string;
  unicode_version: string;
  max_passphrase_input_bytes: number;
  kdf: {
    alg: string;
    argon2_version: number;
    salt_hex: string;
    params: { m: number; t: number; p: number };
    out_bytes: number;
  };
  vectors: PassphraseNormalizationVector[];
  error_vectors: PassphraseNormalizationErrorVector[];
}

function hexToBytes(hex: string): Uint8Array {
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

const UTF8 = new TextEncoder();

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, '../fixtures/kdf/passphrase-normalization.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as PassphraseNormalizationCorpus;

describe('cardano-poe-pw-norm-v1 — normalization + CEK byte-pin corpus', () => {
  it('carries the pinned profile header and the full case set', () => {
    expect(corpus.primitive).toBe('cardano-poe-pw-norm-v1');
    expect(corpus.unicode_version).toBe('16.0.0');
    expect(corpus.max_passphrase_input_bytes).toBe(MAX_PASSPHRASE_INPUT_BYTES);
    expect(corpus.kdf.alg).toBe('argon2id');
    expect(corpus.kdf.argon2_version).toBe(19);
    expect(corpus.kdf.out_bytes).toBe(32);
    expect(corpus.vectors).toHaveLength(17);
    expect(corpus.error_vectors).toHaveLength(8);
  });

  for (const vector of corpus.vectors) {
    it(`normalizes and derives the pinned CEK for ${vector.name}`, async () => {
      const normalized = normalizePassphrase(vector.passphrase);
      expect(bytesToHex(normalized)).toBe(vector.expected_normalized_utf8_hex);
      // The corpus's readable string form and its hex form pin the same bytes.
      expect(normalized).toEqual(UTF8.encode(vector.expected_normalized));

      const cek = await argon2idV13({
        password: normalized,
        salt: hexToBytes(corpus.kdf.salt_hex),
        memSizeKB: corpus.kdf.params.m,
        iterations: corpus.kdf.params.t,
        parallelism: corpus.kdf.params.p,
        outBytes: corpus.kdf.out_bytes,
      });
      expect(bytesToHex(cek)).toBe(vector.expected_cek_hex);
    });
  }

  for (const vector of corpus.error_vectors) {
    it(`rejects ${vector.name} with ${vector.expected_error_code}`, () => {
      expect(() => normalizePassphrase(vector.passphrase)).toThrowError(
        expect.objectContaining({ code: vector.expected_error_code }),
      );
    });
  }
});
