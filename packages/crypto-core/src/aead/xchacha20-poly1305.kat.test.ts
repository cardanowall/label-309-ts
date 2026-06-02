import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { xchacha20Poly1305Decrypt, xchacha20Poly1305Encrypt } from './xchacha20-poly1305';

interface XChaCha20Poly1305KatVector {
  name: string;
  key_hex: string;
  nonce_hex: string;
  aad_hex: string;
  plaintext_hex: string;
  expected_ciphertext_with_tag_hex: string;
}

interface XChaCha20Poly1305KatCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: XChaCha20Poly1305KatVector[];
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
const katFixturePath = path.resolve(
  here,
  '../../tests/fixtures/aead/xchacha20-poly1305-draft-irtf-cfrg-xchacha-03-kat.json',
);
const roundtripFixturePath = path.resolve(
  here,
  '../../tests/fixtures/aead/xchacha20-poly1305-roundtrip.json',
);
const katCorpus = JSON.parse(fs.readFileSync(katFixturePath, 'utf8')) as XChaCha20Poly1305KatCorpus;
const roundtripCorpus = JSON.parse(
  fs.readFileSync(roundtripFixturePath, 'utf8'),
) as XChaCha20Poly1305KatCorpus;

describe('xchacha20Poly1305 — KAT vectors (draft-irtf-cfrg-xchacha-03 Appendix A.3)', () => {
  for (const vector of katCorpus.vectors) {
    it(`encrypts + decrypts byte-identically for ${vector.name}`, () => {
      const key = hexToBytes(vector.key_hex);
      const nonce = hexToBytes(vector.nonce_hex);
      const aad = hexToBytes(vector.aad_hex);
      const plaintext = hexToBytes(vector.plaintext_hex);
      const expected = hexToBytes(vector.expected_ciphertext_with_tag_hex);

      const ct = xchacha20Poly1305Encrypt({ key, nonce, aad, plaintext });
      expect(bytesToHex(ct)).toBe(vector.expected_ciphertext_with_tag_hex);

      const recovered = xchacha20Poly1305Decrypt({ key, nonce, aad, ciphertext: expected });
      expect(bytesToHex(recovered)).toBe(vector.plaintext_hex);
    });
  }
});

describe('xchacha20Poly1305 — roundtrip parity vectors (project-internal)', () => {
  for (const vector of roundtripCorpus.vectors) {
    it(`encrypts + decrypts byte-identically for ${vector.name}`, () => {
      const key = hexToBytes(vector.key_hex);
      const nonce = hexToBytes(vector.nonce_hex);
      const aad = hexToBytes(vector.aad_hex);
      const plaintext = hexToBytes(vector.plaintext_hex);
      const expected = hexToBytes(vector.expected_ciphertext_with_tag_hex);

      const ct = xchacha20Poly1305Encrypt({ key, nonce, aad, plaintext });
      expect(bytesToHex(ct)).toBe(vector.expected_ciphertext_with_tag_hex);

      const recovered = xchacha20Poly1305Decrypt({ key, nonce, aad, ciphertext: expected });
      expect(bytesToHex(recovered)).toBe(vector.plaintext_hex);
    });
  }
});
