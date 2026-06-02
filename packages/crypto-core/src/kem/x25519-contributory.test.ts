import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { x25519Ecdh } from './x25519';

interface X25519ValidationVector {
  name: string;
  secret_key_hex: string;
  peer_public_key_hex: string;
  expected_rejection: boolean;
  rejection_category?: string;
  notes?: string;
}

interface X25519ValidationCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: X25519ValidationVector[];
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
const fixturePath = path.resolve(here, '../../tests/fixtures/kem/x25519-validation.json');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as X25519ValidationCorpus;

describe('x25519Ecdh — small-order / all-zero rejection (RFC 7748 §6.1 contributory check)', () => {
  for (const vector of corpus.vectors) {
    it(`throws for ${vector.name}`, () => {
      expect(vector.expected_rejection).toBe(true);
      expect(() =>
        x25519Ecdh({
          secretKey: hexToBytes(vector.secret_key_hex),
          theirPublicKey: hexToBytes(vector.peer_public_key_hex),
        }),
      ).toThrow();
    });
  }
});
