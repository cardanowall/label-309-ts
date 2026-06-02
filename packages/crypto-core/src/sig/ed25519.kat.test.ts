import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { getPublicKeyEd25519, signEd25519, verifyEd25519 } from './ed25519';

interface Ed25519KatVector {
  name: string;
  seed_hex: string;
  message_hex: string;
  expected_public_key_hex: string;
  expected_signature_hex: string;
}

interface Ed25519KatCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: Ed25519KatVector[];
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
const katFixturePath = path.resolve(here, '../../tests/fixtures/sig/ed25519-kat.json');
const roundtripFixturePath = path.resolve(here, '../../tests/fixtures/sig/ed25519-roundtrip.json');
const katCorpus = JSON.parse(fs.readFileSync(katFixturePath, 'utf8')) as Ed25519KatCorpus;
const roundtripCorpus = JSON.parse(
  fs.readFileSync(roundtripFixturePath, 'utf8'),
) as Ed25519KatCorpus;

describe('ed25519 — KAT vectors (RFC 8032 §7.1)', () => {
  for (const vector of katCorpus.vectors) {
    it(`derives, signs, and verifies for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      const message = hexToBytes(vector.message_hex);

      const pubkey = getPublicKeyEd25519({ seed });
      expect(bytesToHex(pubkey)).toBe(vector.expected_public_key_hex);

      const signature = signEd25519({ seed, message });
      expect(bytesToHex(signature)).toBe(vector.expected_signature_hex);

      const valid = verifyEd25519({
        publicKey: pubkey,
        message,
        signature,
      });
      expect(valid).toBe(true);
    });
  }
});

describe('ed25519 — roundtrip parity vectors (project-internal)', () => {
  for (const vector of roundtripCorpus.vectors) {
    it(`produces byte-identical signature for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      const message = hexToBytes(vector.message_hex);

      const pubkey = getPublicKeyEd25519({ seed });
      expect(bytesToHex(pubkey)).toBe(vector.expected_public_key_hex);

      const signature = signEd25519({ seed, message });
      expect(bytesToHex(signature)).toBe(vector.expected_signature_hex);

      const valid = verifyEd25519({
        publicKey: pubkey,
        message,
        signature,
      });
      expect(valid).toBe(true);
    });
  }
});
