import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { x25519Ecdh, x25519PublicKey } from './x25519';

interface X25519KatVector {
  name: string;
  alice_secret_hex: string;
  expected_alice_public_hex: string;
  bob_secret_hex: string;
  expected_bob_public_hex: string;
  expected_shared_secret_hex: string;
}

interface X25519KatCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: X25519KatVector[];
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
const katFixturePath = path.resolve(here, '../../tests/fixtures/kem/x25519-rfc7748-kat.json');
const roundtripFixturePath = path.resolve(here, '../../tests/fixtures/kem/x25519-roundtrip.json');
const katCorpus = JSON.parse(fs.readFileSync(katFixturePath, 'utf8')) as X25519KatCorpus;
const roundtripCorpus = JSON.parse(
  fs.readFileSync(roundtripFixturePath, 'utf8'),
) as X25519KatCorpus;

describe('x25519 — KAT vectors (RFC 7748 §6.1)', () => {
  for (const vector of katCorpus.vectors) {
    it(`derives + ECDH round-trips byte-identically for ${vector.name}`, () => {
      const aliceSecret = hexToBytes(vector.alice_secret_hex);
      const bobSecret = hexToBytes(vector.bob_secret_hex);

      const alicePublic = x25519PublicKey({ secretKey: aliceSecret });
      expect(bytesToHex(alicePublic)).toBe(vector.expected_alice_public_hex);

      const bobPublic = x25519PublicKey({ secretKey: bobSecret });
      expect(bytesToHex(bobPublic)).toBe(vector.expected_bob_public_hex);

      const sharedFromAlice = x25519Ecdh({
        secretKey: aliceSecret,
        theirPublicKey: bobPublic,
      });
      expect(bytesToHex(sharedFromAlice)).toBe(vector.expected_shared_secret_hex);

      const sharedFromBob = x25519Ecdh({
        secretKey: bobSecret,
        theirPublicKey: alicePublic,
      });
      expect(bytesToHex(sharedFromBob)).toBe(vector.expected_shared_secret_hex);
    });
  }
});

describe('x25519 — roundtrip parity vectors (project-internal)', () => {
  for (const vector of roundtripCorpus.vectors) {
    it(`produces byte-identical shared secret for ${vector.name}`, () => {
      const aliceSecret = hexToBytes(vector.alice_secret_hex);
      const bobSecret = hexToBytes(vector.bob_secret_hex);

      const alicePublic = x25519PublicKey({ secretKey: aliceSecret });
      expect(bytesToHex(alicePublic)).toBe(vector.expected_alice_public_hex);

      const bobPublic = x25519PublicKey({ secretKey: bobSecret });
      expect(bytesToHex(bobPublic)).toBe(vector.expected_bob_public_hex);

      const sharedFromAlice = x25519Ecdh({
        secretKey: aliceSecret,
        theirPublicKey: bobPublic,
      });
      expect(bytesToHex(sharedFromAlice)).toBe(vector.expected_shared_secret_hex);

      const sharedFromBob = x25519Ecdh({
        secretKey: bobSecret,
        theirPublicKey: alicePublic,
      });
      expect(bytesToHex(sharedFromBob)).toBe(vector.expected_shared_secret_hex);
    });
  }
});
