import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { EciesSealedPoeError, type EciesSealedPoeErrorCode } from './errors';
import { eciesSealedPoeWrap, type X25519Slot } from './wrap';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

interface WrapPositiveSlot {
  epk_hex: string;
  wrap_hex: string;
}

interface WrapPositiveVector {
  name: string;
  recipient_publics_hex: string[];
  ephemeral_secrets_hex: string[];
  cek_hex: string;
  nonce_hex: string;
  plaintext_hex: string;
  expected_slots: WrapPositiveSlot[];
  expected_slots_mac_hex: string;
  expected_ciphertext_hex: string;
}

interface WrapPositiveCorpus {
  version: number;
  primitive: string;
  source: string;
  vector: WrapPositiveVector;
}

interface WrapNegativeVector {
  name: string;
  recipient_publics_hex: string[];
  ephemeral_secrets_hex?: string[];
  cek_hex?: string;
  nonce_hex?: string;
  plaintext_hex: string;
  expected_error_code: EciesSealedPoeErrorCode;
}

interface WrapNegativeCorpus {
  version: number;
  primitive: string;
  source: string;
  vectors: WrapNegativeVector[];
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex ${hex.length}`);
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

function loadPositive(filename: string): WrapPositiveCorpus {
  return JSON.parse(
    fs.readFileSync(path.join(fixturesDir, filename), 'utf8'),
  ) as WrapPositiveCorpus;
}

function loadNegative(filename: string): WrapNegativeCorpus {
  return JSON.parse(
    fs.readFileSync(path.join(fixturesDir, filename), 'utf8'),
  ) as WrapNegativeCorpus;
}

function checkPositive(corpus: WrapPositiveCorpus): void {
  const { vector } = corpus;
  const recipientPublicKeys = vector.recipient_publics_hex.map(hexToBytes);
  const ephemeralSecrets = vector.ephemeral_secrets_hex.map(hexToBytes);
  const cek = hexToBytes(vector.cek_hex);
  const nonce = hexToBytes(vector.nonce_hex);
  const plaintext = hexToBytes(vector.plaintext_hex);

  const out = eciesSealedPoeWrap({
    plaintext,
    recipientPublicKeys,
    cek,
    nonce,
    ephemeralSecrets,
    skipShuffle: true,
  });

  expect(out.envelope.scheme).toBe(1);
  expect(out.envelope.aead).toBe('xchacha20-poly1305');
  expect(out.envelope.kem).toBe('x25519');
  if (out.envelope.kem !== 'x25519') throw new Error('expected x25519 envelope');
  const slots: ReadonlyArray<X25519Slot> = out.envelope.slots;
  expect(bytesToHex(out.envelope.nonce)).toBe(vector.nonce_hex);
  expect(slots).toHaveLength(vector.expected_slots.length);
  for (let i = 0; i < vector.expected_slots.length; i++) {
    const slot = slots[i] as X25519Slot;
    const expected = vector.expected_slots[i] as WrapPositiveSlot;
    expect(bytesToHex(slot.epk)).toBe(expected.epk_hex);
    expect(bytesToHex(slot.wrap)).toBe(expected.wrap_hex);
  }
  expect(bytesToHex(out.envelope.slots_mac)).toBe(vector.expected_slots_mac_hex);
  expect(bytesToHex(out.ciphertext)).toBe(vector.expected_ciphertext_hex);

  const epkSet = new Set(slots.map((s) => bytesToHex(s.epk)));
  const wrapSet = new Set(slots.map((s) => bytesToHex(s.wrap)));
  expect(epkSet.size).toBe(slots.length);
  expect(wrapSet.size).toBe(slots.length);
}

describe('sealed-poe wrap — N=1 empty plaintext', () => {
  it('produces byte-identical envelope + ciphertext against the pinned vector', () => {
    checkPositive(loadPositive('wrap-n1-empty.json'));
  });
});

describe('sealed-poe wrap — N=3 32-byte plaintext', () => {
  it('produces byte-identical envelope + ciphertext against the pinned vector', () => {
    checkPositive(loadPositive('wrap-n3.json'));
  });
});

describe('sealed-poe wrap — N=32 recipients', () => {
  it('produces byte-identical envelope + ciphertext against the pinned vector', () => {
    checkPositive(loadPositive('wrap-n32.json'));
  });
});

describe('sealed-poe wrap — negative cases (EciesSealedPoeError codes)', () => {
  const negative = loadNegative('wrap-negative.json');
  for (const vector of negative.vectors) {
    it(`raises EciesSealedPoeError code=${vector.expected_error_code} for ${vector.name}`, () => {
      const recipientPublicKeys = vector.recipient_publics_hex.map(hexToBytes);
      const ephemeralSecrets = vector.ephemeral_secrets_hex?.map(hexToBytes);
      const cek = vector.cek_hex !== undefined ? hexToBytes(vector.cek_hex) : undefined;
      const nonce = vector.nonce_hex !== undefined ? hexToBytes(vector.nonce_hex) : undefined;
      const plaintext = hexToBytes(vector.plaintext_hex);
      try {
        eciesSealedPoeWrap({
          plaintext,
          recipientPublicKeys,
          ...(ephemeralSecrets !== undefined ? { ephemeralSecrets } : {}),
          ...(cek !== undefined ? { cek } : {}),
          ...(nonce !== undefined ? { nonce } : {}),
          skipShuffle: true,
        });
        throw new Error(`${vector.name}: expected EciesSealedPoeError, got success`);
      } catch (err) {
        expect(err).toBeInstanceOf(EciesSealedPoeError);
        if (err instanceof EciesSealedPoeError) {
          expect(err.code).toBe(vector.expected_error_code);
        }
      }
    });
  }
});
