import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { EciesSealedPoeError, type EciesSealedPoeErrorCode } from './errors';
import { eciesSealedPoeWrap, SEALED_POE_AEAD, type X25519Slot } from './wrap';
import type { ItemHashes } from './transcript';

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
  hashes: Record<string, string>;
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

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

function loadPositive(filename: string): WrapPositiveCorpus {
  return JSON.parse(
    fs.readFileSync(path.join(fixturesDir, filename), 'utf8'),
  ) as WrapPositiveCorpus;
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
    hashes: hashesFromHex(vector.hashes),
    recipientPublicKeys,
    cek,
    nonce,
    ephemeralSecrets,
    skipShuffle: true,
  });

  expect(out.envelope.scheme).toBe(1);
  expect(out.envelope.aead).toBe(SEALED_POE_AEAD);
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

// Wrap-input validation errors are construction-only codes whose calling
// conventions differ per SDK, so they are pinned with direct cases here rather
// than a shared byte corpus. Each case supplies an otherwise-valid input set
// and breaks exactly one argument.
describe('sealed-poe wrap — input-validation EciesSealedPoeError codes', () => {
  const fillBytes = (b: number, n: number): Uint8Array => new Uint8Array(n).fill(b & 0xff);
  const validPub = fillBytes(0x42, 32);
  const plaintext = new TextEncoder().encode('wrap validation');
  const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };

  const cases: Array<{
    name: string;
    args: Partial<Parameters<typeof eciesSealedPoeWrap>[0]>;
    expected: EciesSealedPoeErrorCode;
  }> = [
    {
      name: 'zero recipients',
      args: { recipientPublicKeys: [] },
      expected: 'ENC_SLOTS_EMPTY',
    },
    {
      name: '31-byte recipient public key',
      args: { recipientPublicKeys: [fillBytes(0x42, 31)] },
      expected: 'KEM_EPK_LENGTH_MISMATCH',
    },
    {
      name: '31-byte cek',
      args: { recipientPublicKeys: [validPub], cek: fillBytes(0x01, 31) },
      expected: 'INVALID_CEK_LENGTH',
    },
    {
      name: '23-byte nonce',
      args: { recipientPublicKeys: [validPub], nonce: fillBytes(0x01, 23) },
      expected: 'NONCE_LENGTH_MISMATCH',
    },
    {
      name: '31-byte ephemeral secret',
      args: { recipientPublicKeys: [validPub], ephemeralSecrets: [fillBytes(0x01, 31)] },
      expected: 'INVALID_EPHEMERAL_SECRET_LENGTH',
    },
    {
      name: 'ephemeral-secret count mismatch',
      args: {
        recipientPublicKeys: [validPub],
        ephemeralSecrets: [fillBytes(0x01, 32), fillBytes(0x02, 32)],
      },
      expected: 'EPHEMERAL_SECRETS_COUNT_MISMATCH',
    },
    {
      name: 'eseeds supplied for the x25519 path',
      args: { recipientPublicKeys: [validPub], eseeds: [fillBytes(0x01, 64)] },
      expected: 'EPHEMERAL_SECRETS_COUNT_MISMATCH',
    },
    {
      name: 'empty hashes map',
      args: { recipientPublicKeys: [validPub], hashes: {} },
      expected: 'ENC_REQUIRES_CONTENT_HASH',
    },
  ];

  for (const { name, args, expected } of cases) {
    it(`raises EciesSealedPoeError code=${expected} for ${name}`, () => {
      try {
        eciesSealedPoeWrap({
          plaintext,
          hashes,
          recipientPublicKeys: [validPub],
          skipShuffle: true,
          ...args,
        });
        throw new Error(`${name}: expected EciesSealedPoeError, got success`);
      } catch (err) {
        expect(err).toBeInstanceOf(EciesSealedPoeError);
        if (err instanceof EciesSealedPoeError) {
          expect(err.code).toBe(expected);
        }
      }
    });
  }
});
