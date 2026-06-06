// Byte-exact known-answer test for the age recipient codec, driven by the
// shared conformance fixture `seed-derive/recipient-strings-kat.json`.
//
// The fixture pins, for both KEMs, a raw public key and the exact Bech32 string
// it must encode to (and decode back from). This complements the byte-identity
// test against a reference encoder: here the target strings are frozen anchors,
// so a codec change that drifts away from the published recipient form is caught
// even if it still agrees with whatever reference library happens to be present.
// It also locks the HRP / visible-prefix distinction: HRP `age` renders the
// visible `age1…` prefix, and HRP `age1pqc` renders `age1pqc1…` (the leading `1`
// is the Bech32 separator, not part of the HRP), with decode validating the HRP
// exactly.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { bech32EncodeNoLimit } from './bech32';
import {
  encodeAgeX25519Recipient,
  encodeAgeXWingRecipient,
  parseAgeRecipient,
  type RecipientKem,
} from './age-recipient';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

interface RecipientStringVector {
  name: string;
  kem: RecipientKem;
  public_key_hex: string;
  recipient: string;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(
  here,
  '../../tests/fixtures/seed-derive/recipient-strings-kat.json',
);
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as {
  vectors: RecipientStringVector[];
};

function encodeFor(kem: RecipientKem, publicKey: Uint8Array): string {
  return kem === 'x25519'
    ? encodeAgeX25519Recipient(publicKey)
    : encodeAgeXWingRecipient(publicKey);
}

describe('age recipient codec — byte-exact KAT', () => {
  // Cover at least one vector per KEM, or the fixture has silently lost a class.
  it('fixture carries both KEMs', () => {
    const kems = new Set(corpus.vectors.map((v) => v.kem));
    expect(kems.has('x25519')).toBe(true);
    expect(kems.has('mlkem768x25519')).toBe(true);
  });

  for (const vector of corpus.vectors) {
    it(`encodes the pinned public key to the exact string for ${vector.name}`, () => {
      const publicKey = hexToBytes(vector.public_key_hex);
      expect(encodeFor(vector.kem, publicKey)).toBe(vector.recipient);
    });

    it(`decodes the pinned string back to the exact key + KEM for ${vector.name}`, () => {
      const parsed = parseAgeRecipient(vector.recipient);
      expect(parsed.kem).toBe(vector.kem);
      expect(bytesToHex(parsed.publicKey)).toBe(vector.public_key_hex);
    });

    it(`renders the visible prefix the HRP implies for ${vector.name}`, () => {
      const visiblePrefix = vector.kem === 'x25519' ? 'age1' : 'age1pqc1';
      expect(vector.recipient.startsWith(visiblePrefix)).toBe(true);
    });
  }

  // HRP is validated exactly: a checksum-valid string under the hybrid HRP that
  // carries a 32-byte (x25519-length) payload MUST be rejected, not mis-routed
  // to the x25519 KEM. This is the load-bearing HRP/length guard.
  it('rejects a checksum-valid age1pqc string carrying an x25519-length key', () => {
    const x25519Vector = corpus.vectors.find((v) => v.kem === 'x25519')!;
    const x25519Key = hexToBytes(x25519Vector.public_key_hex);
    const hybridHrpShortKey = bech32EncodeNoLimit('age1pqc', x25519Key);
    expect(hybridHrpShortKey.startsWith('age1pqc1')).toBe(true);
    expect(() => parseAgeRecipient(hybridHrpShortKey)).toThrow(/1216-byte/);
  });

  it('rejects a checksum-valid string under an unrecognized HRP', () => {
    const x25519Vector = corpus.vectors.find((v) => v.kem === 'x25519')!;
    const x25519Key = hexToBytes(x25519Vector.public_key_hex);
    const unknownHrp = bech32EncodeNoLimit('xyz', x25519Key);
    expect(() => parseAgeRecipient(unknownHrp)).toThrow(/unrecognized recipient prefix/);
  });
});
