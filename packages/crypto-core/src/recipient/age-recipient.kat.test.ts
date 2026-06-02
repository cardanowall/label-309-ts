// Known-answer + byte-identity tests for the age recipient codec.
//
// The load-bearing assertion is that the inlined bech32 encoder produces
// strings byte-identical to a standard bech32 library used with the
// no-length-limit flag. We compare against @scure/base here (a test-only
// dependency — it never enters the runtime import graph) so any drift in the
// inlined algorithm is caught immediately. @scure/base is the de-facto
// reference bech32 implementation, so byte-identity with it guarantees any
// other conformant encoder produces the same recipient strings on the wire.

import { bech32 } from '@scure/base';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { deriveMlKem768X25519KeypairFromSeed } from '../seed-derive/derive';
import { bech32EncodeNoLimit } from './bech32';
import { encodeAgeX25519Recipient, encodeAgeXWingRecipient } from './age-recipient';

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// X25519 public keys pinned in packages/crypto-core/tests/fixtures/seed-derive/.
const ZERO_X25519_PUBLIC_HEX = 'c527cc01603c30c38718de8bfbca6af5063693c14ebb5dcc42b3f7389dfe6547';
const FF_X25519_PUBLIC_HEX = '367e677010b246efdd40e99d7a54fa73ceca3f161d074cab6bf3b7ba04c6c42a';
const DEADBEEF_X25519_PUBLIC_HEX =
  'e2499ff278f507ed0c48ceea07675d31da7ddf888ddad7d3cdc84b89871ff766';

const X25519_HEXES = [ZERO_X25519_PUBLIC_HEX, FF_X25519_PUBLIC_HEX, DEADBEEF_X25519_PUBLIC_HEX];

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/seed-derive');

function fixtureXWingPublicHex(file: string): string {
  const corpus = JSON.parse(fs.readFileSync(path.join(fixturesDir, file), 'utf8')) as {
    vectors: Array<{ expected_mlkem768x25519_public_key_hex: string }>;
  };
  return corpus.vectors[0]!.expected_mlkem768x25519_public_key_hex;
}

describe('bech32EncodeNoLimit — byte-identity with @scure/base', () => {
  it('matches @scure/base for empty payload (HRP only)', () => {
    const ours = bech32EncodeNoLimit('age', new Uint8Array(0));
    const ref = bech32.encode('age', bech32.toWords(new Uint8Array(0)), false);
    expect(ours).toBe(ref);
  });

  it('matches @scure/base across random byte lengths 1..200', () => {
    let seed = 0x12345678;
    const next = (): number => {
      // Deterministic xorshift so the corpus is stable across runs.
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return (seed >>> 0) & 0xff;
    };
    for (let len = 1; len <= 200; len++) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = next();
      const ours = bech32EncodeNoLimit('age', bytes);
      const ref = bech32.encode('age', bech32.toWords(bytes), false);
      expect(ours).toBe(ref);
    }
  });

  it('throws on empty prefix', () => {
    expect(() => bech32EncodeNoLimit('', new Uint8Array(32))).toThrow(/empty prefix/);
  });
});

describe('encodeAgeX25519Recipient', () => {
  for (const hex of X25519_HEXES) {
    it(`encodes ${hex.slice(0, 8)}… to a 62-char age1 string identical to @scure/base`, () => {
      const pub = hexToBytes(hex);
      const recipient = encodeAgeX25519Recipient(pub);
      const ref = bech32.encode('age', bech32.toWords(pub), false);
      expect(recipient).toBe(ref);
      expect(recipient.startsWith('age1')).toBe(true);
      expect(recipient.length).toBe(62);
    });

    it(`round-trips: bech32 decode of ${hex.slice(0, 8)}… recovers HRP age + the 32 bytes`, () => {
      const pub = hexToBytes(hex);
      const decoded = bech32.decodeToBytes(encodeAgeX25519Recipient(pub));
      expect(decoded.prefix).toBe('age');
      expect(Array.from(decoded.bytes)).toEqual(Array.from(pub));
    });
  }

  it('throws on 31 / 33 / empty input', () => {
    expect(() => encodeAgeX25519Recipient(new Uint8Array(31))).toThrow(/exactly 32 bytes/);
    expect(() => encodeAgeX25519Recipient(new Uint8Array(33))).toThrow(/exactly 32 bytes/);
    expect(() => encodeAgeX25519Recipient(new Uint8Array(0))).toThrow(/exactly 32 bytes/);
  });
});

describe('encodeAgeXWingRecipient', () => {
  it('encodes a synthetic 1216-byte key to a 1960-char age1pqc string identical to @scure/base', () => {
    const pub = new Uint8Array(1216);
    for (let i = 0; i < pub.length; i++) pub[i] = (i * 7) & 0xff;
    const recipient = encodeAgeXWingRecipient(pub);
    const ref = bech32.encode('age1pqc', bech32.toWords(pub), false);
    expect(recipient).toBe(ref);
    expect(recipient.startsWith('age1pqc1')).toBe(true);
    expect(recipient.length).toBe(1960);
  });

  it('encodes the REAL X-Wing pubkey derived from the all-zero seed and round-trips', () => {
    const { publicKey } = deriveMlKem768X25519KeypairFromSeed(new Uint8Array(32));
    expect(publicKey.length).toBe(1216);
    const recipient = encodeAgeXWingRecipient(publicKey);
    // Byte-identity with the reference encoder on a genuine X-Wing key.
    expect(recipient).toBe(bech32.encode('age1pqc', bech32.toWords(publicKey), false));
    const decoded = bech32.decodeToBytes(recipient);
    expect(decoded.prefix).toBe('age1pqc');
    expect(decoded.bytes.length).toBe(1216);
    expect(Array.from(decoded.bytes)).toEqual(Array.from(publicKey));
  });

  it('matches the X-Wing pubkeys pinned in every seed-derive fixture', () => {
    for (const file of ['seed-from-zero.json', 'seed-from-ff.json', 'seed-from-deadbeef.json']) {
      const pub = hexToBytes(fixtureXWingPublicHex(file));
      expect(pub.length).toBe(1216);
      const recipient = encodeAgeXWingRecipient(pub);
      expect(recipient).toBe(bech32.encode('age1pqc', bech32.toWords(pub), false));
      const decoded = bech32.decodeToBytes(recipient);
      expect(decoded.prefix).toBe('age1pqc');
      expect(Array.from(decoded.bytes)).toEqual(Array.from(pub));
    }
  });

  it('throws on 32 / 1215 / 1217 / empty input', () => {
    expect(() => encodeAgeXWingRecipient(new Uint8Array(32))).toThrow(/exactly 1216 bytes/);
    expect(() => encodeAgeXWingRecipient(new Uint8Array(1215))).toThrow(/exactly 1216 bytes/);
    expect(() => encodeAgeXWingRecipient(new Uint8Array(1217))).toThrow(/exactly 1216 bytes/);
    expect(() => encodeAgeXWingRecipient(new Uint8Array(0))).toThrow(/exactly 1216 bytes/);
  });
});
