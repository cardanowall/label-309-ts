// KAT for the hybrid (mlkem768x25519 / X-Wing) sealed-PoE branch.
//
// Wraps deterministically against pinned recipient X-Wing keypairs, per-slot
// eseeds, CEK, and nonce, asserting byte-equality of the produced kem_ct
// (single 1120-byte byte string), wrap, slots_mac, and content ciphertext.
// Then unwraps each recipient secret seed and recovers the CEK + plaintext,
// proving the round-trip and that slots_mac commits to the kem_ct.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';

import { eciesSealedPoeUnwrap } from './unwrap';
import { eciesSealedPoeWrap, SEALED_POE_AEAD, type Mlkem768X25519Slot } from './wrap';
import type { ItemHashes } from './transcript';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

interface HybridSlotHex {
  kem_ct_hex: string;
  wrap_hex: string;
}

interface HybridVector {
  name: string;
  recipient_seeds_hex: string[];
  recipient_publics_hex: string[];
  eseeds_hex: string[];
  cek_hex: string;
  nonce_hex: string;
  plaintext_hex: string;
  hashes: Record<string, string>;
  expected_slots: HybridSlotHex[];
  expected_slots_mac_hex: string;
  expected_ciphertext_hex: string;
  expected_plaintext_hex: string;
}

interface HybridCorpus {
  version: number;
  primitive: string;
  source: string;
  vector: HybridVector;
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

function loadHybrid(filename: string): HybridCorpus {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as HybridCorpus;
}

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

function checkHybridWrap(corpus: HybridCorpus): void {
  const { vector } = corpus;
  // Pinned keypair check: the recorded publics MUST re-derive from the seeds,
  // so the fixture's secret material is internally consistent.
  const recipientSeeds = vector.recipient_seeds_hex.map(hexToBytes);
  const recipientPublicKeys = recipientSeeds.map((s) => {
    const kp = mlkem768x25519Keygen(s);
    return kp.publicKey;
  });
  for (let i = 0; i < recipientPublicKeys.length; i++) {
    expect(bytesToHex(recipientPublicKeys[i]!)).toBe(vector.recipient_publics_hex[i]);
  }

  const hashes = hashesFromHex(vector.hashes);
  const out = eciesSealedPoeWrap({
    plaintext: hexToBytes(vector.plaintext_hex),
    hashes,
    recipientPublicKeys,
    kem: 'mlkem768x25519',
    cek: hexToBytes(vector.cek_hex),
    nonce: hexToBytes(vector.nonce_hex),
    eseeds: vector.eseeds_hex.map(hexToBytes),
    skipShuffle: true,
  });

  expect(out.envelope.scheme).toBe(1);
  expect(out.envelope.aead).toBe(SEALED_POE_AEAD);
  expect(out.envelope.kem).toBe('mlkem768x25519');
  if (out.envelope.kem !== 'mlkem768x25519') throw new Error('expected hybrid envelope');
  const slots: ReadonlyArray<Mlkem768X25519Slot> = out.envelope.slots;

  expect(bytesToHex(out.envelope.nonce)).toBe(vector.nonce_hex);
  expect(slots).toHaveLength(vector.expected_slots.length);
  for (let i = 0; i < vector.expected_slots.length; i++) {
    const slot = slots[i]!;
    const expected = vector.expected_slots[i]!;
    // kem_ct MUST be a single byte string of exactly 1120 bytes.
    expect(slot.kem_ct.length).toBe(1120);
    expect(bytesToHex(slot.kem_ct)).toBe(expected.kem_ct_hex);
    expect(bytesToHex(slot.wrap)).toBe(expected.wrap_hex);
  }
  expect(bytesToHex(out.envelope.slots_mac)).toBe(vector.expected_slots_mac_hex);
  expect(bytesToHex(out.ciphertext)).toBe(vector.expected_ciphertext_hex);

  // Round-trip: every recipient secret seed recovers the plaintext.
  for (const seedHex of vector.recipient_seeds_hex) {
    const kp = mlkem768x25519Keygen(hexToBytes(seedHex));
    const res = eciesSealedPoeUnwrap({
      envelope: out.envelope,
      ciphertext: out.ciphertext,
      hashes,
      recipientSecretKey: kp.secretSeed,
    });
    expect(res.matched).toBe(true);
    if (res.matched) {
      expect(bytesToHex(res.plaintext)).toBe(vector.expected_plaintext_hex);
    }
  }
}

describe('sealed-poe wrap (hybrid mlkem768x25519) — N=1 empty plaintext', () => {
  it('produces byte-identical envelope + ciphertext and round-trips', () => {
    checkHybridWrap(loadHybrid('wrap-hybrid-n1.json'));
  });
});

describe('sealed-poe wrap (hybrid mlkem768x25519) — N=3 32-byte plaintext', () => {
  it('produces byte-identical envelope + ciphertext and round-trips for every recipient', () => {
    checkHybridWrap(loadHybrid('wrap-hybrid-n3.json'));
  });
});
