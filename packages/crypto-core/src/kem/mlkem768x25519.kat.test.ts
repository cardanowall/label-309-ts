import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { shake256 } from '@noble/hashes/sha3.js';
import { describe, expect, it } from 'vitest';

import {
  mlkem768x25519Decapsulate,
  mlkem768x25519Encapsulate,
  mlkem768x25519Keygen,
} from './mlkem768x25519';

// Known-answer vectors from draft-connolly-cfrg-xwing-kem-10 Appendix C,
// byte-identical to the RustCrypto/KEMs x-wing draft-06 vector set (commit
// 2425fe5a3380fcc125f01ae7662e467c8857148d) the bytes were transcribed from.
// These pin the wire format the wrapper depends on: 32-byte seed-only secret
// key, 96-byte SHAKE-256 seed expansion, ML-KEM-first public-key layout, and
// the SHA3-256 combiner output.

interface KeygenVector {
  name: string;
  seed_hex: string;
  expected_pk_hex: string;
  expected_sk_seed_hex: string;
}

interface EncapsVector {
  name: string;
  pk_hex: string;
  eseed_hex: string;
  expected_enc_hex: string;
  expected_ss_hex: string;
}

interface DecapsVector {
  name: string;
  sk_seed_hex: string;
  enc_hex: string;
  expected_ss_hex: string;
}

interface ShakeExpandVector {
  name: string;
  seed_hex: string;
  expected_expanded_hex: string;
  split_note: string;
}

interface DeterministicEncapsVector {
  name: string;
  seed_hex: string;
  expected_pk_hex: string;
  eseed_hex: string;
  expected_enc_hex: string;
  expected_ss_hex: string;
}

interface KatCorpus<V> {
  version: number;
  primitive: string;
  source: string;
  vectors: V[];
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
const fixtureDir = path.resolve(here, '../../tests/fixtures/kem');

function loadCorpus<V>(file: string): KatCorpus<V> {
  return JSON.parse(fs.readFileSync(path.resolve(fixtureDir, file), 'utf8')) as KatCorpus<V>;
}

const keygenCorpus = loadCorpus<KeygenVector>('mlkem768x25519-keygen-kat.json');
const encapsCorpus = loadCorpus<EncapsVector>('mlkem768x25519-encaps-kat.json');
const decapsCorpus = loadCorpus<DecapsVector>('mlkem768x25519-decaps-kat.json');
const shakeExpandCorpus = loadCorpus<ShakeExpandVector>('mlkem768x25519-shake-expand-kat.json');
const deterministicCorpus = loadCorpus<DeterministicEncapsVector>(
  'mlkem768x25519-encaps-deterministic-draft10-kat.json',
);

describe('mlkem768x25519 — keygen KAT (X-Wing draft-10 Appendix C)', () => {
  for (const vector of keygenCorpus.vectors) {
    it(`derives the pinned public key + seed-only secret for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      const { publicKey, secretSeed } = mlkem768x25519Keygen(seed);

      expect(bytesToHex(publicKey)).toBe(vector.expected_pk_hex);
      // The secret key is the 32-byte root seed itself.
      expect(bytesToHex(secretSeed)).toBe(vector.expected_sk_seed_hex);
    });
  }
});

describe('mlkem768x25519 — encapsulate KAT (deterministic eseed)', () => {
  for (const vector of encapsCorpus.vectors) {
    it(`produces the pinned ciphertext + shared secret for ${vector.name}`, () => {
      const publicKey = hexToBytes(vector.pk_hex);
      const eseed = hexToBytes(vector.eseed_hex);
      const { enc, ss } = mlkem768x25519Encapsulate({ publicKey, eseed });

      expect(bytesToHex(enc)).toBe(vector.expected_enc_hex);
      expect(bytesToHex(ss)).toBe(vector.expected_ss_hex);
    });
  }
});

describe('mlkem768x25519 — deterministic keygen+encapsulate KAT (X-Wing draft-10 Appendix C)', () => {
  // The full deterministic chain pinned by draft-10 Appendix C: the seed derives
  // the public key (keygen), and the eseed then derives the ciphertext + shared
  // secret (encaps). This binds keygen and encaps together against an externally
  // pinned anchor — the inline encaps KAT above starts from a hardcoded pk and
  // never re-derives it from the seed.
  for (const vector of deterministicCorpus.vectors) {
    it(`derives pk from seed then ct+ss from eseed for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      const { publicKey } = mlkem768x25519Keygen(seed);
      expect(bytesToHex(publicKey)).toBe(vector.expected_pk_hex);

      const eseed = hexToBytes(vector.eseed_hex);
      const { enc, ss } = mlkem768x25519Encapsulate({ publicKey, eseed });
      expect(bytesToHex(enc)).toBe(vector.expected_enc_hex);
      expect(bytesToHex(ss)).toBe(vector.expected_ss_hex);
    });
  }
});

describe('mlkem768x25519 — decapsulate KAT', () => {
  for (const vector of decapsCorpus.vectors) {
    it(`recovers the pinned shared secret for ${vector.name}`, () => {
      const secretSeed = hexToBytes(vector.sk_seed_hex);
      const enc = hexToBytes(vector.enc_hex);
      const ss = mlkem768x25519Decapsulate({ secretSeed, enc });

      expect(bytesToHex(ss)).toBe(vector.expected_ss_hex);
    });
  }
});

describe('mlkem768x25519 — SHAKE-256 seed expansion KAT', () => {
  // The wrapper relies on noble expanding the 32-byte seed via SHAKE-256 to a
  // 96-byte buffer (ML-KEM coin d || ML-KEM coin z || raw X25519 scalar). This
  // pins that exact expansion so a future noble change cannot silently alter
  // the key-derivation path the KATs depend on.
  for (const vector of shakeExpandCorpus.vectors) {
    it(`expands the seed to the pinned 96-byte buffer for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      const expanded = shake256(seed, { dkLen: 96 });

      expect(expanded.length).toBe(96);
      expect(bytesToHex(expanded)).toBe(vector.expected_expanded_hex);
    });
  }
});
