// Behavioral known-answer test for the raw-seed identity surface — the parity
// twin of the Python `test_seed_identity.py`. Everything a seed holder can do
// from the public SDK is exercised end to end against the shared seed-derive
// fixtures:
//
//   (1) seed → three keypairs (Ed25519 / X25519 / X-Wing), pubkeys pinned to
//       the fixture vectors;
//   (2) seed → age recipient strings (classical "age1…" + hybrid "age1pqc…"),
//       pinned cross-language via tests/fixtures/seed-derive/recipients-from-seed.json;
//   (3) seed → path-1 Signer → COSE Sig_structure → Ed25519 verify round-trip;
//   (4) seed → decrypt a HYBRID (mlkem768x25519) sealed PoE, plus a negative
//       case proving a different seed yields WRONG_RECIPIENT_KEY.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@cardanowall/crypto-core/hash';
import { eciesSealedPoeWrap, type SealedEnvelope } from '@cardanowall/crypto-core/sealed-poe';
import { verifyEd25519 } from '@cardanowall/crypto-core/sig';
import type { PoeRecord } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { prepareSigStructure } from '../client/off-host-sign';

import {
  decryptSealedFromSeed,
  deriveKeysFromSeed,
  recipientKeyBundleFromSeed,
  recipientsFromSeed,
  signerFromSeed,
} from './seed-identity';

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Minimal bech32 decoder — verifies the recipient strings round-trip to the
// original public-key bytes without pulling a base-encoding dependency into the
// SDK test graph. Mirrors the inlined encoder in crypto-core/recipient/bech32.
const BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Decode(s: string): { hrp: string; bytes: Uint8Array } {
  const sep = s.lastIndexOf('1');
  const hrp = s.slice(0, sep);
  const dataPart = s.slice(sep + 1);
  // Drop the 6-symbol checksum; we only need the payload bytes for round-trip.
  const words: number[] = [];
  for (const ch of dataPart.slice(0, dataPart.length - 6)) {
    const v = BECH32_ALPHABET.indexOf(ch);
    if (v === -1) throw new Error(`bech32Decode: bad char ${ch}`);
    words.push(v);
  }
  const bytes: number[] = [];
  let carry = 0;
  let pos = 0;
  for (const w of words) {
    carry = (carry << 5) | w;
    pos += 5;
    while (pos >= 8) {
      pos -= 8;
      bytes.push((carry >> pos) & 0xff);
    }
  }
  return { hrp, bytes: Uint8Array.from(bytes) };
}

interface SeedDeriveVector {
  name: string;
  seed_hex: string;
  expected_ed25519_secret_hex: string;
  expected_ed25519_public_hex: string;
  expected_x25519_secret_hex: string;
  expected_x25519_public_hex: string;
  expected_mlkem768x25519_secret_seed_hex: string;
  expected_mlkem768x25519_public_key_hex: string;
}

interface SeedDeriveCorpus {
  vectors: SeedDeriveVector[];
}

interface RecipientsVector {
  name: string;
  seed_hex: string;
  age: string;
  age1pqc: string;
}

interface RecipientsCorpus {
  vectors: RecipientsVector[];
}

const here = path.dirname(fileURLToPath(import.meta.url));
// The seed-derive corpora are shared across crypto-core, sdk-ts, and sdk-py;
// they live in crypto-core as the single source of truth.
const seedFixturesDir = path.resolve(here, '../../../crypto-core/tests/fixtures/seed-derive');

function loadSeedCorpus(file: string): SeedDeriveCorpus {
  return JSON.parse(fs.readFileSync(path.join(seedFixturesDir, file), 'utf8')) as SeedDeriveCorpus;
}

const SEED_FILES = ['seed-from-zero.json', 'seed-from-ff.json', 'seed-from-deadbeef.json'];
const seedVectors: SeedDeriveVector[] = SEED_FILES.flatMap((f) => loadSeedCorpus(f).vectors);

// The recipient-string corpus is pinned in this package and mirrored verbatim by
// the Python twin, so it enforces cross-language byte-identity of the codec.
const sdkFixturesDir = path.resolve(here, '../../tests/fixtures/seed-derive');
const recipientsCorpus = JSON.parse(
  fs.readFileSync(path.join(sdkFixturesDir, 'recipients-from-seed.json'), 'utf8'),
) as RecipientsCorpus;
const recipientsByName = new Map(recipientsCorpus.vectors.map((v) => [v.name, v]));

describe('seed → keypairs', () => {
  for (const vector of seedVectors) {
    it(`derives Ed25519 + X25519 + X-Wing pubkeys for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      const keys = deriveKeysFromSeed(seed);

      expect(bytesToHex(keys.ed25519.secretKey)).toBe(vector.expected_ed25519_secret_hex);
      expect(bytesToHex(keys.ed25519.publicKey)).toBe(vector.expected_ed25519_public_hex);

      expect(bytesToHex(keys.x25519.secretKey)).toBe(vector.expected_x25519_secret_hex);
      expect(bytesToHex(keys.x25519.publicKey)).toBe(vector.expected_x25519_public_hex);

      expect(bytesToHex(keys.mlkem768x25519.secretSeed)).toBe(
        vector.expected_mlkem768x25519_secret_seed_hex,
      );
      expect(bytesToHex(keys.mlkem768x25519.publicKey)).toBe(
        vector.expected_mlkem768x25519_public_key_hex,
      );
    });
  }
});

describe('seed → age recipient strings', () => {
  for (const vector of seedVectors) {
    it(`emits the cross-language-pinned recipients for ${vector.name}`, () => {
      const seed = hexToBytes(vector.seed_hex);
      const recipients = recipientsFromSeed(seed);
      const pinned = recipientsByName.get(vector.name);
      if (pinned === undefined) {
        throw new Error(`no recipients fixture for ${vector.name}`);
      }

      // Byte-identical to the cross-language fixture the Python twin also pins.
      expect(recipients.age).toBe(pinned.age);
      expect(recipients.age1pqc).toBe(pinned.age1pqc);

      // Structural invariants: HRP + length per the codec contract.
      expect(recipients.age.startsWith('age1')).toBe(true);
      expect(recipients.age.length).toBe(62);
      expect(recipients.age1pqc.startsWith('age1pqc1')).toBe(true);
      expect(recipients.age1pqc.length).toBe(1960);

      // Round-trip: the recipient strings decode back to the derived pubkeys.
      const ageDecoded = bech32Decode(recipients.age);
      expect(ageDecoded.hrp).toBe('age');
      expect(bytesToHex(ageDecoded.bytes)).toBe(vector.expected_x25519_public_hex);

      const pqcDecoded = bech32Decode(recipients.age1pqc);
      expect(pqcDecoded.hrp).toBe('age1pqc');
      expect(pqcDecoded.bytes.length).toBe(1216);
      expect(bytesToHex(pqcDecoded.bytes)).toBe(vector.expected_mlkem768x25519_public_key_hex);
    });
  }
});

describe('seed → path-1 sign → verify round-trip', () => {
  // Minimal hash-only PoE record (profile=core): one item whose `hashes` map
  // carries a single sha2-256 digest. Signing covers the canonical record body,
  // so the exact digest only needs to be well-formed.
  function minimalRecord(): PoeRecord {
    return {
      v: 1,
      items: [
        {
          hashes: {
            'sha2-256': hexToBytes(
              'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            ),
          },
        },
      ],
    };
  }

  for (const vector of seedVectors) {
    it(`signs with the derived Ed25519 key and verifies for ${vector.name}`, async () => {
      const seed = hexToBytes(vector.seed_hex);
      const signer = signerFromSeed(seed);

      // The signer's public key is exactly the derived Ed25519 pubkey.
      expect(bytesToHex(signer.signerPubkey)).toBe(vector.expected_ed25519_public_hex);

      const record = minimalRecord();
      const { sigStructureBytes } = prepareSigStructure({
        record,
        signerPubkey: signer.signerPubkey,
      });
      const signature = await signer.sign(sigStructureBytes);
      expect(signature.length).toBe(64);

      expect(
        verifyEd25519({
          publicKey: signer.signerPubkey,
          message: sigStructureBytes,
          signature,
        }),
      ).toBe(true);

      // Negative control: tampering one byte of the signed message breaks it.
      const tampered = new Uint8Array(sigStructureBytes);
      const last = tampered.length - 1;
      tampered[last] = (tampered[last] ?? 0) ^ 0x01;
      expect(
        verifyEd25519({
          publicKey: signer.signerPubkey,
          message: tampered,
          signature,
        }),
      ).toBe(false);
    });
  }
});

describe('seed → decrypt a HYBRID (mlkem768x25519) sealed PoE', () => {
  // Deterministic wrap params — fixed CEK / nonce / X-Wing eseed so the closed
  // round-trip is reproducible. `skipShuffle` keeps the single slot in place.
  const CEK = hexToBytes('abababababababababababababababababababababababababababababababab');
  const NONCE = hexToBytes('000102030405060708090a0b0c0d0e0f1011121314151617');
  const ESEED = hexToBytes(
    'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1' +
      'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1',
  );
  const PLAINTEXT = new TextEncoder().encode('hybrid sealed PoE plaintext');
  // The item's plaintext-hash claim, bound into the slots transcript by the
  // wrap and required again at unwrap time.
  const HASHES = { 'sha2-256': sha256(PLAINTEXT) };

  function wrapHybridToSeed(seedHex: string): { envelope: SealedEnvelope; ciphertext: Uint8Array } {
    const seed = hexToBytes(seedHex);
    const recipientPublicKey = deriveKeysFromSeed(seed).mlkem768x25519.publicKey;
    const out = eciesSealedPoeWrap({
      plaintext: PLAINTEXT,
      hashes: HASHES,
      recipientPublicKeys: [recipientPublicKey],
      kem: 'mlkem768x25519',
      cek: CEK,
      nonce: NONCE,
      eseeds: [ESEED],
      skipShuffle: true,
    });
    return { envelope: out.envelope, ciphertext: out.ciphertext };
  }

  for (const vector of seedVectors) {
    it(`decrypts a record sealed to its own X-Wing key for ${vector.name}`, () => {
      const { envelope, ciphertext } = wrapHybridToSeed(vector.seed_hex);

      const result = decryptSealedFromSeed({
        seed: hexToBytes(vector.seed_hex),
        envelope,
        ciphertext,
        hashes: HASHES,
      });

      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(bytesToHex(result.plaintext)).toBe(bytesToHex(PLAINTEXT));
      }
    });
  }

  it('returns WRONG_RECIPIENT_KEY when decrypting with a different seed', () => {
    // Seal to seed-from-zero's X-Wing key, attempt decrypt with seed-from-ff.
    const { envelope, ciphertext } = wrapHybridToSeed(seedVectors[0]!.seed_hex);
    const wrongSeed = hexToBytes(seedVectors[1]!.seed_hex);

    const result = decryptSealedFromSeed({ seed: wrongSeed, envelope, ciphertext, hashes: HASHES });

    expect(result.matched).toBe(false);
    if (!result.matched) {
      expect(result.reason).toBe('WRONG_RECIPIENT_KEY');
    }
  });

  it('the bundle the dispatch consumes carries exactly one secret per KEM', () => {
    const bundle = recipientKeyBundleFromSeed(hexToBytes(seedVectors[0]!.seed_hex));
    expect(bundle.x25519PrivateKeys).toHaveLength(1);
    expect(bundle.mlkem768x25519SecretSeeds).toHaveLength(1);
  });
});
