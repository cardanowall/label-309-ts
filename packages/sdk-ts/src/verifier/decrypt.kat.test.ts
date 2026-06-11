// Fixture-consumption gates for the shared sealed-PoE conformance vectors at
// the verifier layer, driven through the public per-item decryption step:
//
//   * passphrase-n1.json — reproduce the producer path (Argon2id-derived CEK,
//     in-ciphertext key commitment, segmented STREAM), assert the pinned blob
//     byte-for-byte, then round-trip the same blob through the verifier.
//   * construction-negative.json (cross_path_vectors) — a slots-shaped record
//     decrypted with a passphrase input, and a passphrase-shaped record
//     decrypted with a recipient key, are both refused as
//     WRONG_DECRYPTION_INPUT_SHAPE before any KDF or AEAD work.
//
// The corpus is the single source of truth shared across crypto-core, sdk-ts,
// and the sibling SDKs; it lives in crypto-core's tests/fixtures and is read
// from there so a divergence fails cross-implementation rather than silently
// passing a self-generated local copy.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { passphraseSealedPoeSeal } from '@cardanowall/crypto-core/sealed-poe';
import type { ItemEntry } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import type { ContentFetchContext } from './content';
import { decryptItem } from './decrypt';
import { IssueSink } from './issues';
import type { DecryptionCredential, FetchOutbound } from './types';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../../crypto-core/tests/fixtures/sealed-poe');

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

function loadFixture<T>(filename: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as T;
}

const NEVER_FETCH: FetchOutbound = async () => {
  throw new Error('KAT must not fetch when out-of-band ciphertext is supplied');
};

function mkCtx(): ContentFetchContext {
  return {
    fetchFn: NEVER_FETCH,
    arweaveGateways: ['https://arweave.example'],
    ipfsGateways: [],
    issues: new IssueSink(),
  };
}

async function runDecrypt(
  item: ItemEntry,
  credentials: ReadonlyArray<DecryptionCredential>,
  blob: Uint8Array,
): Promise<ReturnType<typeof decryptItem>> {
  return decryptItem({
    item,
    itemIndex: 0,
    credentials,
    outOfBandCiphertext: blob,
    fetchContent: false,
    ctx: mkCtx(),
  });
}

// ---------------------------------------------------------------------------
// passphrase-n1.json
// ---------------------------------------------------------------------------

interface PassphraseN1Corpus {
  vector: {
    name: string;
    passphrase: string;
    salt_hex: string;
    params: { m: number; t: number; p: number };
    nonce_hex: string;
    hashes: Record<string, string>;
    plaintext_hex: string;
    expected_commitment_hex: string;
    expected_ciphertext_hex: string;
    expected_plaintext_hex: string;
  };
}

describe('sealed-poe passphrase path — pinned conformance vector', () => {
  it('byte-pins the blob from the producer path and round-trips through the verifier', async () => {
    const { vector } = loadFixture<PassphraseN1Corpus>('passphrase-n1.json');
    const salt = hexToBytes(vector.salt_hex);
    const nonce = hexToBytes(vector.nonce_hex);
    const plaintext = hexToBytes(vector.plaintext_hex);
    const hashes = Object.fromEntries(
      Object.entries(vector.hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]),
    );

    // Producer recompute: commitment(32) || STREAM chunks, pinned byte-exact.
    const sealed = await passphraseSealedPoeSeal({
      plaintext,
      hashes,
      passphrase: vector.passphrase,
      salt,
      params: vector.params,
      nonce,
    });
    expect(bytesToHex(sealed.blob.subarray(0, 32))).toBe(vector.expected_commitment_hex);
    expect(bytesToHex(sealed.blob)).toBe(vector.expected_ciphertext_hex);

    // Round-trip the pinned blob through the public verifier step.
    const item = {
      hashes,
      enc: {
        scheme: 1,
        aead: sealed.envelope.aead,
        nonce,
        passphrase: { alg: 'argon2id', salt, params: vector.params },
      },
    } as unknown as ItemEntry;
    const result = await runDecrypt(
      item,
      [{ passphrase: vector.passphrase }],
      hexToBytes(vector.expected_ciphertext_hex),
    );
    expect(result.contentCheck).toBe('checked');
    expect(result.decryption).toEqual({ decrypted: true, plaintextHashOk: true });
    expect(bytesToHex(plaintext)).toBe(vector.expected_plaintext_hex);
  });
});

// ---------------------------------------------------------------------------
// construction-negative.json — cross_path_vectors
// ---------------------------------------------------------------------------

interface X25519SlotHex {
  epk_hex: string;
  wrap_hex: string;
}

interface CrossPathVector {
  name: string;
  slots_envelope: {
    scheme: number;
    aead: string;
    kem: string;
    nonce_hex: string;
    slots: X25519SlotHex[];
    slots_mac_hex: string;
  };
  passphrase_envelope: {
    scheme: number;
    aead: string;
    nonce_hex: string;
    passphrase: {
      alg: string;
      salt_hex: string;
      params: { m: number; t: number; p: number };
    };
  };
}

interface ConstructionNegativeCorpus {
  cross_path_vectors: CrossPathVector[];
}

describe('sealed-poe cross-path confusion — pinned conformance vectors', () => {
  const corpus = loadFixture<ConstructionNegativeCorpus>('construction-negative.json');

  for (const v of corpus.cross_path_vectors) {
    it(`a slots-shaped record + passphrase input is refused before any AEAD: ${v.name}`, async () => {
      const env = v.slots_envelope;
      const item = {
        hashes: { 'sha2-256': new Uint8Array(32) },
        enc: {
          scheme: env.scheme,
          aead: env.aead,
          kem: env.kem,
          nonce: hexToBytes(env.nonce_hex),
          slots: env.slots.map((s) => ({
            epk: hexToBytes(s.epk_hex),
            wrap: hexToBytes(s.wrap_hex),
          })),
          slots_mac: hexToBytes(env.slots_mac_hex),
        },
      } as unknown as ItemEntry;

      const result = await runDecrypt(item, [{ passphrase: 'anything' }], new Uint8Array(16));
      expect(result.contentCheck).toBe('not_checked');
      expect(result.decryption).toEqual({
        decrypted: false,
        code: 'WRONG_DECRYPTION_INPUT_SHAPE',
      });
    });

    it(`a passphrase-shaped record + recipient key is refused before any AEAD: ${v.name}`, async () => {
      const env = v.passphrase_envelope;
      const item = {
        hashes: { 'sha2-256': new Uint8Array(32) },
        enc: {
          scheme: env.scheme,
          aead: env.aead,
          nonce: hexToBytes(env.nonce_hex),
          passphrase: {
            alg: env.passphrase.alg,
            salt: hexToBytes(env.passphrase.salt_hex),
            params: env.passphrase.params,
          },
        },
      } as unknown as ItemEntry;

      const result = await runDecrypt(
        item,
        [{ recipientSecretKey: new Uint8Array(32).fill(0x11) }],
        new Uint8Array(16),
      );
      expect(result.contentCheck).toBe('not_checked');
      expect(result.decryption).toEqual({
        decrypted: false,
        code: 'WRONG_DECRYPTION_INPUT_SHAPE',
      });
    });
  }
});
