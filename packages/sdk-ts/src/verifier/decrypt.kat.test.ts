// Fixture-consumption gates for the shared sealed-PoE conformance vectors at the
// verifier layer. The passphrase path and the cross-path shape check both live
// in the verifier, so the pinned vectors are driven through the public
// `tryDecryptions` surface here:
//
//   * passphrase-n1.json — reproduce the producer path (Argon2id-derived CEK,
//     HKDF payload_key, structured AAD, XChaCha20-Poly1305), assert the pinned
//     ciphertext byte-for-byte, then round-trip the same ciphertext through the
//     verifier.
//   * construction-negative.json (cross_path_vectors) — a slots-shaped record
//     decrypted with a passphrase input, and a passphrase-shaped record
//     decrypted with a recipient key, are both refused as
//     WRONG_DECRYPTION_INPUT_SHAPE before any AEAD.
//
// The corpus is the single source of truth shared across crypto-core, sdk-ts,
// and sdk-py; it lives in crypto-core's tests/fixtures and is read from there so
// a divergence fails cross-implementation rather than silently passing a
// self-generated local copy.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { xchacha20Poly1305Encrypt } from '@cardanowall/crypto-core/aead';
import { sha256 } from '@cardanowall/crypto-core/hash';
import { argon2idV13 } from '@cardanowall/crypto-core/kdf';
import { adContentPassphrase, passphrasePayloadKey } from '@cardanowall/crypto-core/sealed-poe';
import type { ItemEntry, PoeRecord } from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { normalizePassphrase, tryDecryptions } from './decrypt';
import type { FetchOutbound, HttpCallRecord, VerifyTxInput, VerifyUriCheck } from './types';

const here = path.dirname(fileURLToPath(import.meta.url));
// The sealed-PoE conformance corpus is shared across crypto-core, sdk-ts, and
// sdk-py; it lives in crypto-core as the single source of truth.
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
  throw new Error('KAT must not fetch when ciphertextBytes are supplied');
};

async function runDecrypt(
  record: PoeRecord,
  decryption: NonNullable<VerifyTxInput['decryption']>,
  ciphertext: Uint8Array,
): Promise<ReturnType<typeof tryDecryptions>> {
  const httpCalls: HttpCallRecord[] = [];
  const uriChecksOut: VerifyUriCheck[] = [];
  const input: VerifyTxInput = {
    txHash: 'a'.repeat(64),
    decryption,
    ciphertextBytes: { 0: ciphertext },
  };
  return tryDecryptions({
    record,
    input,
    fetchFn: NEVER_FETCH,
    httpCalls,
    uriChecksOut,
    allowUriFetch: false,
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
    plaintext_hex: string;
    expected_ciphertext_hex: string;
    expected_plaintext_hex: string;
  };
}

describe('sealed-poe passphrase path — pinned conformance vector', () => {
  it('byte-pins the ciphertext from the producer path and round-trips through the verifier', async () => {
    const { vector } = loadFixture<PassphraseN1Corpus>('passphrase-n1.json');
    const { passphrase } = vector;
    const salt = hexToBytes(vector.salt_hex);
    const { m, t, p } = vector.params;
    const nonce = hexToBytes(vector.nonce_hex);
    const plaintext = hexToBytes(vector.plaintext_hex);

    // Producer recompute: CEK = Argon2id(normalize(pw)); payload_key = HKDF(CEK,
    // salt=nonce, info=payload-passphrase); AAD = canonicalEncode(AD_CONTENT_PASSPHRASE).
    const cek = await argon2idV13({
      password: normalizePassphrase(passphrase),
      salt,
      memSizeKB: m,
      iterations: t,
      parallelism: p,
      outBytes: 32,
    });
    const payloadKey = passphrasePayloadKey({ cek, nonce });
    const aad = adContentPassphrase({
      nonce,
      passphrase: { alg: 'argon2id', salt, params: { m, t, p } },
    });
    const ciphertext = xchacha20Poly1305Encrypt({ key: payloadKey, nonce, aad, plaintext });
    expect(bytesToHex(ciphertext)).toBe(vector.expected_ciphertext_hex);

    // Round-trip the pinned ciphertext through the public verifier.
    const item = {
      hashes: { 'sha2-256': sha256(plaintext) },
      enc: {
        scheme: 1,
        aead: 'xchacha20-poly1305',
        nonce,
        passphrase: { alg: 'argon2id', salt, params: { m, t, p } },
      },
    } as unknown as ItemEntry;
    const record = { v: 1, items: [item] } as unknown as PoeRecord;

    const { results } = await runDecrypt(record, [{ itemIndex: 0, passphrase }], ciphertext);
    expect(results[0]?.verdict).toBe('decrypted');
    expect(results[0]?.plaintext_hash_ok).toBe(true);
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
      const record = { v: 1, items: [item] } as unknown as PoeRecord;

      const { results } = await runDecrypt(
        record,
        [{ itemIndex: 0, passphrase: 'anything' }],
        new Uint8Array(16),
      );
      expect(results[0]?.verdict).toBe('wrong-input-shape');
      expect(results[0]?.reason).toBe('WRONG_DECRYPTION_INPUT_SHAPE');
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
      const record = { v: 1, items: [item] } as unknown as PoeRecord;

      const { results } = await runDecrypt(
        record,
        [{ itemIndex: 0, recipientSecretKey: new Uint8Array(32).fill(0x11) }],
        new Uint8Array(16),
      );
      expect(results[0]?.verdict).toBe('wrong-input-shape');
      expect(results[0]?.reason).toBe('WRONG_DECRYPTION_INPUT_SHAPE');
    });
  }
});
