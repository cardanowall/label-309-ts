// Behavioural tests for the passphrase key path: seal/open roundtrip, the
// in-ciphertext commitment gate (verified before any chunk opens), parameter
// binding via the passphrase transcript, and the single generic failure
// contract — plus the pinned cross-SDK conformance vectors (passphrase-n1.json
// and passphrase-negative.json).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { EciesSealedPoeError, type EciesSealedPoeErrorCode } from './errors';
import { passphraseSealedPoeOpen, passphraseSealedPoeSeal } from './passphrase';
import type { PassphraseSealedEnvelope } from './passphrase';
import type { ItemHashes } from './transcript';

// Floor-valued Argon2id params keep the per-test KDF cost bounded while staying
// construction-conformant.
const PARAMS = { m: 65536, t: 3, p: 1 } as const;
const PLAINTEXT = new TextEncoder().encode('passphrase-path plaintext');
const HASHES: ItemHashes = { 'sha2-256': sha256(PLAINTEXT) };
const PASSPHRASE = 'correct horse battery staple';

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

describe('passphrase sealed PoE — seal/open', () => {
  it('roundtrips, with the 32-byte commitment prepended inside the blob', async () => {
    const sealed = await passphraseSealedPoeSeal({
      plaintext: PLAINTEXT,
      hashes: HASHES,
      passphrase: PASSPHRASE,
      salt: fillBytes(0x5a, 16),
      params: PARAMS,
      nonce: fillBytes(0x10, 24),
    });
    // blob = commitment(32) || STREAM (plaintext + one 16-byte tag).
    expect(sealed.blob.length).toBe(32 + PLAINTEXT.length + 16);
    expect(sealed.envelope.scheme).toBe(1);
    expect(sealed.envelope.aead).toBe('chacha20-poly1305-stream64k');
    expect(sealed.envelope.passphrase.alg).toBe('argon2id');

    const opened = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: sealed.blob,
      passphrase: PASSPHRASE,
      hashes: HASHES,
    });
    expect(opened.matched).toBe(true);
    if (opened.matched) expect(opened.plaintext).toEqual(PLAINTEXT);

    // The wrong passphrase is the single generic failure — indistinguishable
    // from a tampered record.
    const wrong = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: sealed.blob,
      passphrase: 'wrong horse battery staple',
      hashes: HASHES,
    });
    expect(wrong.matched).toBe(false);
    if (!wrong.matched) expect(wrong.reason).toBe('TAMPERED_CIPHERTEXT');

    // A flipped commitment header byte fails before any chunk opens, with the
    // same generic failure.
    const flipped = Uint8Array.from(sealed.blob);
    flipped[0]! ^= 0x01;
    const commitFlip = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: flipped,
      passphrase: PASSPHRASE,
      hashes: HASHES,
    });
    expect(commitFlip.matched).toBe(false);
    if (!commitFlip.matched) expect(commitFlip.reason).toBe('TAMPERED_CIPHERTEXT');

    // Tampered Argon2id params: the transcript binds them, so the recomputed
    // commitment differs even though the salt and blob are honest.
    const paramsTampered: PassphraseSealedEnvelope = {
      ...sealed.envelope,
      passphrase: { ...sealed.envelope.passphrase, params: { ...PARAMS, t: PARAMS.t + 1 } },
    };
    const paramFlip = await passphraseSealedPoeOpen({
      envelope: paramsTampered,
      blob: sealed.blob,
      passphrase: PASSPHRASE,
      hashes: HASHES,
    });
    expect(paramFlip.matched).toBe(false);
    if (!paramFlip.matched) expect(paramFlip.reason).toBe('TAMPERED_CIPHERTEXT');

    // A spliced hash claim (same envelope, different item.hashes) fails the
    // commitment check before any chunk opens.
    const spliced = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: sealed.blob,
      passphrase: PASSPHRASE,
      hashes: { 'sha2-256': sha256(new Uint8Array([0x01])) },
    });
    expect(spliced.matched).toBe(false);
    if (!spliced.matched) expect(spliced.reason).toBe('TAMPERED_CIPHERTEXT');

    // A flipped STREAM byte passes the commitment (correct CEK) but fails the
    // chunk tag — still the same generic failure shape.
    const streamFlip = Uint8Array.from(sealed.blob);
    streamFlip[32]! ^= 0x80;
    const tamperedStream = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: streamFlip,
      passphrase: PASSPHRASE,
      hashes: HASHES,
    });
    expect(tamperedStream.matched).toBe(false);
    if (!tamperedStream.matched) expect(tamperedStream.reason).toBe('TAMPERED_CIPHERTEXT');
  }, 120_000);

  it('normalization-equivalent passphrases derive the same CEK (NFKC + whitespace collapse + trim)', async () => {
    const sealed = await passphraseSealedPoeSeal({
      plaintext: PLAINTEXT,
      hashes: HASHES,
      passphrase: 'Á café　 ', // decomposed Á + ideographic space + trailing space
      salt: fillBytes(0x66, 16),
      params: PARAMS,
      nonce: fillBytes(0x11, 24),
    });
    const opened = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: sealed.blob,
      passphrase: 'Á café', // precomposed Á, collapsed/trimmed whitespace
      hashes: HASHES,
    });
    expect(opened.matched).toBe(true);
  }, 120_000);

  it('a blob below the 48-byte floor is the generic failure before any KDF-independent work', async () => {
    const sealed = await passphraseSealedPoeSeal({
      plaintext: new Uint8Array(0),
      hashes: HASHES,
      passphrase: PASSPHRASE,
      salt: fillBytes(0x77, 16),
      params: PARAMS,
      nonce: fillBytes(0x12, 24),
    });
    // Empty plaintext still yields a 48-byte blob (32 commitment + lone tag).
    expect(sealed.blob.length).toBe(48);
    const short = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: sealed.blob.subarray(0, 47),
      passphrase: PASSPHRASE,
      hashes: HASHES,
    });
    expect(short.matched).toBe(false);
    if (!short.matched) expect(short.reason).toBe('TAMPERED_CIPHERTEXT');
  }, 120_000);
});

describe('passphrase sealed PoE — input validation', () => {
  it('rejects a whitespace-only passphrase (ENC_PASSPHRASE_EMPTY) before any KDF work', async () => {
    await expect(
      passphraseSealedPoeSeal({
        plaintext: PLAINTEXT,
        hashes: HASHES,
        passphrase: ' \t 　 ',
        salt: fillBytes(0x01, 16),
        params: PARAMS,
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_EMPTY' });
  });

  it('rejects sub-floor Argon2id params (ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW)', async () => {
    await expect(
      passphraseSealedPoeSeal({
        plaintext: PLAINTEXT,
        hashes: HASHES,
        passphrase: PASSPHRASE,
        salt: fillBytes(0x01, 16),
        params: { m: 8, t: 1, p: 1 },
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW' });
  });

  it('rejects an out-of-range salt (ENC_PASSPHRASE_SALT_TOO_SHORT / _LONG)', async () => {
    await expect(
      passphraseSealedPoeSeal({
        plaintext: PLAINTEXT,
        hashes: HASHES,
        passphrase: PASSPHRASE,
        salt: fillBytes(0x01, 15),
        params: PARAMS,
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_SALT_TOO_SHORT' });
    await expect(
      passphraseSealedPoeSeal({
        plaintext: PLAINTEXT,
        hashes: HASHES,
        passphrase: PASSPHRASE,
        salt: fillBytes(0x01, 65),
        params: PARAMS,
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_SALT_TOO_LONG' });
  });

  it('rejects an empty hashes map (ENC_REQUIRES_CONTENT_HASH)', async () => {
    await expect(
      passphraseSealedPoeSeal({
        plaintext: PLAINTEXT,
        hashes: {},
        passphrase: PASSPHRASE,
        salt: fillBytes(0x01, 16),
        params: PARAMS,
      }),
    ).rejects.toMatchObject({ code: 'ENC_REQUIRES_CONTENT_HASH' });
  });

  it('rejects an unregistered passphrase.alg at open (ENC_PASSPHRASE_ALG_UNSUPPORTED)', async () => {
    const envelope = {
      scheme: 1,
      aead: 'chacha20-poly1305-stream64k',
      nonce: fillBytes(0x13, 24),
      passphrase: { alg: 'scrypt', salt: fillBytes(0x01, 16), params: PARAMS },
    } as unknown as PassphraseSealedEnvelope;
    await expect(
      passphraseSealedPoeOpen({
        envelope,
        blob: new Uint8Array(48),
        passphrase: PASSPHRASE,
        hashes: HASHES,
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_ALG_UNSUPPORTED' });
  });
});

// ---------------------------------------------------------------------------
// Pinned cross-SDK conformance vectors (passphrase-n1.json /
// passphrase-negative.json)
// ---------------------------------------------------------------------------

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../tests/fixtures/sealed-poe',
);

function loadFixture<T>(filename: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as T;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
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

interface PassphraseEnvelopeHex {
  scheme: number;
  aead: string;
  nonce_hex: string;
  passphrase: {
    alg: string;
    salt_hex: string;
    params: { m: number; t: number; p: number };
  };
}

function envelopeFromHex(env: PassphraseEnvelopeHex): PassphraseSealedEnvelope {
  return {
    scheme: env.scheme as 1,
    aead: env.aead as PassphraseSealedEnvelope['aead'],
    nonce: hexToBytes(env.nonce_hex),
    passphrase: {
      alg: env.passphrase.alg as 'argon2id',
      salt: hexToBytes(env.passphrase.salt_hex),
      params: env.passphrase.params,
    },
  };
}

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

describe('passphrase sealed PoE — pinned conformance vector (passphrase-n1.json)', () => {
  it('reproduces the blob byte-for-byte and round-trips it', async () => {
    const { vector } = loadFixture<PassphraseN1Corpus>('passphrase-n1.json');
    const hashes = hashesFromHex(vector.hashes);
    const sealed = await passphraseSealedPoeSeal({
      plaintext: hexToBytes(vector.plaintext_hex),
      hashes,
      passphrase: vector.passphrase,
      salt: hexToBytes(vector.salt_hex),
      params: vector.params,
      nonce: hexToBytes(vector.nonce_hex),
    });
    expect(bytesToHex(sealed.blob.subarray(0, 32))).toBe(vector.expected_commitment_hex);
    expect(bytesToHex(sealed.blob)).toBe(vector.expected_ciphertext_hex);

    const opened = await passphraseSealedPoeOpen({
      envelope: sealed.envelope,
      blob: hexToBytes(vector.expected_ciphertext_hex),
      passphrase: vector.passphrase,
      hashes,
    });
    expect(opened.matched).toBe(true);
    if (opened.matched) {
      expect(bytesToHex(opened.plaintext)).toBe(vector.expected_plaintext_hex);
    }
  });
});

interface PassphraseNegativeMatchedFalse {
  name: string;
  envelope: PassphraseEnvelopeHex;
  ciphertext_hex: string;
  passphrase: string;
  hashes: Record<string, string>;
  expected_reason: string;
}

interface PassphraseNegativeRaise {
  name: string;
  envelope: PassphraseEnvelopeHex;
  ciphertext_hex: string;
  passphrase: string;
  hashes: Record<string, string>;
  expected_error_code: EciesSealedPoeErrorCode;
}

interface PassphraseNegativeCorpus {
  matched_false_vectors: PassphraseNegativeMatchedFalse[];
  raise_vectors: PassphraseNegativeRaise[];
}

describe('passphrase sealed PoE — pinned negatives (passphrase-negative.json)', () => {
  const corpus = loadFixture<PassphraseNegativeCorpus>('passphrase-negative.json');

  for (const v of corpus.matched_false_vectors) {
    it(`fails generically before any chunk opens: ${v.name}`, async () => {
      const result = await passphraseSealedPoeOpen({
        envelope: envelopeFromHex(v.envelope),
        blob: hexToBytes(v.ciphertext_hex),
        passphrase: v.passphrase,
        hashes: hashesFromHex(v.hashes),
      });
      expect(result.matched).toBe(false);
      if (!result.matched) expect(result.reason).toBe(v.expected_reason);
    });
  }

  for (const v of corpus.raise_vectors) {
    it(`raises code=${v.expected_error_code}: ${v.name}`, async () => {
      try {
        await passphraseSealedPoeOpen({
          envelope: envelopeFromHex(v.envelope),
          blob: hexToBytes(v.ciphertext_hex),
          passphrase: v.passphrase,
          hashes: hashesFromHex(v.hashes),
        });
        throw new Error(`${v.name}: expected EciesSealedPoeError, got a structured result`);
      } catch (err) {
        expect(err).toBeInstanceOf(EciesSealedPoeError);
        if (err instanceof EciesSealedPoeError) {
          expect(err.code).toBe(v.expected_error_code);
        }
      }
    });
  }
});
