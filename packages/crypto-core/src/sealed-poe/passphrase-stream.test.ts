// Byte-parity and outcome tests for the streaming passphrase pair
// (`passphraseSealStream` / `passphraseOpenStream`). The streamed blob MUST be
// byte-identical to the buffered `passphraseSealedPoeSeal` for the same
// passphrase / salt / params / nonce / hashes, so these tests use the EXISTING
// pinned vector (`passphrase-n1.json`) and the buffered pair (itself pinned by
// passphrase.test.ts) as the oracle — no new crypto vectors. Source read
// boundaries are NOT STREAM chunk boundaries, so plaintext and blob are fed in
// odd-sized producer chunks that cut across both the 64 KiB grid and the
// 48-byte open lookahead; every failure mode (wrong passphrase, tampered
// header, tampered body, short blob) must surface as the single generic
// rejection, and typed caller-input rejections must mirror the buffered pair's
// pinned order.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import {
  passphraseOpenStream,
  passphraseSealedPoeOpen,
  passphraseSealedPoeSeal,
  passphraseSealStream,
  type PassphraseSealedEnvelope,
} from './passphrase';
import { CHUNK_SIZE } from './stream';
import type { ItemHashes } from './transcript';

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../tests/fixtures/sealed-poe',
);

// Every KDF-running test derives at the registry floors (m=65536, t=3, p=1)
// except the pinned vector (p=4); both are heavyweight in JS, so the
// KDF-running tests carry an explicit generous timeout.
const KDF_TIMEOUT = 120_000;

const PARAMS = { m: 65536, t: 3, p: 1 } as const;
const PASSPHRASE = 'correct horse battery staple';

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

function patterned(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 7 + 3) & 0xff;
  return out;
}

// A producer that hands `bytes` over in fixed-size reads (the source's read
// boundaries, deliberately NOT aligned to the STREAM grid or the 48-byte open
// lookahead). A `readSize` of 0 yields the whole buffer in one read; an empty
// buffer yields nothing at all.
async function* chunkedSource(bytes: Uint8Array, readSize: number): AsyncGenerator<Uint8Array> {
  if (bytes.length === 0) return;
  const step = readSize <= 0 ? bytes.length : readSize;
  for (let off = 0; off < bytes.length; off += step) {
    yield bytes.subarray(off, Math.min(off + step, bytes.length));
  }
}

async function collect(iter: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const part of iter) {
    parts.push(part);
    total += part.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Fixture replay against the pinned passphrase-n1.json vector
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
    expected_ciphertext_hex: string;
    expected_plaintext_hex: string;
  };
}

describe('passphraseSealStream / passphraseOpenStream — pinned vector (passphrase-n1.json)', () => {
  const { vector } = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'passphrase-n1.json'), 'utf8'),
  ) as PassphraseN1Corpus;
  const hashes = hashesFromHex(vector.hashes);
  const plaintext = hexToBytes(vector.plaintext_hex);
  const pinnedBlob = hexToBytes(vector.expected_ciphertext_hex);

  // Odd producer read sizes plus one-shot: none aligns to the STREAM grid.
  for (const readSize of [1, 7, 31, 0]) {
    it(
      `streamed seal at producer reads of ${readSize || 'whole'} equals the pinned blob`,
      async () => {
        const { envelope, blob } = await passphraseSealStream({
          plaintext: chunkedSource(plaintext, readSize),
          hashes,
          passphrase: vector.passphrase,
          salt: hexToBytes(vector.salt_hex),
          params: vector.params,
          nonce: hexToBytes(vector.nonce_hex),
        });
        expect(envelope.passphrase.alg).toBe('argon2id');
        expect(bytesToHex(await collect(blob))).toBe(vector.expected_ciphertext_hex);
      },
      KDF_TIMEOUT,
    );
  }

  // The wire envelope, assembled from the vector's fields exactly as a
  // verifier receives it (no extra KDF run to obtain it).
  const envelope: PassphraseSealedEnvelope = {
    scheme: 1,
    aead: 'chacha20-poly1305-stream64k',
    nonce: hexToBytes(vector.nonce_hex),
    passphrase: {
      alg: 'argon2id',
      salt: hexToBytes(vector.salt_hex),
      params: vector.params,
    },
  };

  // Read sizes 47 and 48 straddle / align to the open's 48-byte lookahead
  // boundary, so the leftover-replay path is driven both ways.
  for (const readSize of [1, 7, 47, 48, 0]) {
    it(
      `streamed open at source reads of ${readSize || 'whole'} recovers the pinned plaintext`,
      async () => {
        const { outcome, plaintext: out } = await passphraseOpenStream({
          envelope,
          blob: chunkedSource(pinnedBlob, readSize),
          passphrase: vector.passphrase,
          hashes,
        });
        const recovered = await collect(out);
        expect(await outcome).toEqual({ matched: true });
        expect(bytesToHex(recovered)).toBe(vector.expected_plaintext_hex);
      },
      KDF_TIMEOUT,
    );
  }
});

// ---------------------------------------------------------------------------
// Streaming equals buffered across the chunk-boundary matrix
// ---------------------------------------------------------------------------

describe('passphraseSealStream — equals the buffered seal across the chunk boundary', () => {
  const salt = fillBytes(0x5a, 16);
  const nonce = fillBytes(0x10, 24);

  const lengths: Array<{ name: string; length: number }> = [
    { name: 'empty', length: 0 },
    { name: '1 byte', length: 1 },
    { name: 'exactly one chunk', length: CHUNK_SIZE },
    { name: 'exactly two chunks', length: 2 * CHUNK_SIZE },
    { name: 'two chunks plus an odd tail', length: 2 * CHUNK_SIZE + 4242 },
  ];
  // Producer read sizes that cut across the 64 KiB grid differently.
  const readSizes = [1, 65537, CHUNK_SIZE];

  for (const { name, length } of lengths) {
    const plaintext = patterned(length);
    const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };

    it(
      `${name} (${length} B): every producer chunking equals the buffered blob, and the streamed open recovers it`,
      async () => {
        const buffered = await passphraseSealedPoeSeal({
          plaintext,
          hashes,
          passphrase: PASSPHRASE,
          salt,
          params: PARAMS,
          nonce,
        });
        for (const readSize of readSizes) {
          const { envelope, blob } = await passphraseSealStream({
            plaintext: chunkedSource(plaintext, readSize),
            hashes,
            passphrase: PASSPHRASE,
            salt,
            params: PARAMS,
            nonce,
          });
          expect(envelope).toEqual(buffered.envelope);
          expect(bytesToHex(await collect(blob))).toBe(bytesToHex(buffered.blob));
        }
        // The streamed open of the buffered blob recovers the plaintext, and
        // agrees with the buffered open (oracle cross-check).
        const { outcome, plaintext: out } = await passphraseOpenStream({
          envelope: buffered.envelope,
          blob: chunkedSource(buffered.blob, 65537),
          passphrase: PASSPHRASE,
          hashes,
        });
        const recovered = await collect(out);
        expect(await outcome).toEqual({ matched: true });
        expect(bytesToHex(recovered)).toBe(bytesToHex(plaintext));
        const bufferedOpen = await passphraseSealedPoeOpen({
          envelope: buffered.envelope,
          blob: buffered.blob,
          passphrase: PASSPHRASE,
          hashes,
        });
        expect(bufferedOpen.matched).toBe(true);
        if (bufferedOpen.matched) {
          expect(bytesToHex(bufferedOpen.plaintext)).toBe(bytesToHex(recovered));
        }
      },
      KDF_TIMEOUT * 5,
    );
  }
});

// ---------------------------------------------------------------------------
// Rejection outcomes — the single generic failure
// ---------------------------------------------------------------------------

describe('passphraseOpenStream — generic rejection outcomes', () => {
  const salt = fillBytes(0x66, 16);
  const nonce = fillBytes(0x11, 24);

  async function sealSmall(
    plaintext: Uint8Array,
    hashes: ItemHashes,
  ): Promise<{ envelope: PassphraseSealedEnvelope; blob: Uint8Array }> {
    return passphraseSealedPoeSeal({
      plaintext,
      hashes,
      passphrase: PASSPHRASE,
      salt,
      params: PARAMS,
      nonce,
    });
  }

  it(
    'a wrong passphrase resolves the rejection with nothing yielded',
    async () => {
      const plaintext = patterned(100);
      const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
      const sealed = await sealSmall(plaintext, hashes);
      const { outcome, plaintext: out } = await passphraseOpenStream({
        envelope: sealed.envelope,
        blob: chunkedSource(sealed.blob, 17),
        passphrase: 'wrong horse battery staple',
        hashes,
      });
      expect(await outcome).toEqual({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
      expect((await collect(out)).length).toBe(0);
    },
    KDF_TIMEOUT,
  );

  it(
    'a flipped commitment-header byte resolves the rejection with nothing yielded',
    async () => {
      const plaintext = patterned(100);
      const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
      const sealed = await sealSmall(plaintext, hashes);
      const tampered = Uint8Array.from(sealed.blob);
      tampered[0]! ^= 0x01;
      const { outcome, plaintext: out } = await passphraseOpenStream({
        envelope: sealed.envelope,
        blob: chunkedSource(tampered, 17),
        passphrase: PASSPHRASE,
        hashes,
      });
      expect(await outcome).toEqual({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
      expect((await collect(out)).length).toBe(0);
    },
    KDF_TIMEOUT,
  );

  it(
    'a flipped final-tag byte settles the rejection mid-body AND throws from the iterable',
    async () => {
      // Spans two chunks so the first chunk opens fine and the tamper hits the
      // final chunk: yielded bytes precede the failure, exactly the case the
      // dual outcome-and-throw contract exists for.
      const plaintext = patterned(CHUNK_SIZE + 33);
      const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
      const sealed = await sealSmall(plaintext, hashes);
      const tampered = Uint8Array.from(sealed.blob);
      tampered[tampered.length - 1]! ^= 0x80;
      const { outcome, plaintext: out } = await passphraseOpenStream({
        envelope: sealed.envelope,
        blob: chunkedSource(tampered, 65537),
        passphrase: PASSPHRASE,
        hashes,
      });
      // Draining the iterable must throw the tamper (a draining consumer
      // cannot mistake it for success)...
      await expect(collect(out)).rejects.toMatchObject({ code: 'TAMPERED_CIPHERTEXT' });
      // ...and the checkable outcome resolves (never rejects) to the same
      // generic rejection.
      expect(await outcome).toEqual({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
    },
    KDF_TIMEOUT,
  );

  it('a source ending below the 48-byte floor rejects without running the KDF', async () => {
    const hashes: ItemHashes = { 'sha2-256': sha256(patterned(10)) };
    // Absurdly expensive (but floor-valid) parameters: if the implementation
    // ran Argon2id before the lookahead floor check, this test would hang or
    // fail on the derivation instead of resolving instantly.
    const envelope: PassphraseSealedEnvelope = {
      scheme: 1,
      aead: 'chacha20-poly1305-stream64k',
      nonce: fillBytes(0x12, 24),
      passphrase: {
        alg: 'argon2id',
        salt: fillBytes(0x13, 16),
        params: { m: 1048576, t: 8, p: 1 },
      },
    };
    const { outcome, plaintext: out } = await passphraseOpenStream({
      envelope,
      blob: chunkedSource(patterned(47), 5),
      passphrase: PASSPHRASE,
      hashes,
    });
    expect(await outcome).toEqual({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
    expect((await collect(out)).length).toBe(0);
  }, 10_000);
});

// ---------------------------------------------------------------------------
// Typed caller-input rejections — mirror the buffered pair's pinned order
// ---------------------------------------------------------------------------

describe('passphraseSealStream / passphraseOpenStream — typed rejections', () => {
  const hashes: ItemHashes = { 'sha2-256': sha256(patterned(10)) };
  const shortBlob = patterned(47);

  function envelope(overrides?: {
    aead?: string;
    params?: { m: number; t: number; p: number };
  }): PassphraseSealedEnvelope {
    return {
      scheme: 1,
      aead: (overrides?.aead ?? 'chacha20-poly1305-stream64k') as PassphraseSealedEnvelope['aead'],
      nonce: fillBytes(0x14, 24),
      passphrase: {
        alg: 'argon2id',
        salt: fillBytes(0x15, 16),
        params: overrides?.params ?? { m: 8, t: 1, p: 1 },
      },
    };
  }

  it('seal rejects a short salt before any plaintext byte is read', async () => {
    let pulled = false;
    // eslint-disable-next-line require-yield -- the assertion is that this body never runs.
    const source = (async function* (): AsyncGenerator<Uint8Array> {
      pulled = true;
      return;
    })();
    await expect(
      passphraseSealStream({
        plaintext: source,
        hashes,
        passphrase: PASSPHRASE,
        salt: fillBytes(0x01, 15),
        params: PARAMS,
        nonce: fillBytes(0x16, 24),
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_SALT_TOO_SHORT' });
    expect(pulled).toBe(false);
  });

  it('seal rejects below-floor params and an empty hashes map in the buffered order', async () => {
    await expect(
      passphraseSealStream({
        plaintext: chunkedSource(patterned(10), 0),
        hashes,
        passphrase: PASSPHRASE,
        salt: fillBytes(0x01, 16),
        params: { m: 8, t: 1, p: 1 },
        nonce: fillBytes(0x16, 24),
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW' });
    // The envelope shape is validated before the hash claim (as on the
    // buffered seal), so with a valid shape the empty hashes map is next.
    await expect(
      passphraseSealStream({
        plaintext: chunkedSource(patterned(10), 0),
        hashes: {},
        passphrase: PASSPHRASE,
        salt: fillBytes(0x01, 16),
        params: PARAMS,
        nonce: fillBytes(0x16, 24),
      }),
    ).rejects.toMatchObject({ code: 'ENC_REQUIRES_CONTENT_HASH' });
  });

  it('open typed rejections fire in the pinned order, all before any blob-dependent work', async () => {
    // Every call carries the SAME short blob: a typed rejection surfacing
    // instead of the generic short-blob rejection proves the precedence.
    const openShort = (input: {
      env: PassphraseSealedEnvelope;
      passphrase: string;
      hashes: ItemHashes;
    }) =>
      passphraseOpenStream({
        envelope: input.env,
        blob: chunkedSource(shortBlob, 5),
        passphrase: input.passphrase,
        hashes: input.hashes,
      });

    // (1) The hash claim is validated before normalization, envelope, blob.
    await expect(
      openShort({ env: envelope({ aead: 'bogus' }), passphrase: ' \t ', hashes: {} }),
    ).rejects.toMatchObject({ code: 'ENC_REQUIRES_CONTENT_HASH' });
    // (2) Normalization is validated before the envelope and the blob.
    await expect(
      openShort({ env: envelope({ aead: 'bogus' }), passphrase: ' \t ', hashes }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_EMPTY' });
    // (3) The aead identifier is validated before the KDF floors and the blob.
    await expect(
      openShort({ env: envelope({ aead: 'bogus' }), passphrase: PASSPHRASE, hashes }),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_AEAD_ALG' });
    // (4) Below-floor params are a typed error even though the blob is also
    // short (the KDF floor precedes the blob floor).
    await expect(
      openShort({ env: envelope(), passphrase: PASSPHRASE, hashes }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW' });
    // (5) With well-formed inputs the short blob is the generic rejection.
    const { outcome } = await openShort({
      env: envelope({ params: PARAMS }),
      passphrase: PASSPHRASE,
      hashes,
    });
    expect(await outcome).toEqual({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
  });
});

// ---------------------------------------------------------------------------
// AbortSignal cancellation at chunk boundaries
// ---------------------------------------------------------------------------

describe('passphraseSealStream / passphraseOpenStream — AbortSignal', () => {
  const salt = fillBytes(0x77, 16);
  const nonce = fillBytes(0x17, 24);

  it('an already-aborted signal rejects the seal before any body byte', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      passphraseSealStream({
        plaintext: chunkedSource(patterned(10), 0),
        hashes: { 'sha2-256': sha256(patterned(10)) },
        passphrase: PASSPHRASE,
        salt,
        params: PARAMS,
        nonce,
        signal: controller.signal,
      }),
    ).rejects.toThrow();
  });

  it('an already-aborted signal rejects the open before the source is pulled', async () => {
    const controller = new AbortController();
    controller.abort();
    let pulled = false;
    // eslint-disable-next-line require-yield -- the assertion is that this body never runs.
    const source = (async function* (): AsyncGenerator<Uint8Array> {
      pulled = true;
      return;
    })();
    await expect(
      passphraseOpenStream({
        envelope: {
          scheme: 1,
          aead: 'chacha20-poly1305-stream64k',
          nonce,
          passphrase: { alg: 'argon2id', salt, params: PARAMS },
        },
        blob: source,
        passphrase: PASSPHRASE,
        hashes: { 'sha2-256': sha256(patterned(10)) },
        signal: controller.signal,
      }),
    ).rejects.toThrow();
    expect(pulled).toBe(false);
  });

  it(
    'aborting mid-body stops the seal stream at the next chunk boundary',
    async () => {
      const controller = new AbortController();
      const plaintext = patterned(3 * CHUNK_SIZE);
      const { blob } = await passphraseSealStream({
        plaintext: chunkedSource(plaintext, CHUNK_SIZE),
        hashes: { 'sha2-256': sha256(plaintext) },
        passphrase: PASSPHRASE,
        salt,
        params: PARAMS,
        nonce,
        signal: controller.signal,
      });
      const iter = blob[Symbol.asyncIterator]();
      // The commitment header and the first sealed chunk drain fine; then
      // abort and the next pull rejects.
      await iter.next();
      await iter.next();
      controller.abort();
      await expect(iter.next()).rejects.toThrow();
    },
    KDF_TIMEOUT,
  );

  it(
    'aborting mid-body stops the open stream at the next chunk boundary',
    async () => {
      const controller = new AbortController();
      const plaintext = patterned(3 * CHUNK_SIZE);
      const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
      const sealed = await passphraseSealedPoeSeal({
        plaintext,
        hashes,
        passphrase: PASSPHRASE,
        salt,
        params: PARAMS,
        nonce,
      });
      const { plaintext: out } = await passphraseOpenStream({
        envelope: sealed.envelope,
        blob: chunkedSource(sealed.blob, CHUNK_SIZE),
        passphrase: PASSPHRASE,
        hashes,
        signal: controller.signal,
      });
      const iter = out[Symbol.asyncIterator]();
      await iter.next();
      controller.abort();
      await expect(iter.next()).rejects.toThrow();
    },
    KDF_TIMEOUT,
  );
});
