// Byte-parity tests for the high-level streaming seal / unwrap wrappers
// (`sealStream` / `unwrapStream`). The streamed output MUST be byte-identical to
// the buffered `eciesSealedPoeWrap` / `eciesSealedPoeUnwrap` path, so these tests
// use the EXISTING pinned vectors (`wrap-*.json`, `unwrap-*.json`) as the oracle
// — no new crypto vectors. The load-bearing proof is R1: source read boundaries
// are NOT STREAM chunk boundaries, so the streamed plaintext is fed in odd-sized
// producer chunks (1 B, 65535, 65537, exact 64 KiB, exact 2×64 KiB) and the
// concatenated ciphertext is asserted against the buffered output. Tampering a
// sealed chunk must surface as TAMPERED_CIPHERTEXT.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { x25519PublicKey } from '../kem/x25519';

import { CHUNK_SIZE } from './stream';
import { sealStream, unwrapStream } from './stream-seal';
import type { ItemHashes } from './transcript';
import { eciesSealedPoeUnwrap } from './unwrap';
import {
  eciesSealedPoeWrap,
  SEALED_POE_AEAD,
  type Mlkem768X25519Slot,
  type SealedEnvelope,
  type X25519Slot,
} from './wrap';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex ${hex.length}`);
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

function patterned(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 7 + 3) & 0xff;
  return out;
}

// A producer that hands `bytes` over in fixed-size reads (the source's read
// boundaries, deliberately NOT aligned to CHUNK_SIZE). A `readSize` of 0 yields
// the whole buffer in one read; an empty buffer yields nothing at all.
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

// The producer read sizes that exercise the R1 EOF-lookahead boundaries: each
// straddles or aligns to CHUNK_SIZE differently, so the re-chunker's pending /
// final-flag logic is driven across every boundary class.
const READ_SIZES = [1, 65535, 65537, CHUNK_SIZE, 2 * CHUNK_SIZE, 0];

// ---------------------------------------------------------------------------
// Seal byte-parity against the pinned wrap-*.json vectors
// ---------------------------------------------------------------------------

interface WrapVector {
  name: string;
  recipient_publics_hex: string[];
  ephemeral_secrets_hex: string[];
  cek_hex: string;
  nonce_hex: string;
  plaintext_hex: string;
  hashes: Record<string, string>;
  expected_slots_mac_hex: string;
  expected_ciphertext_hex: string;
}

function loadWrap(filename: string): WrapVector {
  return (
    JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as { vector: WrapVector }
  ).vector;
}

describe('sealStream — byte-identical ciphertext against pinned wrap vectors', () => {
  for (const file of ['wrap-n1-empty.json', 'wrap-n3.json', 'wrap-n32.json']) {
    const vector = loadWrap(file);
    const plaintext = hexToBytes(vector.plaintext_hex);
    // Feed the same plaintext through the stream in several producer chunkings;
    // every one must reproduce the pinned ciphertext byte-for-byte.
    for (const readSize of READ_SIZES) {
      it(`${vector.name}: producer reads of ${readSize || 'whole'} → pinned ciphertext`, async () => {
        const { envelope, ciphertext } = await sealStream({
          plaintext: chunkedSource(plaintext, readSize),
          recipientPublicKeys: vector.recipient_publics_hex.map(hexToBytes),
          hashes: hashesFromHex(vector.hashes),
          cek: hexToBytes(vector.cek_hex),
          nonce: hexToBytes(vector.nonce_hex),
          ephemeralSecrets: vector.ephemeral_secrets_hex.map(hexToBytes),
          skipShuffle: true,
        });
        // The envelope is resolved up front and matches the buffered wrap.
        expect(envelope.kem).toBe('x25519');
        expect(bytesToHex(envelope.slots_mac)).toBe(vector.expected_slots_mac_hex);
        // The streamed body is byte-identical to the pinned ciphertext.
        expect(bytesToHex(await collect(ciphertext))).toBe(vector.expected_ciphertext_hex);
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Seal byte-parity against the buffered path across the 64 KiB chunk boundary
// (R1). No vector covers a multi-chunk plaintext, so the buffered
// eciesSealedPoeWrap (itself pinned by wrap.kat.test.ts) is the equivalence
// oracle — the standard incremental-vs-whole proof, zero new vectors.
// ---------------------------------------------------------------------------

describe('sealStream — equals the buffered seal across the chunk boundary (R1)', () => {
  // Deterministic envelope inputs so the buffered and streamed seals are fully
  // byte-identical and the only variable is the producer chunking: a fixed CEK,
  // nonce, AND ephemeral secret (otherwise the random epk per call would change
  // the slots_mac even though the body ciphertext, keyed only by CEK+nonce, stays
  // the same).
  const priv = new Uint8Array(32).fill(0x11);
  const recipientPublicKeys = [x25519PublicKey({ secretKey: priv })];
  const cek = new Uint8Array(32).fill(0x22);
  const nonce = new Uint8Array(24).fill(0x33);
  const ephemeralSecrets = [new Uint8Array(32).fill(0x44)];

  const lengths: Array<{ name: string; length: number }> = [
    { name: 'empty', length: 0 },
    { name: '1 byte', length: 1 },
    { name: 'one below the boundary', length: CHUNK_SIZE - 1 },
    { name: 'exactly one chunk', length: CHUNK_SIZE },
    { name: 'one over the boundary', length: CHUNK_SIZE + 1 },
    { name: 'exactly two chunks', length: 2 * CHUNK_SIZE },
    { name: 'two chunks plus a tail', length: 2 * CHUNK_SIZE + 777 },
  ];

  for (const { name, length } of lengths) {
    const plaintext = patterned(length);
    const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
    const buffered = eciesSealedPoeWrap({
      plaintext,
      hashes,
      recipientPublicKeys,
      cek,
      nonce,
      ephemeralSecrets,
      skipShuffle: true,
    });
    for (const readSize of READ_SIZES) {
      it(`${name} (${length} B), producer reads of ${readSize || 'whole'}`, async () => {
        const { envelope, ciphertext } = await sealStream({
          plaintext: chunkedSource(plaintext, readSize),
          recipientPublicKeys,
          hashes,
          cek,
          nonce,
          ephemeralSecrets,
          skipShuffle: true,
        });
        expect(bytesToHex(envelope.slots_mac)).toBe(bytesToHex(buffered.envelope.slots_mac));
        expect(bytesToHex(await collect(ciphertext))).toBe(bytesToHex(buffered.ciphertext));
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Unwrap byte-parity against the pinned unwrap-*.json vectors
// ---------------------------------------------------------------------------

interface SlotHex {
  epk_hex?: string;
  kem_ct_hex?: string;
  wrap_hex: string;
}

interface EnvelopeHex {
  scheme: number;
  aead: string;
  kem: string;
  nonce_hex: string;
  slots: SlotHex[];
  slots_mac_hex: string;
}

interface UnwrapVector {
  name: string;
  recipient_secrets_hex: string[];
  hashes: Record<string, string>;
  envelope: EnvelopeHex;
  ciphertext_hex: string;
  expected_plaintext_hex: string;
}

function loadUnwrap(filename: string): UnwrapVector {
  return (
    JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as {
      vector: UnwrapVector;
    }
  ).vector;
}

function envelopeFromHex(env: EnvelopeHex): SealedEnvelope {
  if (env.kem === 'mlkem768x25519') {
    const slots: Mlkem768X25519Slot[] = env.slots.map((s) => ({
      kem_ct: hexToBytes(s.kem_ct_hex ?? ''),
      wrap: hexToBytes(s.wrap_hex),
    }));
    return {
      scheme: env.scheme as 1,
      aead: env.aead as typeof SEALED_POE_AEAD,
      kem: 'mlkem768x25519',
      nonce: hexToBytes(env.nonce_hex),
      slots,
      slots_mac: hexToBytes(env.slots_mac_hex),
    };
  }
  const slots: X25519Slot[] = env.slots.map((s) => ({
    epk: hexToBytes(s.epk_hex ?? ''),
    wrap: hexToBytes(s.wrap_hex),
  }));
  return {
    scheme: env.scheme as 1,
    aead: env.aead as typeof SEALED_POE_AEAD,
    kem: 'x25519',
    nonce: hexToBytes(env.nonce_hex),
    slots,
    slots_mac: hexToBytes(env.slots_mac_hex),
  };
}

describe('unwrapStream — byte-identical plaintext against pinned unwrap vectors', () => {
  for (const file of ['unwrap-n1-empty.json', 'unwrap-n3.json', 'unwrap-n32.json']) {
    const vector = loadUnwrap(file);
    const envelope = envelopeFromHex(vector.envelope);
    const ciphertext = hexToBytes(vector.ciphertext_hex);
    const hashes = hashesFromHex(vector.hashes);
    const recipientSecretKey = hexToBytes(vector.recipient_secrets_hex[0]!);
    for (const readSize of READ_SIZES) {
      it(`${vector.name}: ciphertext reads of ${readSize || 'whole'} → pinned plaintext`, async () => {
        const { outcome, plaintext } = unwrapStream({
          envelope,
          ciphertext: chunkedSource(ciphertext, readSize),
          hashes,
          keys: { recipientSecretKey },
        });
        const recovered = await collect(plaintext);
        expect(await outcome).toEqual({ matched: true });
        expect(bytesToHex(recovered)).toBe(vector.expected_plaintext_hex);
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Unwrap byte-parity against the buffered path across the chunk boundary (R1)
// ---------------------------------------------------------------------------

describe('unwrapStream — equals the buffered unwrap across the chunk boundary (R1)', () => {
  const priv = new Uint8Array(32).fill(0x44);
  const recipientPublicKeys = [x25519PublicKey({ secretKey: priv })];

  const lengths = [
    0,
    1,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 5,
  ];
  for (const length of lengths) {
    const plaintext = patterned(length);
    const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
    const sealed = eciesSealedPoeWrap({
      plaintext,
      hashes,
      recipientPublicKeys,
      skipShuffle: true,
    });
    for (const readSize of READ_SIZES) {
      it(`${length} B, ciphertext reads of ${readSize || 'whole'}`, async () => {
        const { outcome, plaintext: out } = unwrapStream({
          envelope: sealed.envelope,
          ciphertext: chunkedSource(sealed.ciphertext, readSize),
          hashes,
          keys: { recipientSecretKey: priv },
        });
        const recovered = await collect(out);
        expect(await outcome).toEqual({ matched: true });
        expect(bytesToHex(recovered)).toBe(bytesToHex(plaintext));
        // And the buffered unwrap recovers the same bytes (oracle cross-check).
        const buffered = eciesSealedPoeUnwrap({
          envelope: sealed.envelope,
          ciphertext: sealed.ciphertext,
          hashes,
          recipientSecretKey: priv,
        });
        expect(buffered.matched).toBe(true);
        if (buffered.matched) expect(bytesToHex(buffered.plaintext)).toBe(bytesToHex(recovered));
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Tamper + wrong-key outcomes
// ---------------------------------------------------------------------------

describe('unwrapStream — tamper and wrong-key outcomes', () => {
  const priv = new Uint8Array(32).fill(0x55);
  const recipientPublicKeys = [x25519PublicKey({ secretKey: priv })];
  const plaintext = patterned(CHUNK_SIZE + 100); // spans two chunks
  const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
  const sealed = eciesSealedPoeWrap({ plaintext, hashes, recipientPublicKeys, skipShuffle: true });

  it('a flipped sealed byte resolves outcome=TAMPERED_CIPHERTEXT and throws from the iterable', async () => {
    const tampered = Uint8Array.from(sealed.ciphertext);
    tampered[3]! ^= 0x80; // ciphertext byte in the first chunk
    const { outcome, plaintext: out } = unwrapStream({
      envelope: sealed.envelope,
      ciphertext: chunkedSource(tampered, 0),
      hashes,
      keys: { recipientSecretKey: priv },
    });
    // Draining the iterable must throw the tamper (a draining consumer cannot
    // mistake it for success)...
    await expect(collect(out)).rejects.toMatchObject({ code: 'TAMPERED_CIPHERTEXT' });
    // ...and the checkable outcome resolves (never rejects) to the same verdict.
    expect(await outcome).toEqual({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
  });

  it('truncation that drops the final chunk resolves TAMPERED_CIPHERTEXT', async () => {
    const truncated = sealed.ciphertext.subarray(0, CHUNK_SIZE + 16); // keep only the first sealed chunk
    const { outcome, plaintext: out } = unwrapStream({
      envelope: sealed.envelope,
      ciphertext: chunkedSource(truncated, 12345),
      hashes,
      keys: { recipientSecretKey: priv },
    });
    await expect(collect(out)).rejects.toMatchObject({ code: 'TAMPERED_CIPHERTEXT' });
    expect(await outcome).toEqual({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
  });

  it('a wrong recipient key resolves WRONG_RECIPIENT_KEY and yields no plaintext', async () => {
    const wrongPriv = new Uint8Array(32).fill(0x66);
    const { outcome, plaintext: out } = unwrapStream({
      envelope: sealed.envelope,
      ciphertext: chunkedSource(sealed.ciphertext, 0),
      hashes,
      keys: { recipientSecretKey: wrongPriv },
    });
    const recovered = await collect(out);
    expect(recovered.length).toBe(0);
    expect(await outcome).toEqual({ matched: false, reason: 'WRONG_RECIPIENT_KEY' });
  });
});

// ---------------------------------------------------------------------------
// Key-form parity: single / multi / bundle all drive the same selection
// ---------------------------------------------------------------------------

describe('unwrapStream — accepts the single / multi / bundle key forms', () => {
  const priv = new Uint8Array(32).fill(0x77);
  const recipientPublicKeys = [x25519PublicKey({ secretKey: priv })];
  const plaintext = patterned(200);
  const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
  const sealed = eciesSealedPoeWrap({ plaintext, hashes, recipientPublicKeys, skipShuffle: true });

  it('the flat multi-priv chain recovers the plaintext', async () => {
    const { outcome, plaintext: out } = unwrapStream({
      envelope: sealed.envelope,
      ciphertext: chunkedSource(sealed.ciphertext, 0),
      hashes,
      keys: { recipientSecretKeys: [priv] },
    });
    expect(bytesToHex(await collect(out))).toBe(bytesToHex(plaintext));
    expect(await outcome).toEqual({ matched: true });
  });

  it('the recipient key bundle (X25519 list) recovers the plaintext', async () => {
    const { outcome, plaintext: out } = unwrapStream({
      envelope: sealed.envelope,
      ciphertext: chunkedSource(sealed.ciphertext, 0),
      hashes,
      keys: { recipientKeyBundle: { x25519PrivateKeys: [priv], mlkem768x25519SecretSeeds: [] } },
    });
    expect(bytesToHex(await collect(out))).toBe(bytesToHex(plaintext));
    expect(await outcome).toEqual({ matched: true });
  });
});

// ---------------------------------------------------------------------------
// AbortSignal cancellation
// ---------------------------------------------------------------------------

describe('sealStream / unwrapStream — AbortSignal', () => {
  it('an already-aborted signal rejects the seal before any body byte', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      sealStream({
        plaintext: chunkedSource(patterned(10), 0),
        recipientPublicKeys: [x25519PublicKey({ secretKey: new Uint8Array(32).fill(0x01) })],
        hashes: { 'sha2-256': sha256(patterned(10)) },
        signal: controller.signal,
      }),
    ).rejects.toThrow();
  });

  it('aborting mid-body stops the seal stream', async () => {
    const controller = new AbortController();
    const recipientPublicKeys = [x25519PublicKey({ secretKey: new Uint8Array(32).fill(0x02) })];
    const plaintext = patterned(3 * CHUNK_SIZE);
    const { ciphertext } = await sealStream({
      plaintext: chunkedSource(plaintext, CHUNK_SIZE),
      recipientPublicKeys,
      hashes: { 'sha2-256': sha256(plaintext) },
      signal: controller.signal,
    });
    const iter = ciphertext[Symbol.asyncIterator]();
    // First chunk drains fine; then abort and the next pull rejects.
    await iter.next();
    controller.abort();
    await expect(iter.next()).rejects.toThrow();
  });
});
