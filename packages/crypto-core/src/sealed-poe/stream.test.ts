// Behavioural tests for the chacha20-poly1305-stream64k chunk machine: layout
// math, the final-flag truncation detector, and the rejection of every
// malformed-stream class (truncation, trailing data, short non-final chunk,
// zero-length final chunk on a non-empty stream, flipped tag) — plus the
// pinned cross-SDK chunk-layout conformance vectors (stream-layout.json).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  CHUNK_SIZE,
  StreamOpener,
  StreamSealer,
  StreamTamperedError,
  streamOpen,
  streamSeal,
  streamSealedLength,
  TAG_SIZE,
} from './stream';

const KEY = new Uint8Array(32).fill(0x42);
const SEALED_CHUNK = CHUNK_SIZE + TAG_SIZE;

function patterned(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 7 + 3) & 0xff;
  return out;
}

function roundtrip(plaintext: Uint8Array): Uint8Array {
  const sealed = streamSeal({ payloadKey: KEY, plaintext });
  return streamOpen({ payloadKey: KEY, ciphertext: sealed });
}

describe('stream64k — pinned constants', () => {
  it('CHUNK_SIZE is 65536 and TAG_SIZE is 16', () => {
    expect(CHUNK_SIZE).toBe(65536);
    expect(TAG_SIZE).toBe(16);
  });
});

describe('stream64k — layout roundtrips across the chunk boundary', () => {
  const cases: Array<{ name: string; length: number; sealedLength: number }> = [
    // Empty plaintext: exactly one zero-length final chunk — a lone tag.
    { name: 'empty', length: 0, sealedLength: TAG_SIZE },
    { name: '1 byte', length: 1, sealedLength: 1 + TAG_SIZE },
    {
      name: 'one byte below the boundary',
      length: CHUNK_SIZE - 1,
      sealedLength: CHUNK_SIZE - 1 + TAG_SIZE,
    },
    // Exactly one full chunk: a single FINAL full chunk, never a full chunk
    // plus an empty final.
    { name: 'exactly one chunk', length: CHUNK_SIZE, sealedLength: SEALED_CHUNK },
    {
      name: 'one byte over the boundary',
      length: CHUNK_SIZE + 1,
      sealedLength: SEALED_CHUNK + 1 + TAG_SIZE,
    },
    { name: 'two full chunks', length: 2 * CHUNK_SIZE, sealedLength: 2 * SEALED_CHUNK },
    {
      name: 'two chunks plus tail',
      length: 2 * CHUNK_SIZE + 5,
      sealedLength: 2 * SEALED_CHUNK + 5 + TAG_SIZE,
    },
  ];
  for (const c of cases) {
    it(`roundtrips ${c.name} (${c.length} bytes → ${c.sealedLength} sealed bytes)`, () => {
      const plaintext = patterned(c.length);
      const sealed = streamSeal({ payloadKey: KEY, plaintext });
      expect(sealed.length).toBe(c.sealedLength);
      expect(streamOpen({ payloadKey: KEY, ciphertext: sealed })).toEqual(plaintext);
    });
  }

  it('streamSealedLength predicts the exact sealed length for every layout case', () => {
    for (const c of cases) {
      expect(streamSealedLength(c.length)).toBe(c.sealedLength);
      // The prediction is the inverse of the real seal: assert against the
      // actually-emitted ciphertext, not just the table value.
      const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(c.length) });
      expect(streamSealedLength(c.length)).toBe(sealed.length);
    }
  });

  it('streamSealedLength rejects negative and non-integer lengths', () => {
    expect(() => streamSealedLength(-1)).toThrowError(/non-negative integer/);
    expect(() => streamSealedLength(1.5)).toThrowError(/non-negative integer/);
  });

  it('chunks are nonce-domain-separated: two equal plaintext chunks seal to different bytes', () => {
    const plaintext = new Uint8Array(2 * CHUNK_SIZE); // both chunks all-zero
    const sealed = streamSeal({ payloadKey: KEY, plaintext });
    const chunk0 = sealed.subarray(0, SEALED_CHUNK);
    const chunk1 = sealed.subarray(SEALED_CHUNK);
    expect(Buffer.from(chunk0).equals(Buffer.from(chunk1))).toBe(false);
  });
});

describe('stream64k — tampering and layout violations', () => {
  it('rejects a flipped tag byte in the first chunk', () => {
    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(CHUNK_SIZE + 10) });
    const tampered = Uint8Array.from(sealed);
    tampered[CHUNK_SIZE + TAG_SIZE - 1]! ^= 0x01; // last tag byte of chunk 0
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: tampered })).toThrowError(
      StreamTamperedError,
    );
  });

  it('rejects a flipped ciphertext byte in the final chunk', () => {
    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(40) });
    const tampered = Uint8Array.from(sealed);
    tampered[3]! ^= 0x80;
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: tampered })).toThrowError(
      StreamTamperedError,
    );
  });

  it('rejects truncation that removes the final chunk (full-chunk prefix)', () => {
    // Two full chunks; cut the second. The remaining bytes parse as a single
    // FINAL chunk, but chunk 0 was sealed with the 0x00 flag, so the 0x01-flag
    // nonce fails its tag — the final-flag byte is the truncation detector.
    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(2 * CHUNK_SIZE) });
    const truncated = sealed.subarray(0, SEALED_CHUNK);
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: truncated })).toThrowError(
      StreamTamperedError,
    );
  });

  it('rejects truncation inside the final chunk', () => {
    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(100) });
    const truncated = sealed.subarray(0, sealed.length - 1);
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: truncated })).toThrowError(
      StreamTamperedError,
    );
  });

  it('rejects trailing bytes appended after the final chunk', () => {
    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(100) });
    const trailing = new Uint8Array(sealed.length + TAG_SIZE);
    trailing.set(sealed, 0);
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: trailing })).toThrowError(
      StreamTamperedError,
    );
  });

  it('rejects a blob below the single-tag floor', () => {
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: new Uint8Array(0) })).toThrowError(
      StreamTamperedError,
    );
    expect(() =>
      streamOpen({ payloadKey: KEY, ciphertext: new Uint8Array(TAG_SIZE - 1) }),
    ).toThrowError(StreamTamperedError);
  });

  it('rejects a tail that cannot form a well-formed final chunk', () => {
    // One full sealed chunk plus a sub-tag-size tail.
    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(CHUNK_SIZE) });
    const malformed = new Uint8Array(sealed.length + TAG_SIZE - 1);
    malformed.set(sealed, 0);
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: malformed })).toThrowError(
      StreamTamperedError,
    );
  });

  it('rejects a zero-length final chunk on a non-empty stream', () => {
    // Forge the layout: a full sealed chunk followed by a lone-tag final chunk.
    // The blob length itself is the violation — rejected before any tag check.
    const blob = new Uint8Array(SEALED_CHUNK + TAG_SIZE);
    expect(() => streamOpen({ payloadKey: KEY, ciphertext: blob })).toThrowError(
      /zero-length final chunk/,
    );
  });

  it('rejects a non-final short chunk in incremental open', () => {
    const opener = new StreamOpener(KEY);
    expect(() => opener.openChunk(new Uint8Array(SEALED_CHUNK - 1), false)).toThrowError(
      StreamTamperedError,
    );
  });

  it('fails under a different payload key', () => {
    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(10) });
    const otherKey = new Uint8Array(32).fill(0x43);
    expect(() => streamOpen({ payloadKey: otherKey, ciphertext: sealed })).toThrowError(
      StreamTamperedError,
    );
  });
});

describe('stream64k — incremental chunk machine', () => {
  it('incremental seal matches the whole-buffer helper byte-for-byte', () => {
    const plaintext = patterned(CHUNK_SIZE + 123);
    const sealer = new StreamSealer(KEY);
    const c0 = sealer.sealChunk(plaintext.subarray(0, CHUNK_SIZE), false);
    const c1 = sealer.sealChunk(plaintext.subarray(CHUNK_SIZE), true);
    const incremental = new Uint8Array(c0.length + c1.length);
    incremental.set(c0, 0);
    incremental.set(c1, c0.length);
    expect(incremental).toEqual(streamSeal({ payloadKey: KEY, plaintext }));
  });

  it('incremental open releases each chunk only after its tag verifies', () => {
    const plaintext = patterned(CHUNK_SIZE + 9);
    const sealed = streamSeal({ payloadKey: KEY, plaintext });
    const opener = new StreamOpener(KEY);
    const p0 = opener.openChunk(sealed.subarray(0, SEALED_CHUNK), false);
    expect(p0).toEqual(plaintext.subarray(0, CHUNK_SIZE));
    const p1 = opener.openChunk(sealed.subarray(SEALED_CHUNK), true);
    expect(p1).toEqual(plaintext.subarray(CHUNK_SIZE));
  });

  it('refuses chunks after the final chunk (seal and open)', () => {
    const sealer = new StreamSealer(KEY);
    sealer.sealChunk(new Uint8Array(3), true);
    expect(() => sealer.sealChunk(new Uint8Array(3), true)).toThrowError(/final/);

    const sealed = streamSeal({ payloadKey: KEY, plaintext: patterned(3) });
    const opener = new StreamOpener(KEY);
    opener.openChunk(sealed, true);
    expect(() => opener.openChunk(sealed, true)).toThrowError(/final/);
  });

  it('refuses a short non-final chunk at seal time (producer misuse)', () => {
    const sealer = new StreamSealer(KEY);
    expect(() => sealer.sealChunk(new Uint8Array(CHUNK_SIZE - 1), false)).toThrowError(
      /non-final chunk/,
    );
  });

  it('refuses a zero-length final chunk after data at seal time', () => {
    const sealer = new StreamSealer(KEY);
    sealer.sealChunk(new Uint8Array(CHUNK_SIZE), false);
    expect(() => sealer.sealChunk(new Uint8Array(0), true)).toThrowError(/zero-length/);
  });
});

describe('stream64k — large-payload sanity', () => {
  it('roundtrips a payload spanning several chunks with content intact', () => {
    const plaintext = patterned(3 * CHUNK_SIZE + 7777);
    expect(roundtrip(plaintext)).toEqual(plaintext);
  });
});

// ---------------------------------------------------------------------------
// stream-layout.json — pinned cross-SDK conformance vectors
// ---------------------------------------------------------------------------

interface StreamLayoutPositive {
  name: string;
  plaintext_hex: string;
  expected_ciphertext_hex: string;
}

interface StreamLayoutTransform {
  kind: 'flip_byte' | 'truncate_to' | 'append_hex' | 'remove';
  offset?: number;
  length?: number;
  bytes_hex?: string;
}

interface StreamLayoutNegative {
  name: string;
  base: string;
  transforms: StreamLayoutTransform[];
  expected_error_code: string;
}

interface StreamLayoutCorpus {
  payload_key_hex: string;
  positive_vectors: StreamLayoutPositive[];
  negative_vectors: StreamLayoutNegative[];
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

function applyTransforms(base: Uint8Array, transforms: StreamLayoutTransform[]): Uint8Array {
  let out = base;
  for (const transform of transforms) {
    switch (transform.kind) {
      case 'flip_byte': {
        const mutated = Uint8Array.from(out);
        mutated[transform.offset!] = mutated[transform.offset!]! ^ 0x01;
        out = mutated;
        break;
      }
      case 'truncate_to':
        out = out.subarray(0, transform.length!);
        break;
      case 'append_hex': {
        const extra = hexToBytes(transform.bytes_hex!);
        const appended = new Uint8Array(out.length + extra.length);
        appended.set(out, 0);
        appended.set(extra, out.length);
        out = appended;
        break;
      }
      case 'remove': {
        const removed = new Uint8Array(out.length - transform.length!);
        removed.set(out.subarray(0, transform.offset!), 0);
        removed.set(out.subarray(transform.offset! + transform.length!), transform.offset!);
        out = removed;
        break;
      }
    }
  }
  return out;
}

describe('stream64k — pinned conformance vectors (stream-layout.json)', () => {
  const fixturesDir = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../tests/fixtures/sealed-poe',
  );
  const corpus = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'stream-layout.json'), 'utf8'),
  ) as StreamLayoutCorpus;
  const payloadKey = hexToBytes(corpus.payload_key_hex);
  // Sealed eagerly so the negative transforms below never depend on test
  // execution order.
  const sealedByName = new Map<string, Uint8Array>(
    corpus.positive_vectors.map((v) => [
      v.name,
      streamSeal({ payloadKey, plaintext: hexToBytes(v.plaintext_hex) }),
    ]),
  );

  for (const v of corpus.positive_vectors) {
    it(`seals and opens byte-identically: ${v.name}`, () => {
      const sealed = sealedByName.get(v.name)!;
      expect(bytesToHex(sealed)).toBe(v.expected_ciphertext_hex);
      expect(bytesToHex(streamOpen({ payloadKey, ciphertext: sealed }))).toBe(v.plaintext_hex);
    });
  }

  for (const v of corpus.negative_vectors) {
    it(`rejects the ${v.transforms.map((t) => t.kind).join('+')} transform: ${v.name}`, () => {
      expect(v.expected_error_code).toBe('TAMPERED_CIPHERTEXT');
      const base = sealedByName.get(v.base);
      if (base === undefined) throw new Error(`negative base ${v.base} not sealed`);
      const mutated = applyTransforms(base, v.transforms);
      expect(() => streamOpen({ payloadKey, ciphertext: mutated })).toThrowError(
        StreamTamperedError,
      );
    });
  }
});
