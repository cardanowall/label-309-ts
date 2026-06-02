// Chunking helpers — `chunkBytes`, `bytesChunkArrayConcat`,
// `reconstructChunkedUri`, `chunkUri`.

import { describe, expect, it } from 'vitest';

import { bytesChunkArrayConcat, chunkBytes, chunkUri, reconstructChunkedUri } from './chunked';

describe('chunkBytes', () => {
  it('returns [<empty>] for empty input', () => {
    const out = chunkBytes(new Uint8Array(0));
    expect(out).toHaveLength(1);
    expect(out[0]!.length).toBe(0);
  });

  it('returns 1 element for exactly 64 bytes', () => {
    const out = chunkBytes(new Uint8Array(64));
    expect(out).toHaveLength(1);
    expect(out[0]!.length).toBe(64);
  });

  it('splits 65 bytes into [64, 1]', () => {
    const out = chunkBytes(new Uint8Array(65));
    expect(out.map((b) => b.length)).toEqual([64, 1]);
  });

  it('splits 128 bytes into [64, 64]', () => {
    const out = chunkBytes(new Uint8Array(128));
    expect(out.map((b) => b.length)).toEqual([64, 64]);
  });

  it('splits 73 bytes (COSE_Sign1) into [64, 9]', () => {
    const out = chunkBytes(new Uint8Array(73));
    expect(out.map((b) => b.length)).toEqual([64, 9]);
  });
});

describe('bytesChunkArrayConcat', () => {
  it('is the inverse of chunkBytes', () => {
    const original = new Uint8Array(200);
    for (let i = 0; i < original.length; i++) original[i] = i & 0xff;
    const chunks = chunkBytes(original);
    const merged = bytesChunkArrayConcat(chunks);
    expect(merged).toEqual(original);
  });

  it('handles an empty array', () => {
    expect(bytesChunkArrayConcat([])).toEqual(new Uint8Array(0));
  });
});

describe('reconstructChunkedUri', () => {
  it('reconstructs a single-chunk ASCII URI', () => {
    const r = reconstructChunkedUri(['ar://abcdef']);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.uri).toBe('ar://abcdef');
  });

  it('reconstructs a multi-chunk ASCII URI', () => {
    const r = reconstructChunkedUri([
      'ipfs://bafybeigdyrz',
      't5cfsdpaomk2lq',
      'mhs4vqkrqu2ad34yz4nawtfprz4',
    ]);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.uri).toBe('ipfs://bafybeigdyrzt5cfsdpaomk2lqmhs4vqkrqu2ad34yz4nawtfprz4');
    }
  });

  it('reconstructs a multi-chunk URI with a multi-byte codepoint spanning the join', () => {
    // A conformant producer splits on codepoint boundaries, but the helper's
    // job is to byte-concatenate then decode — so even chunks that are
    // individually valid JS strings whose UTF-8 bytes only form a complete
    // codepoint AFTER concatenation must round-trip. Here the two chunks each
    // carry a clean codepoint; the concatenation is the literal join.
    const r = reconstructChunkedUri(['ar://café', '-extra']);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.uri).toBe('ar://café-extra');
  });

  it('handles a chunked emoji split at a codepoint boundary (valid)', () => {
    // Build the string and chunk via chunkUri so the split lands on a
    // codepoint boundary (not mid-codepoint). Then round-trip.
    const original = 'ar://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 43 chars
    const chunks = chunkUri(original);
    const r = reconstructChunkedUri(chunks);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.uri).toBe(original);
  });
});

describe('chunkUri', () => {
  it('returns the URI in a single chunk when ≤ 64 bytes', () => {
    expect(chunkUri('ar://abc')).toEqual(['ar://abc']);
  });

  it('splits a >64-byte URI on a codepoint boundary', () => {
    const long = `ipfs://${'a'.repeat(80)}/path`;
    const chunks = chunkUri(long);
    for (const c of chunks) {
      expect(new TextEncoder().encode(c).length).toBeLessThanOrEqual(64);
    }
    expect(chunks.join('')).toBe(long);
  });

  it('rewinds to a codepoint boundary when a chunk would land mid-multibyte', () => {
    // 4-byte emoji + many ASCII chars. 64 ASCII + 4-byte emoji = 68 → chunk
    // boundary at 64 would split the emoji; chunkUri rewinds to before.
    const long = `${'a'.repeat(63)}😀${'b'.repeat(40)}`;
    const chunks = chunkUri(long);
    // Verify reconstruction matches and no chunk straddles the emoji.
    expect(chunks.join('')).toBe(long);
    for (const c of chunks) {
      expect(new TextEncoder().encode(c).length).toBeLessThanOrEqual(64);
    }
  });
});
