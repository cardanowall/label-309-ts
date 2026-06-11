// Behaviour tests for the runtime-neutral resumable upload source adapters.
//
// The load-bearing concern here is the filesystem-path source: a positional
// read may legitimately return fewer bytes than requested (a short read), and
// emitting a short chunk for a non-final index would corrupt the assembled file
// because the gateway writes each chunk at its deterministic offset. The slice
// reader must therefore loop until the requested range is filled (or real EOF).

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { toResumableSource } from './resumable-source';

describe('in-memory bytes source', () => {
  it('slices the requested byte range', async () => {
    const source = await toResumableSource(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]));
    expect(source.size).toBe(8);
    expect(Array.from(await source.slice(2, 5))).toEqual([2, 3, 4]);
  });

  it('streams the whole input', async () => {
    const source = await toResumableSource(new Uint8Array(3).fill(0x42));
    const seen: number[] = [];
    for await (const part of source.stream()) seen.push(...part);
    expect(seen).toEqual([0x42, 0x42, 0x42]);
  });
});

describe('browser-safety — node:fs is loaded lazily, only for path sources', () => {
  // This package is browser-safe: it carries no top-level `node:` import, and the
  // only branch that touches `node:fs/promises` (a filesystem path) loads it
  // lazily at use time. A browser caller passes a Blob/File or Uint8Array and
  // must never trigger that load.

  // Part 1: the browser-shaped sources (Blob, Uint8Array) work end to end with
  // the real module — no node:fs is needed for them at all.
  it('a Blob source slices and streams without any filesystem involvement', async () => {
    const blob = new Blob([new Uint8Array([1, 2, 3, 4])]);
    const source = await toResumableSource(blob);
    expect(source.size).toBe(4);
    expect(Array.from(await source.slice(0, 2))).toEqual([1, 2]);
    const seen: number[] = [];
    for await (const part of source.stream()) seen.push(...part);
    expect(seen).toEqual([1, 2, 3, 4]);
  });

  it('a Uint8Array source slices and streams without any filesystem involvement', async () => {
    const source = await toResumableSource(new Uint8Array([10, 20, 30, 40, 50]));
    expect(source.size).toBe(5);
    expect(Array.from(await source.slice(1, 4))).toEqual([20, 30, 40]);
    const seen: number[] = [];
    for await (const part of source.stream()) seen.push(...part);
    expect(seen).toEqual([10, 20, 30, 40, 50]);
  });

  // Part 2: instrument the lazy node:fs loader. With `open` mocked as a counting
  // spy, a Uint8Array source must NOT reach it, while a path source MUST — proving
  // the node dependency is lazy and exercised only by the filesystem branch.
  describe('lazy node:fs loader is reached only by path sources', () => {
    afterEach(() => {
      vi.restoreAllMocks();
      vi.doUnmock('node:fs/promises');
      vi.resetModules();
    });

    async function freshWithOpenSpy(): Promise<{
      toResumableSource: typeof toResumableSource;
      openCalls: () => number;
    }> {
      vi.resetModules();
      const realFs = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
      let openCalls = 0;
      vi.doMock('node:fs/promises', () => ({
        ...realFs,
        open: (...args: Parameters<typeof realFs.open>) => {
          openCalls++;
          return realFs.open(...args);
        },
      }));
      const mod = await import('./resumable-source');
      return { toResumableSource: mod.toResumableSource, openCalls: () => openCalls };
    }

    it('a Uint8Array source never opens a node:fs handle', async () => {
      const { toResumableSource: fresh, openCalls } = await freshWithOpenSpy();
      const source = await fresh(new Uint8Array([7, 7, 7, 7]));
      expect(source.size).toBe(4);
      expect(Array.from(await source.slice(1, 3))).toEqual([7, 7]);
      const seen: number[] = [];
      for await (const part of source.stream()) seen.push(...part);
      expect(seen).toEqual([7, 7, 7, 7]);
      // No filesystem handle was ever opened for an in-memory source.
      expect(openCalls()).toBe(0);
    });

    it('a path source opens a node:fs handle (control)', async () => {
      const { toResumableSource: fresh, openCalls } = await freshWithOpenSpy();
      const dir = mkdtempSync(join(tmpdir(), 'resumable-source-lazy-'));
      const path = join(dir, 'content.bin');
      writeFileSync(path, new Uint8Array([9, 8, 7]));
      try {
        const source = await fresh(path);
        expect(source.size).toBe(3);
        // The path branch is the one place that loads node:fs and opens a handle.
        expect(openCalls()).toBeGreaterThan(0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});

describe('filesystem-path source — short read handling', () => {
  let dir: string;
  let path: string;
  const FILE = new Uint8Array(48);
  for (let i = 0; i < FILE.length; i++) FILE[i] = (i * 5) & 0xff;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'resumable-source-'));
    path = join(dir, 'content.bin');
    writeFileSync(path, FILE);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('node:fs/promises');
    vi.resetModules();
    rmSync(dir, { recursive: true, force: true });
  });

  it('loops the positional read so a short read never yields a truncated chunk', async () => {
    // Wrap node:fs/promises so every handle.read of a non-trivial slice returns
    // at most a few bytes per call. A reader that trusts a single read would emit
    // a truncated chunk; a looping reader fills the requested range across calls.
    vi.resetModules();
    const realFs = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
    vi.doMock('node:fs/promises', () => ({
      ...realFs,
      open: async (...args: Parameters<typeof realFs.open>) => {
        const handle = await realFs.open(...args);
        const realRead = handle.read.bind(handle);
        // Force a short read: serve at most 3 bytes per positional read call.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handle as any).read = (
          buffer: Uint8Array,
          offset: number,
          length: number,
          position: number,
        ) => realRead(buffer, offset, Math.min(length, 3), position);
        return handle;
      },
    }));

    const { toResumableSource: freshToResumableSource } = await import('./resumable-source');
    const source = await freshToResumableSource(path);
    expect(source.size).toBe(FILE.length);

    // A full-width, non-final 16-byte slice must come back complete despite the
    // 3-byte-per-read cap.
    const chunk = await source.slice(0, 16);
    expect(chunk.byteLength).toBe(16);
    expect(Array.from(chunk)).toEqual(Array.from(FILE.subarray(0, 16)));

    // A mid-file slice is likewise filled completely.
    const mid = await source.slice(16, 32);
    expect(mid.byteLength).toBe(16);
    expect(Array.from(mid)).toEqual(Array.from(FILE.subarray(16, 32)));
  });

  it('returns a genuinely short final slice at real EOF', async () => {
    const source = await toResumableSource(path);
    // Request past EOF: only the bytes that exist are returned, never padding.
    const tail = await source.slice(40, 64);
    expect(tail.byteLength).toBe(FILE.length - 40);
    expect(Array.from(tail)).toEqual(Array.from(FILE.subarray(40)));
  });

  it('reassembles the whole file from per-chunk slices under a short-read cap', async () => {
    vi.resetModules();
    const realFs = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
    vi.doMock('node:fs/promises', () => ({
      ...realFs,
      open: async (...args: Parameters<typeof realFs.open>) => {
        const handle = await realFs.open(...args);
        const realRead = handle.read.bind(handle);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handle as any).read = (
          buffer: Uint8Array,
          offset: number,
          length: number,
          position: number,
        ) => realRead(buffer, offset, Math.min(length, 5), position);
        return handle;
      },
    }));

    const { toResumableSource: freshToResumableSource } = await import('./resumable-source');
    const source = await freshToResumableSource(path);
    const reassembled = new Uint8Array(FILE.length);
    const chunkBytes = 16;
    for (let start = 0; start < FILE.length; start += chunkBytes) {
      const end = Math.min(start + chunkBytes, FILE.length);
      const slice = await source.slice(start, end);
      reassembled.set(slice, start);
    }
    expect(Array.from(reassembled)).toEqual(Array.from(FILE));
  });
});
