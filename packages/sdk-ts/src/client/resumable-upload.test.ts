// Behaviour tests for the threshold-gated resumable upload helper
// (client.poe.uploadResumable). The HTTP layer is mocked the way the other
// client tests mock it — a stateful fetch that emulates the session protocol
// server-side (assembles chunks at their declared offsets, verifies the
// per-chunk Digest, and returns the create/chunk/status/complete/attempt
// shapes) so the assertions check real end-state (assembled bytes -> URI,
// resume gap, dedup short-circuit, accepted -> poll) rather than request copy.

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it, vi } from 'vitest';

import { InsufficientFundsError } from './insufficient-funds-error';
import { Label309Client } from './label-309-client';
import { ResumableUploadError } from './resumable-upload';

const JSON_CT = 'application/json';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': JSON_CT } });
}

function problemResponse(code: string, status: number, detail = code): Response {
  return new Response(
    JSON.stringify({
      type: 'about:blank',
      title: code,
      status,
      detail,
      code,
      trace_id: '01977c00-0000-7000-8000-000000000000',
    }),
    { status, headers: { 'content-type': 'application/problem+json' } },
  );
}

function makeClient(fetchMock: ReturnType<typeof vi.fn>): Label309Client {
  return new Label309Client({
    baseUrl: 'https://cardanowall.com/api/v1',
    apiKey: 'opaque-bearer-token',
    fetch: fetchMock as unknown as typeof globalThis.fetch,
  });
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

async function bodyBytes(body: unknown): Promise<Uint8Array> {
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof Uint8Array) return body;
  throw new Error('unexpected chunk body type');
}

// A configurable in-memory gateway for the session protocol. Drop options to
// simulate dedup-at-create, an accepted+poll completion, or a missing chunk on
// the first status read (to exercise resume).
interface FakeGatewayOptions {
  readonly chunkBytes: number;
  readonly maxChunkBytes?: number;
  readonly dedupOnCreate?: { uri: string };
  readonly acceptedComplete?: { attemptId: string; finalUri: string; charged?: number };
  /** ar:// URI returned on a synchronous committed completion. */
  readonly uri?: string;
  /**
   * Charge (USD micro-cents, a JSON number) on a synchronous committed
   * completion. `0` simulates a dedup-on-commit. Defaults to a non-zero charge.
   */
  readonly completeCharged?: number;
}

function makeFakeGateway(opts: FakeGatewayOptions) {
  const SESSION_ID = 'sess-0001';
  const maxChunkBytes = opts.maxChunkBytes ?? 94_371_840;
  let totalBytes = 0;
  let chunkCount = 0;
  const stored = new Map<number, Uint8Array>();
  let attemptPolls = 0;
  let declaredSha = '';
  // Track whether each handler has been hit, for assertions.
  const calls = {
    create: 0,
    put: 0,
    status: 0,
    complete: 0,
    attempt: 0,
    singleShot: 0,
    abandon: 0,
  };

  const received = (): number[] => [...stored.keys()].sort((a, b) => a - b);
  const missing = (): number[] => {
    const have = new Set(stored.keys());
    const out: number[] = [];
    for (let i = 0; i < chunkCount; i++) if (!have.has(i)) out.push(i);
    return out;
  };
  const assembled = (): Uint8Array => {
    const out = new Uint8Array(totalBytes);
    for (const [idx, bytes] of stored) out.set(bytes, idx * opts.chunkBytes);
    return out;
  };

  const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = typeof url === 'string' ? url : url.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const path = new URL(u).pathname;

    // Single-shot multipart (below-threshold path). The client carries the
    // version segment in its base URL and appends the bare `/poe/uploads`
    // suffix, so the in-memory gateway matches on the suffix it serves.
    if (path.endsWith('/poe/uploads') && method === 'POST') {
      calls.singleShot++;
      return jsonResponse({
        uploads: [
          {
            idx: 0,
            ok: true,
            uri: opts.uri ?? `ar://${'S'.repeat(43)}`,
            sha256: '00'.repeat(32),
            bytes: 1,
          },
        ],
      });
    }

    // Create session.
    if (path.endsWith('/poe/uploads/sessions') && method === 'POST') {
      calls.create++;
      const body = JSON.parse(init!.body as string) as {
        total_bytes: number;
        chunk_bytes: number;
        sha256: string;
      };
      if (opts.dedupOnCreate) {
        // Dedup-on-create: charged_usd_micros is the JSON number 0, never a
        // string (matches the gateway's session-create dedup short-circuit).
        return jsonResponse({
          deduplicated: true,
          uri: opts.dedupOnCreate.uri,
          sha256: body.sha256,
          bytes: body.total_bytes,
          charged_usd_micros: 0,
        });
      }
      totalBytes = body.total_bytes;
      declaredSha = body.sha256;
      // Server clamps the requested chunk size to its ceiling, then echoes it.
      const effectiveChunk = Math.min(opts.chunkBytes, maxChunkBytes);
      chunkCount = Math.ceil(totalBytes / effectiveChunk);
      return jsonResponse(
        {
          session_id: SESSION_ID,
          chunk_bytes: effectiveChunk,
          chunk_count: chunkCount,
          received: [],
          expires_at: '2026-06-09T00:00:00Z',
          max_chunk_bytes: maxChunkBytes,
        },
        201,
      );
    }

    // Chunk PUT.
    const putMatch = path.match(/\/sessions\/[^/]+\/chunks\/(\d+)$/);
    if (putMatch && method === 'PUT') {
      calls.put++;
      const index = Number(putMatch[1]);
      const bytes = await bodyBytes(init?.body);
      // Verify the per-chunk Digest header (RFC 9530 style sha-256=<base64>).
      const headers = init!.headers as Headers;
      const digestHeader = headers.get('digest');
      const expected = `sha-256=${bytesToBase64(nobleSha256(bytes))}`;
      if (digestHeader !== expected) {
        return problemResponse('chunk-digest-mismatch', 400);
      }
      if (headers.get('content-length') !== String(bytes.byteLength)) {
        return problemResponse('chunk-size-mismatch', 400);
      }
      stored.set(index, bytes);
      return jsonResponse({
        index,
        received: received(),
        remaining: missing().length,
        complete: missing().length === 0,
      });
    }

    // Abandon (DELETE the session). The gateway replies 204 No Content.
    if (path.match(/\/sessions\/([^/]+)$/) && method === 'DELETE') {
      calls.abandon++;
      return new Response(null, { status: 204 });
    }

    // Status (resume).
    const statusMatch = path.match(/\/sessions\/([^/]+)$/);
    if (statusMatch && method === 'GET') {
      calls.status++;
      return jsonResponse({
        session_id: SESSION_ID,
        state: 'open',
        sha256: declaredSha,
        total_bytes: totalBytes,
        chunk_bytes: opts.chunkBytes,
        chunk_count: chunkCount,
        received: received(),
        missing: missing(),
        expires_at: '2026-06-09T00:00:00Z',
        attempt_id: null,
        uri: null,
      });
    }

    // Complete.
    if (path.match(/\/sessions\/[^/]+\/complete$/) && method === 'POST') {
      calls.complete++;
      if (missing().length > 0) {
        return problemResponse('incomplete-upload', 409);
      }
      // Integrity gate: the assembled bytes must match the declared digest.
      if (bytesToHex(nobleSha256(assembled())) !== declaredSha) {
        return problemResponse('sha256-mismatch', 400);
      }
      if (opts.acceptedComplete) {
        return jsonResponse({ accepted: true, attempt_id: opts.acceptedComplete.attemptId });
      }
      // A synchronous committed completion: charged_usd_micros is a JSON
      // number (0 on a dedup-on-commit), never a string.
      return jsonResponse({
        ok: true,
        uri: opts.uri ?? `ar://${'C'.repeat(43)}`,
        sha256: declaredSha,
        bytes: totalBytes,
        charged_usd_micros: opts.completeCharged ?? 123,
      });
    }

    // Attempt poll. The shared attempt endpoint reaches exactly one of
    // {reserved, committed, released}: reserved is in flight (poll again);
    // committed carries uri + numeric charged_usd_micros; released carries a
    // reason. sha256/bytes/backend are present in EVERY state; uri and
    // charged_usd_micros appear ONLY on committed.
    const attemptMatch = path.match(/\/uploads\/attempts\/([^/]+)$/);
    if (attemptMatch && method === 'GET') {
      calls.attempt++;
      attemptPolls++;
      // First poll is still reserved, second resolves committed (exercises the
      // poll loop, which polls while state === 'reserved').
      if (attemptPolls < 2) {
        return jsonResponse({
          attempt_id: opts.acceptedComplete!.attemptId,
          state: 'reserved',
          sha256: declaredSha,
          bytes: totalBytes,
          backend: 'arweave',
        });
      }
      return jsonResponse({
        attempt_id: opts.acceptedComplete!.attemptId,
        state: 'committed',
        sha256: declaredSha,
        bytes: totalBytes,
        backend: 'arweave',
        uri: opts.acceptedComplete!.finalUri,
        charged_usd_micros: opts.acceptedComplete!.charged ?? 123,
      });
    }

    throw new Error(`unexpected request ${method} ${path}`);
  });

  return {
    fetchMock,
    calls,
    assembled,
    get declaredSha() {
      return declaredSha;
    },
  };
}

describe('uploadResumable — threshold gate', () => {
  it('routes a file at/below the threshold through the single-shot path', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'S'.repeat(43)}` });
    const client = makeClient(gw.fetchMock);

    const small = new Uint8Array(8).fill(0xab);
    const result = await client.poe.uploadResumable({ source: small, threshold: 64 });

    expect(result.mode).toBe('single-shot');
    expect(result.uri).toBe(`ar://${'S'.repeat(43)}`);
    // Single-shot only: no session was created.
    expect(gw.calls.singleShot).toBe(1);
    expect(gw.calls.create).toBe(0);
  });

  it('routes a file above the threshold through the session flow', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16 });
    const client = makeClient(gw.fetchMock);

    const big = new Uint8Array(40);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    const result = await client.poe.uploadResumable({ source: big, threshold: 32, chunkBytes: 16 });

    expect(result.mode).toBe('chunked');
    expect(gw.calls.singleShot).toBe(0);
    expect(gw.calls.create).toBe(1);
  });
});

describe('uploadResumable — multi-chunk session', () => {
  it('uploads >=3 chunks that reassemble to the declared file and complete', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'C'.repeat(43)}` });
    const client = makeClient(gw.fetchMock);

    // 40 bytes / 16-byte chunks => 3 chunks (16, 16, 8).
    const file = new Uint8Array(40);
    for (let i = 0; i < file.length; i++) file[i] = (i * 7) & 0xff;

    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 32,
      chunkBytes: 16,
      parallelism: 2,
    });

    expect(result.uri).toBe(`ar://${'C'.repeat(43)}`);
    expect(gw.calls.put).toBe(3);
    // The assembled server-side bytes equal the original file.
    expect(bytesToHex(gw.assembled())).toBe(bytesToHex(file));
    // The declared whole-file digest matches the real hash of the file.
    expect(gw.declaredSha).toBe(bytesToHex(nobleSha256(file)));
  });

  it('honours the server-clamped chunk size from the create response', async () => {
    // Client asks for 32-byte chunks; server caps at 16.
    const gw = makeFakeGateway({ chunkBytes: 16, maxChunkBytes: 16 });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x5a);
    await client.poe.uploadResumable({ source: file, threshold: 16, chunkBytes: 32 });

    // 40 / 16 = 3 chunks because the server's clamp won, not the client's 32.
    expect(gw.calls.put).toBe(3);
    expect(bytesToHex(gw.assembled())).toBe(bytesToHex(file));
  });
});

describe('uploadResumable — resume', () => {
  it('on resume, GETs status and PUTs only the missing indices', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'R'.repeat(43)}` });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40);
    for (let i = 0; i < file.length; i++) file[i] = (i + 1) & 0xff;

    // First pass: create + upload chunk 0 and 1, then abort before chunk 2.
    const ac = new AbortController();
    let putsBeforeAbort = 0;
    const original = gw.fetchMock.getMockImplementation()!;
    gw.fetchMock.mockImplementation(async (url, init) => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      if (path.includes('/chunks/')) {
        putsBeforeAbort++;
        if (putsBeforeAbort > 2) {
          ac.abort();
          throw new ResumableUploadError('ABORTED', 'upload aborted');
        }
      }
      return original(url, init);
    });

    await expect(
      client.poe.uploadResumable({
        source: file,
        threshold: 16,
        chunkBytes: 16,
        parallelism: 1,
        signal: ac.signal,
      }),
    ).rejects.toBeDefined();

    const putsAfterFirstPass = gw.calls.put;
    expect(putsAfterFirstPass).toBe(2); // only chunks 0 and 1 landed

    // Restore the plain gateway and resume with the same session id.
    gw.fetchMock.mockImplementation(original);
    const statusBefore = gw.calls.status;

    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
      sessionId: 'sess-0001',
    });

    expect(result.uri).toBe(`ar://${'R'.repeat(43)}`);
    // Resume GETs the session status at least once.
    expect(gw.calls.status).toBeGreaterThan(statusBefore);
    // Only the single missing chunk (index 2) was re-PUT.
    expect(gw.calls.put).toBe(putsAfterFirstPass + 1);
    expect(bytesToHex(gw.assembled())).toBe(bytesToHex(file));
  });

  it('re-PUTs exactly the server-reported missing set, not a set derived from received', async () => {
    // The server is authoritative for which indices to resend. Here `received`
    // and `missing` deliberately disagree with what a naive recompute from
    // `received` would produce: the server reports index 1 as the ONLY missing
    // chunk even though `received` lists [0, 2] (so a recompute over a 3-chunk
    // grid would also yield [1], but we make the grid 4 chunks and have the
    // server claim only [1] is missing — proving the helper trusts `missing`).
    const putIndices: number[] = [];
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      // Resume: GET status with a server-chosen missing set that is NARROWER
      // than the gap a recompute from `received` would yield.
      if (path.match(/\/sessions\/([^/]+)$/) && method === 'GET') {
        return jsonResponse({
          session_id: 'sess-auth',
          state: 'open',
          sha256: '00'.repeat(32),
          total_bytes: 64,
          chunk_bytes: 16,
          chunk_count: 4,
          // received omits indices 1 AND 3, but the server says only 1 is missing
          // (index 3 is, say, mid-assembly server-side and must NOT be re-sent).
          received: [0, 2],
          missing: [1],
          expires_at: '2026-06-09T00:00:00Z',
          attempt_id: null,
          uri: null,
        });
      }
      if (path.match(/\/sessions\/[^/]+\/chunks\/(\d+)$/) && method === 'PUT') {
        putIndices.push(Number(path.match(/\/chunks\/(\d+)$/)![1]));
        const idx = Number(path.match(/\/chunks\/(\d+)$/)![1]);
        return jsonResponse({ index: idx, received: [0, 1, 2, 3], remaining: 0, complete: true });
      }
      if (path.match(/\/sessions\/[^/]+\/complete$/) && method === 'POST') {
        return jsonResponse({
          ok: true,
          uri: `ar://${'M'.repeat(43)}`,
          sha256: '00'.repeat(32),
          bytes: 64,
          charged_usd_micros: 50,
        });
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const client = makeClient(fetchMock);

    const file = new Uint8Array(64).fill(0x77);
    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
      sessionId: 'sess-auth',
    });

    expect(result.uri).toBe(`ar://${'M'.repeat(43)}`);
    // The helper sent exactly the server's missing set [1], NOT the [1, 3] gap a
    // recompute from received=[0,2] over a 4-chunk grid would have produced.
    expect(putIndices).toEqual([1]);
  });
});

describe('uploadResumable — resume bounds the final chunk against the server total', () => {
  it('a source that grew after create still sends the declared remainder, never over-reading', async () => {
    // The session was created over a 40-byte file in 16-byte chunks: 3 chunks of
    // (16, 16, 8). The gateway already holds chunks 0 and 1 and reports only the
    // final chunk (index 2) as missing, with total_bytes=40 / chunk_bytes=16.
    // Between attempts the LOCAL source grew to 64 bytes. The helper must bound
    // the final chunk against the server-declared total (40), so chunk 2 is the
    // declared 8-byte remainder [32, 40) and never the 16 bytes a grown-local
    // recompute would over-read — which would also contradict the declared digest.
    const SERVER_TOTAL = 40;
    const SERVER_CHUNK = 16;
    const putBodies: Array<{ index: number; bytes: Uint8Array }> = [];

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();

      if (path.match(/\/sessions\/([^/]+)$/) && method === 'GET') {
        return jsonResponse({
          session_id: 'sess-grew',
          state: 'open',
          sha256: '00'.repeat(32),
          total_bytes: SERVER_TOTAL,
          chunk_bytes: SERVER_CHUNK,
          chunk_count: 3,
          received: [0, 1],
          missing: [2],
          expires_at: '2026-06-09T00:00:00Z',
          attempt_id: null,
          uri: null,
        });
      }
      if (path.match(/\/sessions\/[^/]+\/chunks\/(\d+)$/) && method === 'PUT') {
        const index = Number(path.match(/\/chunks\/(\d+)$/)![1]);
        putBodies.push({ index, bytes: await bodyBytes(init?.body) });
        return jsonResponse({ index, received: [0, 1, 2], remaining: 0, complete: true });
      }
      if (path.match(/\/sessions\/[^/]+\/complete$/) && method === 'POST') {
        return jsonResponse({
          ok: true,
          uri: `ar://${'G'.repeat(43)}`,
          sha256: '00'.repeat(32),
          bytes: SERVER_TOTAL,
          charged_usd_micros: 99,
        });
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const client = makeClient(fetchMock);

    // Local source is now LARGER (64 bytes) than the 40 declared at create time.
    const grown = new Uint8Array(64);
    for (let i = 0; i < grown.length; i++) grown[i] = (i + 1) & 0xff;

    const result = await client.poe.uploadResumable({
      source: grown,
      threshold: 16,
      chunkBytes: 16,
      sessionId: 'sess-grew',
    });

    expect(result.uri).toBe(`ar://${'G'.repeat(43)}`);
    // Exactly one chunk was sent: the final missing index.
    expect(putBodies).toHaveLength(1);
    const finalChunk = putBodies[0]!;
    expect(finalChunk.index).toBe(2);
    // The final chunk is the declared 8-byte remainder [32, 40) of the ORIGINAL
    // 40-byte declaration, not 16 bytes pulled from the grown local source.
    expect(finalChunk.bytes.byteLength).toBe(SERVER_TOTAL - 2 * SERVER_CHUNK);
    expect(Array.from(finalChunk.bytes)).toEqual(Array.from(grown.subarray(32, 40)));
    // The result bytes reflect the server-declared total, not the live source size.
    expect(result.bytes).toBe(SERVER_TOTAL);
  });
});

describe('uploadResumable — resume adopts the server digest, never re-hashing the source', () => {
  it('does NOT stream the whole source on resume, reads only the missing ranges, and returns the server status sha256', async () => {
    // A session content-addressed by the digest declared at CREATE time. The
    // local source has since GROWN (64 bytes) past the original 40-byte
    // declaration, and its bytes differ from what was originally hashed. A
    // correct resume must (a) never re-read the whole local source to recompute
    // a digest (the point of resumable upload), and (b) return the
    // server-declared digest, not a locally recomputed one over the grown bytes.
    const SERVER_TOTAL = 40;
    const SERVER_CHUNK = 16;
    const SERVER_SHA = 'ab'.repeat(32); // the digest declared at create time
    const sliceRanges: Array<[number, number]> = [];
    let streamCalls = 0;

    // A ResumableSource whose stream() (the whole-file hash pass) and slice()
    // (per-chunk reads) are counting spies. The underlying bytes are LARGER than
    // the server-declared total to model a source that grew after create.
    const grownBytes = new Uint8Array(64);
    for (let i = 0; i < grownBytes.length; i++) grownBytes[i] = (i + 1) & 0xff;
    const spySource = {
      size: grownBytes.byteLength,
      slice(start: number, end: number): Uint8Array {
        sliceRanges.push([start, end]);
        return grownBytes.subarray(start, end);
      },
      stream(): AsyncIterable<Uint8Array> {
        streamCalls++;
        return (async function* () {
          yield grownBytes;
        })();
      },
    };

    const putBodies: Array<{ index: number; bytes: Uint8Array }> = [];
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      if (path.match(/\/sessions\/([^/]+)$/) && method === 'GET') {
        return jsonResponse({
          session_id: 'sess-spy',
          state: 'open',
          sha256: SERVER_SHA,
          total_bytes: SERVER_TOTAL,
          chunk_bytes: SERVER_CHUNK,
          chunk_count: 3,
          received: [0, 1],
          missing: [2],
          expires_at: '2026-06-09T00:00:00Z',
          attempt_id: null,
          uri: null,
        });
      }
      if (path.match(/\/sessions\/[^/]+\/chunks\/(\d+)$/) && method === 'PUT') {
        const index = Number(path.match(/\/chunks\/(\d+)$/)![1]);
        putBodies.push({ index, bytes: await bodyBytes(init?.body) });
        return jsonResponse({ index, received: [0, 1, 2], remaining: 0, complete: true });
      }
      if (path.match(/\/sessions\/[^/]+\/complete$/) && method === 'POST') {
        return jsonResponse({
          ok: true,
          uri: `ar://${'Z'.repeat(43)}`,
          sha256: SERVER_SHA,
          bytes: SERVER_TOTAL,
          charged_usd_micros: 7,
        });
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const client = makeClient(fetchMock);

    const result = await client.poe.uploadResumable({
      source: spySource,
      threshold: 16,
      chunkBytes: 16,
      sessionId: 'sess-spy',
    });

    // The whole-file hash pass (stream()) was NEVER invoked on resume — the
    // helper adopts the server digest instead of re-reading the source.
    expect(streamCalls).toBe(0);
    // The source was read ONLY for the single missing chunk range, bounded to the
    // server-declared total (the 8-byte remainder [32, 40)), never [0, 64).
    expect(sliceRanges).toEqual([[32, 40]]);
    expect(putBodies).toHaveLength(1);
    expect(putBodies[0]!.index).toBe(2);
    expect(putBodies[0]!.bytes.byteLength).toBe(SERVER_TOTAL - 2 * SERVER_CHUNK);
    // The returned digest is the SERVER-declared one, NOT a hash recomputed over
    // the grown local source.
    expect(result.sha256).toBe(SERVER_SHA);
    expect(result.sha256).not.toBe(bytesToHex(nobleSha256(grownBytes)));
    expect(result.bytes).toBe(SERVER_TOTAL);
    expect(result.uri).toBe(`ar://${'Z'.repeat(43)}`);
  });

  it('returns the server status sha256 (not a local hash) on a completed-session resume', async () => {
    // The session is already completed server-side. The resume must short-circuit
    // to the server's recorded digest/uri/total without touching the local source.
    const SERVER_SHA = 'cd'.repeat(32);
    let streamCalls = 0;
    let sliceCalls = 0;
    const localBytes = new Uint8Array(64).fill(0x9e); // differs from what was stored
    const spySource = {
      size: localBytes.byteLength,
      slice(start: number, end: number): Uint8Array {
        sliceCalls++;
        return localBytes.subarray(start, end);
      },
      stream(): AsyncIterable<Uint8Array> {
        streamCalls++;
        return (async function* () {
          yield localBytes;
        })();
      },
    };

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      if (path.match(/\/sessions\/([^/]+)$/) && method === 'GET') {
        return jsonResponse({
          session_id: 'sess-done',
          state: 'completed',
          sha256: SERVER_SHA,
          total_bytes: 40,
          chunk_bytes: 16,
          chunk_count: 3,
          received: [0, 1, 2],
          missing: [],
          expires_at: '2026-06-09T00:00:00Z',
          attempt_id: null,
          uri: `ar://${'Q'.repeat(43)}`,
        });
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const client = makeClient(fetchMock);

    const result = await client.poe.uploadResumable({
      source: spySource,
      threshold: 16,
      chunkBytes: 16,
      sessionId: 'sess-done',
    });

    expect(result.uri).toBe(`ar://${'Q'.repeat(43)}`);
    expect(result.sha256).toBe(SERVER_SHA);
    expect(result.bytes).toBe(40);
    // Neither the whole-file hash pass nor any chunk read touched the local source.
    expect(streamCalls).toBe(0);
    expect(sliceCalls).toBe(0);
  });
});

describe('uploadResumable — create-time dedup', () => {
  it('short-circuits with the existing uri and uploads nothing', async () => {
    const gw = makeFakeGateway({
      chunkBytes: 16,
      dedupOnCreate: { uri: `ar://${'D'.repeat(43)}` },
    });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x11);
    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
    });

    expect(result.deduplicated).toBe(true);
    expect(result.uri).toBe(`ar://${'D'.repeat(43)}`);
    expect(gw.calls.create).toBe(1);
    expect(gw.calls.put).toBe(0);
    expect(gw.calls.complete).toBe(0);
  });
});

describe('uploadResumable — accepted completion', () => {
  it('polls the attempt endpoint to the terminal committed result', async () => {
    const gw = makeFakeGateway({
      chunkBytes: 16,
      acceptedComplete: { attemptId: 'att-77', finalUri: `ar://${'A'.repeat(43)}` },
    });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x22);
    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
    });

    expect(result.uri).toBe(`ar://${'A'.repeat(43)}`);
    // The committed attempt's numeric bytes/sha256 flow through verbatim, and a
    // non-zero charge is not a dedup hit.
    expect(result.bytes).toBe(file.byteLength);
    expect(result.sha256).toBe(bytesToHex(nobleSha256(file)));
    expect(result.deduplicated).toBe(false);
    // Completed asynchronously: at least two attempt polls (reserved then committed).
    expect(gw.calls.attempt).toBeGreaterThanOrEqual(2);
  });

  it('treats a committed attempt with charged_usd_micros === 0 as a dedup hit', async () => {
    const gw = makeFakeGateway({
      chunkBytes: 16,
      acceptedComplete: { attemptId: 'att-dd', finalUri: `ar://${'E'.repeat(43)}`, charged: 0 },
    });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x44);
    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
    });

    // A committed attempt that charged the number 0 deduped against stored bytes.
    expect(result.uri).toBe(`ar://${'E'.repeat(43)}`);
    expect(result.deduplicated).toBe(true);
  });

  it('fails with the released reason when the polled attempt is released', async () => {
    // The attempt endpoint reaches 'released' (terminal failure) instead of
    // 'committed'; the helper surfaces the server's reason and does not return a uri.
    let polls = 0;
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      if (path.endsWith('/poe/uploads/sessions') && method === 'POST') {
        const body = JSON.parse(init!.body as string) as { total_bytes: number };
        return jsonResponse(
          {
            session_id: 'sess-rel',
            chunk_bytes: 16,
            chunk_count: Math.ceil(body.total_bytes / 16),
            received: [],
            expires_at: '2026-06-09T00:00:00Z',
            max_chunk_bytes: 94_371_840,
          },
          201,
        );
      }
      if (path.match(/\/sessions\/[^/]+\/chunks\/(\d+)$/) && method === 'PUT') {
        const idx = Number(path.match(/\/chunks\/(\d+)$/)![1]);
        return jsonResponse({ index: idx, received: [idx], remaining: 0, complete: true });
      }
      if (path.match(/\/sessions\/[^/]+\/complete$/) && method === 'POST') {
        return jsonResponse({ accepted: true, attempt_id: 'att-rel' });
      }
      // A released attempt is a terminal failure, so the driver abandons the
      // session; the gateway answers the DELETE with 204. (Without this the
      // abandon would mask the real ATTEMPT_FAILED reason with SESSION_FAILED.)
      if (path.match(/\/sessions\/([^/]+)$/) && method === 'DELETE') {
        return new Response(null, { status: 204 });
      }
      if (path.match(/\/uploads\/attempts\/([^/]+)$/) && method === 'GET') {
        polls++;
        if (polls < 2) {
          return jsonResponse({
            attempt_id: 'att-rel',
            state: 'reserved',
            sha256: '00'.repeat(32),
            bytes: 16,
            backend: 'arweave',
          });
        }
        return jsonResponse({
          attempt_id: 'att-rel',
          state: 'released',
          sha256: '00'.repeat(32),
          bytes: 16,
          backend: 'arweave',
          reason: 'provider_rejected',
        });
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const client = makeClient(fetchMock);

    const file = new Uint8Array(16).fill(0x55);
    await expect(
      client.poe.uploadResumable({ source: file, threshold: 8, chunkBytes: 16 }),
    ).rejects.toMatchObject({
      code: 'ATTEMPT_FAILED',
      message: expect.stringContaining('provider_rejected'),
    });
  });
});

describe('uploadResumable — funding error at create', () => {
  // All three 402 funding codes the gateway emits are one condition to the
  // caller: the account cannot fund the operation. Each MUST surface as the same
  // typed funding error (InsufficientFundsError), matching the Rust SDK.
  it.each(['insufficient-funds', 'insufficient-storage-credit', 'no-funding-grant'])(
    'surfaces the 402 %s code as InsufficientFundsError before any bytes flow',
    async (code) => {
      const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
        const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
        if (
          path.endsWith('/poe/uploads/sessions') &&
          (init?.method ?? '').toUpperCase() === 'POST'
        ) {
          return problemResponse(code, 402, 'the account cannot fund this upload');
        }
        throw new Error(`unexpected ${path}`);
      });
      const client = makeClient(fetchMock);

      const file = new Uint8Array(40).fill(0x33);
      const err = await client.poe
        .uploadResumable({ source: file, threshold: 16, chunkBytes: 16 })
        .then(
          () => {
            throw new Error('expected the funding error to reject');
          },
          (e: unknown) => e,
        );
      expect(err).toBeInstanceOf(InsufficientFundsError);
      expect((err as InsufficientFundsError).httpStatus).toBe(402);
      expect((err as InsufficientFundsError).code).toBe(code);
      // No chunk PUT was attempted.
      expect(fetchMock.mock.calls.some(([u]) => String(u).includes('/chunks/'))).toBe(false);
    },
  );
});

describe('uploadResumable — terminal chunk error fails fast', () => {
  // A deterministic 4xx on a chunk PUT (400 chunk-size-mismatch, 400
  // chunk-digest-mismatch, 409 chunk-conflict) cannot be fixed by resending the
  // same bytes: the helper must FAIL FAST with the real problem code and NOT
  // retry. Only transient failures (5xx/429/408/network) are retried.
  it.each([
    ['chunk-size-mismatch', 400],
    ['chunk-digest-mismatch', 400],
    ['chunk-conflict', 409],
  ])('does not retry a %s (%d) chunk PUT and surfaces the problem code', async (code, status) => {
    let putCount = 0;
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      if (path.endsWith('/poe/uploads/sessions') && method === 'POST') {
        const body = JSON.parse(init!.body as string) as { total_bytes: number };
        return jsonResponse(
          {
            session_id: 'sess-term',
            chunk_bytes: 16,
            chunk_count: Math.ceil(body.total_bytes / 16),
            received: [],
            expires_at: '2026-06-09T00:00:00Z',
            max_chunk_bytes: 94_371_840,
          },
          201,
        );
      }
      if (path.match(/\/sessions\/[^/]+\/chunks\/(\d+)$/) && method === 'PUT') {
        putCount++;
        return problemResponse(code, status);
      }
      // The terminal chunk error fails the upload, so the driver abandons the
      // session; the gateway answers the DELETE with 204. (Without this the
      // abandon would mask the real chunk problem code with SESSION_FAILED.)
      if (path.match(/\/sessions\/([^/]+)$/) && method === 'DELETE') {
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const client = makeClient(fetchMock);

    const file = new Uint8Array(40).fill(0x66);
    await expect(
      client.poe.uploadResumable({
        source: file,
        threshold: 16,
        chunkBytes: 16,
        parallelism: 1,
        // A generous retry budget; a terminal error must short-circuit it.
        maxChunkRetries: 5,
      }),
    ).rejects.toMatchObject({ code, httpStatus: status });
    // Exactly one PUT for the first chunk: the terminal error was not retried.
    expect(putCount).toBe(1);
  });

  it('retries a transient 503 chunk PUT and then succeeds', async () => {
    let firstChunkPuts = 0;
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'T'.repeat(43)}` });
    const original = gw.fetchMock.getMockImplementation()!;
    gw.fetchMock.mockImplementation(async (url, init) => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const m = path.match(/\/chunks\/(\d+)$/);
      if (m && Number(m[1]) === 0) {
        firstChunkPuts++;
        // Fail the first PUT of chunk 0 transiently, then let it through.
        if (firstChunkPuts === 1) return problemResponse('service-unavailable', 503);
      }
      return original(url, init);
    });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40);
    for (let i = 0; i < file.length; i++) file[i] = (i * 3) & 0xff;
    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
      parallelism: 1,
    });

    expect(result.uri).toBe(`ar://${'T'.repeat(43)}`);
    // Chunk 0 was retried (failed once, then succeeded) — the transient error
    // was not treated as terminal.
    expect(firstChunkPuts).toBeGreaterThanOrEqual(2);
    expect(bytesToHex(gw.assembled())).toBe(bytesToHex(file));
  });
});

describe('uploadResumable — progress reporting', () => {
  it('fires onProgress once per chunk with a monotonically growing byte count', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'P'.repeat(43)}` });
    const client = makeClient(gw.fetchMock);

    // 40 bytes / 16-byte chunks => 3 chunks (16, 16, 8).
    const file = new Uint8Array(40).fill(0x5a);
    const progress: Array<{ bytesSent: number; totalBytes: number; chunksTotal: number }> = [];
    const result = await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
      parallelism: 1, // deterministic order for the assertion
      onProgress: (p) => progress.push({ ...p }),
    });

    expect(result.uri).toBe(`ar://${'P'.repeat(43)}`);
    // One callback per chunk; bytesSent reaches the full file size.
    expect(progress).toHaveLength(3);
    expect(progress.map((p) => p.bytesSent)).toEqual([16, 32, 40]);
    expect(progress.every((p) => p.totalBytes === 40 && p.chunksTotal === 3)).toBe(true);
  });

  it('accumulates progress across all parallel chunks regardless of order', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'Q'.repeat(43)}` });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x5b);
    let maxBytes = 0;
    let count = 0;
    await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
      parallelism: 4,
      onProgress: (p) => {
        count++;
        maxBytes = Math.max(maxBytes, p.bytesSent);
      },
    });
    // 3 chunks => 3 callbacks; the final cumulative byte count is the whole file.
    expect(count).toBe(3);
    expect(maxBytes).toBe(40);
  });

  it('the single-shot path reports a single terminal 100% progress', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'S'.repeat(43)}` });
    const client = makeClient(gw.fetchMock);

    const small = new Uint8Array(8).fill(0xab);
    const progress: Array<{ bytesSent: number; totalBytes: number; chunksTotal: number }> = [];
    const result = await client.poe.uploadResumable({
      source: small,
      threshold: 64,
      onProgress: (p) => progress.push({ ...p }),
    });

    expect(result.mode).toBe('single-shot');
    // Exactly one callback, at 100%, with a single-chunk grid.
    expect(progress).toHaveLength(1);
    expect(progress[0]).toEqual({
      bytesSent: result.bytes,
      totalBytes: result.bytes,
      chunkIndex: 0,
      chunksTotal: 1,
    });
  });
});

describe('uploadResumable — early session id', () => {
  it('fires onSessionCreated with the session id before any chunk PUT', async () => {
    let sessionIdAtCallback: string | null = null;
    let putsAtCallback = -1;
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'I'.repeat(43)}` });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x5c);
    await client.poe.uploadResumable({
      source: file,
      threshold: 16,
      chunkBytes: 16,
      onSessionCreated: (sid) => {
        sessionIdAtCallback = sid;
        putsAtCallback = gw.calls.put;
      },
    });

    // The callback fired with the server-issued id, and BEFORE any chunk PUT.
    expect(sessionIdAtCallback).toBe('sess-0001');
    expect(putsAtCallback).toBe(0);
  });

  it('does NOT fire onSessionCreated on the single-shot path or a create-time dedup', async () => {
    // Single-shot: no session exists.
    const gwSmall = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'S'.repeat(43)}` });
    let smallFired = false;
    await makeClient(gwSmall.fetchMock).poe.uploadResumable({
      source: new Uint8Array(8).fill(1),
      threshold: 64,
      onSessionCreated: () => {
        smallFired = true;
      },
    });
    expect(smallFired).toBe(false);

    // Create-time dedup: the create short-circuits before a session id is issued.
    const gwDedup = makeFakeGateway({
      chunkBytes: 16,
      dedupOnCreate: { uri: `ar://${'D'.repeat(43)}` },
    });
    let dedupFired = false;
    const result = await makeClient(gwDedup.fetchMock).poe.uploadResumable({
      source: new Uint8Array(40).fill(2),
      threshold: 16,
      chunkBytes: 16,
      onSessionCreated: () => {
        dedupFired = true;
      },
    });
    expect(result.deduplicated).toBe(true);
    expect(dedupFired).toBe(false);
  });
});

describe('uploadResumable — a failure after the session exists abandons it', () => {
  it('on abort during chunk upload, DELETEs the session and rejects', async () => {
    const ac = new AbortController();
    const gw = makeFakeGateway({ chunkBytes: 16, uri: `ar://${'A'.repeat(43)}` });
    const original = gw.fetchMock.getMockImplementation()!;
    // Abort once the first chunk PUT is in flight.
    gw.fetchMock.mockImplementation(async (url, init) => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      if (path.includes('/chunks/')) {
        ac.abort();
        throw new ResumableUploadError('ABORTED', 'upload aborted');
      }
      return original(url, init);
    });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x77);
    await expect(
      client.poe.uploadResumable({
        source: file,
        threshold: 16,
        chunkBytes: 16,
        parallelism: 1,
        signal: ac.signal,
      }),
    ).rejects.toBeDefined();

    // The session was created, then abandoned (DELETE) exactly once on abort.
    expect(gw.calls.create).toBe(1);
    expect(gw.calls.abandon).toBe(1);
  });

  it('surfaces a SESSION_FAILED naming the session id when the abandon itself fails', async () => {
    const ac = new AbortController();
    const gw = makeFakeGateway({ chunkBytes: 16 });
    const original = gw.fetchMock.getMockImplementation()!;
    gw.fetchMock.mockImplementation(async (url, init) => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      // The abandon DELETE fails with a 500 (not a 404/410), so it is NOT
      // idempotent-OK and must surface to the caller with the session id.
      if (path.match(/\/sessions\/([^/]+)$/) && method === 'DELETE') {
        return problemResponse('internal-error', 500);
      }
      if (path.includes('/chunks/')) {
        ac.abort();
        throw new ResumableUploadError('ABORTED', 'upload aborted');
      }
      return original(url, init);
    });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0x88);
    await expect(
      client.poe.uploadResumable({
        source: file,
        threshold: 16,
        chunkBytes: 16,
        parallelism: 1,
        signal: ac.signal,
      }),
    ).rejects.toMatchObject({
      code: 'SESSION_FAILED',
      message: expect.stringContaining('sess-0001'),
    });
  });

  it('abandons the session and rethrows the original error when onSessionCreated throws', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16 });
    const client = makeClient(gw.fetchMock);

    const callbackError = new Error('caller persistence failed');
    const file = new Uint8Array(40).fill(0x99);
    await expect(
      client.poe.uploadResumable({
        source: file,
        threshold: 16,
        chunkBytes: 16,
        onSessionCreated: () => {
          throw callbackError;
        },
      }),
    ).rejects.toBe(callbackError);

    // The session was created, then abandoned (DELETE) — a throwing callback must
    // not leak the freshly-created session. No chunk was PUT (the throw preempts
    // the upload).
    expect(gw.calls.create).toBe(1);
    expect(gw.calls.put).toBe(0);
    expect(gw.calls.abandon).toBe(1);
  });

  it('abandons the session and rethrows the original error when onProgress throws', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16 });
    const client = makeClient(gw.fetchMock);

    const callbackError = new Error('progress sink failed');
    const file = new Uint8Array(40).fill(0xaa);
    await expect(
      client.poe.uploadResumable({
        source: file,
        threshold: 16,
        chunkBytes: 16,
        parallelism: 1,
        onProgress: () => {
          throw callbackError;
        },
      }),
    ).rejects.toBe(callbackError);

    // A throwing onProgress (fired after the first chunk lands) abandons the
    // session rather than leaving it dangling — the catch is not gated on abort.
    expect(gw.calls.create).toBe(1);
    expect(gw.calls.abandon).toBe(1);
  });

  it('surfaces SESSION_FAILED naming the session id when a throwing callback then fails to abandon', async () => {
    const gw = makeFakeGateway({ chunkBytes: 16 });
    const original = gw.fetchMock.getMockImplementation()!;
    gw.fetchMock.mockImplementation(async (url, init) => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      // The abandon DELETE fails with a 500, so the leaked session must surface
      // to the caller with its id — even when the trigger was a throwing callback.
      if (path.match(/\/sessions\/([^/]+)$/) && method === 'DELETE') {
        return problemResponse('internal-error', 500);
      }
      return original(url, init);
    });
    const client = makeClient(gw.fetchMock);

    const file = new Uint8Array(40).fill(0xbb);
    await expect(
      client.poe.uploadResumable({
        source: file,
        threshold: 16,
        chunkBytes: 16,
        onSessionCreated: () => {
          throw new Error('caller persistence failed');
        },
      }),
    ).rejects.toMatchObject({
      code: 'SESSION_FAILED',
      message: expect.stringContaining('sess-0001'),
    });
  });
});

describe('poe.abandonUploadSession', () => {
  it('DELETEs the session and resolves on 204', async () => {
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
      const method = (init?.method ?? 'GET').toUpperCase();
      expect(method).toBe('DELETE');
      expect(path).toBe('/api/v1/poe/uploads/sessions/sess-xyz');
      return new Response(null, { status: 204 });
    });
    await expect(
      makeClient(fetchMock).poe.abandonUploadSession('sess-xyz'),
    ).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('treats a 404/410 as already-gone (idempotent), not an error', async () => {
    for (const status of [404, 410]) {
      const fetchMock = vi
        .fn()
        .mockResolvedValue(problemResponse('not-found', status, 'no such upload session'));
      await expect(
        makeClient(fetchMock).poe.abandonUploadSession('sess-gone'),
      ).resolves.toBeUndefined();
    }
  });

  it('throws the typed error on a non-idempotent failure (e.g. 403)', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(problemResponse('forbidden', 403, 'not your session'));
    await expect(makeClient(fetchMock).poe.abandonUploadSession('sess-403')).rejects.toMatchObject({
      httpStatus: 403,
    });
  });
});
