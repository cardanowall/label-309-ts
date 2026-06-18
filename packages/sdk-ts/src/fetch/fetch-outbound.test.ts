import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  BodyTooLargeError,
  DEFAULT_OUTBOUND_MAX_BYTES,
  defaultFetchOutbound,
  DenyHostError,
  fetchOutbound,
  matchesDenyList,
  OutboundExhaustedError,
  UnsupportedMethodError,
  UnsupportedProtocolError,
  wrapFetchOutbound,
  type FetchOutbound,
  type HttpCallRecord,
} from './fetch-outbound';

afterEach(() => {
  vi.restoreAllMocks();
});

function okInner(status = 200, bytes = new Uint8Array([1, 2, 3])): FetchOutbound {
  return async () => ({ status, bytes, durationMs: 1 });
}

describe('matchesDenyList — IP-literal expansion', () => {
  it('exact host match', () => {
    expect(matchesDenyList('operator.example', ['operator.example'])).toBe(true);
    expect(matchesDenyList('other.com', ['operator.example'])).toBe(false);
  });

  it('glob suffix match: *.operator.example matches subdomain but not bare', () => {
    expect(matchesDenyList('api.operator.example', ['*.operator.example'])).toBe(true);
    expect(matchesDenyList('operator.example', ['*.operator.example'])).toBe(false);
  });

  it('case + trailing-dot tolerant', () => {
    expect(matchesDenyList('Operator.Example.', ['operator.example'])).toBe(true);
  });

  it('IPv6 [::1] (bracket-stripped) blocked when localhost in deny', () => {
    expect(matchesDenyList('[::1]', ['localhost'])).toBe(true);
    expect(matchesDenyList('::1', ['localhost'])).toBe(true);
  });

  it('0.0.0.0 blocked when localhost in deny', () => {
    expect(matchesDenyList('0.0.0.0', ['localhost'])).toBe(true);
  });

  it('127.1.2.3 blocked when 127.0.0.1 in deny (full /8 block)', () => {
    expect(matchesDenyList('127.1.2.3', ['127.0.0.1'])).toBe(true);
    expect(matchesDenyList('127.0.0.99', ['127.0.0.1'])).toBe(true);
  });

  it('169.254.169.254 (cloud metadata) blocked when localhost in deny', () => {
    expect(matchesDenyList('169.254.169.254', ['localhost'])).toBe(true);
  });

  it('8.8.8.8 NOT blocked (non-loopback control case)', () => {
    expect(matchesDenyList('8.8.8.8', ['localhost', '127.0.0.1'])).toBe(false);
  });

  it('empty deny-list allows everything', () => {
    expect(matchesDenyList('operator.example', [])).toBe(false);
    expect(matchesDenyList('127.0.0.1', [])).toBe(false);
  });
});

describe('wrapFetchOutbound — deny-host short-circuit', () => {
  it('records audit row then throws DenyHostError; inner never called', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>().mockResolvedValue({
      status: 200,
      bytes: new Uint8Array(0),
      durationMs: 0,
    });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, {
      denyHosts: ['operator.example'],
    });
    await expect(
      wrapped('https://operator.example/x', { method: 'GET', purpose: 'https' }),
    ).rejects.toBeInstanceOf(DenyHostError);
    expect(inner).not.toHaveBeenCalled();
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      url: 'https://operator.example/x',
      method: 'GET',
      status: null,
      bytes: 0,
      durationMs: 0,
      purpose: 'https',
    });
  });

  it('attaches code SERVICE_INDEPENDENCE_VIOLATION + host + url', async () => {
    const audit: HttpCallRecord[] = [];
    const wrapped = wrapFetchOutbound(okInner(), audit, { denyHosts: ['operator.example'] });
    try {
      await wrapped('https://operator.example/secret', { method: 'GET', purpose: 'https' });
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(DenyHostError);
      const err = e as DenyHostError;
      expect(err.code).toBe('SERVICE_INDEPENDENCE_VIOLATION');
      expect(err.host).toBe('operator.example');
      expect(err.url).toBe('https://operator.example/secret');
    }
  });
});

describe('wrapFetchOutbound — audit row shape', () => {
  it('one success records one row with all six fields', async () => {
    const audit: HttpCallRecord[] = [];
    const wrapped = wrapFetchOutbound(okInner(200, new Uint8Array([1, 2, 3, 4])), audit);
    const r = await wrapped('https://example.com/x', { method: 'GET', purpose: 'arweave' });
    expect(r.status).toBe(200);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toEqual({
      url: 'https://example.com/x',
      method: 'GET',
      status: 200,
      bytes: 4,
      durationMs: expect.any(Number),
      purpose: 'arweave',
    });
    expect(audit[0]!.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('multiple calls preserve FIFO order', async () => {
    const audit: HttpCallRecord[] = [];
    const wrapped = wrapFetchOutbound(
      async (url) => ({ status: 200, bytes: new TextEncoder().encode(url), durationMs: 1 }),
      audit,
    );
    await wrapped('https://a/', { method: 'GET', purpose: 'cardano' });
    await wrapped('https://b/', { method: 'GET', purpose: 'cardano' });
    await wrapped('https://c/', { method: 'POST', purpose: 'cardano' });
    expect(audit.map((a) => a.url)).toEqual(['https://a/', 'https://b/', 'https://c/']);
    expect(audit[2]!.method).toBe('POST');
  });
});

describe('wrapFetchOutbound — audit on errored fetch', () => {
  it('audit row recorded with status:0 before re-throwing original error', async () => {
    const audit: HttpCallRecord[] = [];
    const original = new Error('boom');
    const inner: FetchOutbound = async () => {
      throw original;
    };
    const wrapped = wrapFetchOutbound(inner, audit);
    await expect(
      wrapped('https://example.com/x', { method: 'GET', purpose: 'cardano' }),
    ).rejects.toBe(original);
    expect(audit).toHaveLength(1);
    expect(audit[0]!.status).toBeNull();
    expect(audit[0]!.bytes).toBe(0);
    expect(audit[0]!.durationMs).toBeGreaterThanOrEqual(0);
  });
});

describe('wrapFetchOutbound — protocol allowlist', () => {
  it.each([
    ['data:text/plain;base64,SGVsbG8=', 'data:'],
    ['file:///etc/passwd', 'file:'],
    ['ar://abc', 'ar:'],
    ['ws://example.com/', 'ws:'],
  ])('rejects %s with UnsupportedProtocolError', async (url, expectedProto) => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>();
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit);
    try {
      await wrapped(url, { method: 'GET', purpose: 'https' });
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(UnsupportedProtocolError);
      const err = e as UnsupportedProtocolError;
      expect(err.code).toBe('UNSUPPORTED_PROTOCOL');
      expect(err.protocol).toBe(expectedProto);
      expect(err.url).toBe(url);
    }
    expect(inner).not.toHaveBeenCalled();
    expect(audit).toHaveLength(1);
    expect(audit[0]!.status).toBeNull();
    expect(audit[0]!.bytes).toBe(0);
    expect(audit[0]!.durationMs).toBe(0);
  });
});

describe('wrapFetchOutbound — method allowlist', () => {
  it.each(['PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])(
    'rejects %s with UnsupportedMethodError',
    async (method) => {
      const audit: HttpCallRecord[] = [];
      const inner = vi.fn<FetchOutbound>();
      const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit);
      try {
        await wrapped('https://example.com/x', {
          method: method as 'GET',
          purpose: 'https',
        });
        throw new Error('expected throw');
      } catch (e) {
        expect(e).toBeInstanceOf(UnsupportedMethodError);
        const err = e as UnsupportedMethodError;
        expect(err.code).toBe('UNSUPPORTED_METHOD');
        expect(err.method).toBe(method);
      }
      expect(inner).not.toHaveBeenCalled();
      expect(audit).toHaveLength(1);
      expect(audit[0]!.method).toBe('GET');
    },
  );
});

describe('wrapFetchOutbound — IP-literal blocking via wrap', () => {
  const LOOPBACK_DENY = ['localhost', '127.0.0.1'] as const;
  it.each([
    'http://[::1]/anything',
    'http://0.0.0.0:8080/x',
    'http://127.1.2.3/x',
    'http://169.254.169.254/latest/meta-data',
  ])('denies %s when localhost/127.0.0.1 in deny-list', async (url) => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>().mockResolvedValue({
      status: 200,
      bytes: new Uint8Array(0),
      durationMs: 0,
    });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, {
      denyHosts: [...LOOPBACK_DENY],
    });
    await expect(wrapped(url, { method: 'GET', purpose: 'https' })).rejects.toBeInstanceOf(
      DenyHostError,
    );
    expect(inner).not.toHaveBeenCalled();
  });

  it('does NOT deny 8.8.8.8 with same deny-list', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>().mockResolvedValue({
      status: 200,
      bytes: new Uint8Array(0),
      durationMs: 0,
    });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, {
      denyHosts: [...LOOPBACK_DENY],
    });
    await wrapped('http://8.8.8.8/x', { method: 'GET', purpose: 'https' });
    expect(inner).toHaveBeenCalledOnce();
  });
});

describe('wrapFetchOutbound — retry policy', () => {
  it('8.1 retries=0 disables retry: single attempt, audit row, return-or-throw', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi
      .fn<FetchOutbound>()
      .mockResolvedValue({ status: 503, bytes: new Uint8Array(0), durationMs: 1 });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, { retries: 0 });
    const r = await wrapped('https://example.com/', { method: 'GET', purpose: 'https' });
    expect(inner).toHaveBeenCalledOnce();
    expect(r.status).toBe(503);
    expect(audit).toHaveLength(1);
  });

  it('8.3 200 on attempt 1 records one row and returns immediately', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi
      .fn<FetchOutbound>()
      .mockResolvedValue({ status: 200, bytes: new Uint8Array(0), durationMs: 1 });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, { retries: 3 });
    await wrapped('https://example.com/', { method: 'GET', purpose: 'https' });
    expect(inner).toHaveBeenCalledOnce();
    expect(audit).toHaveLength(1);
  });

  it('8.4 503 then 200 records two rows; returns the second', async () => {
    vi.useFakeTimers();
    try {
      const audit: HttpCallRecord[] = [];
      const inner = vi
        .fn<FetchOutbound>()
        .mockResolvedValueOnce({ status: 503, bytes: new Uint8Array(0), durationMs: 1 })
        .mockResolvedValueOnce({ status: 200, bytes: new Uint8Array([1]), durationMs: 1 });
      const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, { retries: 3 });
      const promise = wrapped('https://example.com/', { method: 'GET', purpose: 'https' });
      await vi.runAllTimersAsync();
      const r = await promise;
      expect(r.status).toBe(200);
      expect(audit.map((a) => a.status)).toEqual([503, 200]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('8.5 four consecutive 503 with retries=3 → four rows + OutboundExhaustedError', async () => {
    vi.useFakeTimers();
    try {
      const audit: HttpCallRecord[] = [];
      const inner = vi
        .fn<FetchOutbound>()
        .mockResolvedValue({ status: 503, bytes: new Uint8Array(0), durationMs: 1 });
      const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, { retries: 3 });
      const promise = wrapped('https://example.com/', {
        method: 'GET',
        purpose: 'https',
      }).catch((e) => e);
      await vi.runAllTimersAsync();
      const result = await promise;
      expect(result).toBeInstanceOf(OutboundExhaustedError);
      const err = result as OutboundExhaustedError;
      expect(err.code).toBe('OUTBOUND_EXHAUSTED');
      expect(err.attempts).toBe(4);
      expect(err.lastStatus).toBe(503);
      expect(audit).toHaveLength(4);
    } finally {
      vi.useRealTimers();
    }
  });

  it('8.6 timeout-style throw on every attempt → OutboundExhaustedError with lastError', async () => {
    vi.useFakeTimers();
    try {
      const audit: HttpCallRecord[] = [];
      const timeoutErr = new Error('AbortError-style timeout');
      const inner: FetchOutbound = async () => {
        throw timeoutErr;
      };
      const wrapped = wrapFetchOutbound(inner, audit, { retries: 3 });
      const promise = wrapped('https://example.com/', {
        method: 'GET',
        purpose: 'https',
      }).catch((e) => e);
      await vi.runAllTimersAsync();
      const result = await promise;
      expect(result).toBeInstanceOf(OutboundExhaustedError);
      const err = result as OutboundExhaustedError;
      expect(err.lastError).toBe(timeoutErr);
      expect(err.attempts).toBe(4);
      expect(audit).toHaveLength(4);
      expect(audit.every((a) => a.status === null)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('8.7 jitter is bounded: 100 attempt-1 backoff samples all fall in [750, 1250] ms', async () => {
    const realSetTimeout = globalThis.setTimeout.bind(globalThis);
    const samples: number[] = [];
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((
      fn: () => void,
      ms?: number,
    ) => {
      if (typeof ms === 'number' && ms > 0) samples.push(ms);
      return realSetTimeout(fn, 0);
    }) as unknown as typeof setTimeout);
    try {
      for (let i = 0; i < 100; i++) {
        const audit: HttpCallRecord[] = [];
        const inner: FetchOutbound = async () => ({
          status: 503,
          bytes: new Uint8Array(0),
          durationMs: 0,
        });
        const wrapped = wrapFetchOutbound(inner, audit, { retries: 1 });
        await wrapped('https://example.com/', { method: 'GET', purpose: 'https' }).catch(() => {});
      }
      expect(samples.length).toBe(100);
      for (const s of samples) {
        expect(s).toBeGreaterThanOrEqual(750);
        expect(s).toBeLessThanOrEqual(1250);
      }
    } finally {
      setTimeoutSpy.mockRestore();
    }
  });

  it('8.2 retryableStatuses=[] disables status-based retry', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi
      .fn<FetchOutbound>()
      .mockResolvedValue({ status: 503, bytes: new Uint8Array(0), durationMs: 1 });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, {
      retries: 3,
      retryableStatuses: [],
    });
    const r = await wrapped('https://example.com/', { method: 'GET', purpose: 'https' });
    expect(inner).toHaveBeenCalledOnce();
    expect(r.status).toBe(503);
    expect(audit).toHaveLength(1);
  });

  it('non-retryable typed errors short-circuit: DenyHostError is not retried', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>();
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, {
      denyHosts: ['operator.example'],
      retries: 3,
    });
    await expect(
      wrapped('https://operator.example/x', { method: 'GET', purpose: 'https' }),
    ).rejects.toBeInstanceOf(DenyHostError);
    expect(inner).not.toHaveBeenCalled();
    expect(audit).toHaveLength(1);
  });
});

describe('defaultFetchOutbound', () => {
  it('forwards method, headers, body to fetch and shapes the result', async () => {
    const body = new Uint8Array([7, 8, 9]);
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(body, { status: 200 }));
    const result = await defaultFetchOutbound('https://example.com/x', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"k":1}',
      purpose: 'cardano',
    });
    expect(fetchSpy).toHaveBeenCalledOnce();
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(init.body).toBe('{"k":1}');
    expect((init.headers as Record<string, string>)['content-type']).toBe('application/json');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(result.status).toBe(200);
    expect(Array.from(result.bytes)).toEqual([7, 8, 9]);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('exposes a default response-size cap', () => {
    // 64 MiB — documented in fetch-outbound.ts. Pinned so a regression that
    // silently drops the cap (back to unbounded) is caught here.
    expect(DEFAULT_OUTBOUND_MAX_BYTES).toBe(64 * 1024 * 1024);
  });

  it('rejects with BodyTooLargeError + aborts when Content-Length exceeds maxBytes', async () => {
    const signals: AbortSignal[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation((async (_url: string, init?: RequestInit) => {
      if (init?.signal) signals.push(init.signal);
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(8));
          controller.close();
        },
      });
      return new Response(body, { status: 200, headers: { 'content-length': '999999' } });
    }) as typeof fetch);
    await expect(
      defaultFetchOutbound('https://gw.example/blob', {
        method: 'GET',
        purpose: 'arweave',
        maxBytes: 1024,
      }),
    ).rejects.toBeInstanceOf(BodyTooLargeError);
    // The request was aborted (defence: the socket is torn down, not left open).
    expect(signals[0]?.aborted).toBe(true);
  });

  it('aborts the stream once accumulated bytes exceed maxBytes (absent Content-Length)', async () => {
    let bytesRead = 0;
    const signals: AbortSignal[] = [];
    // A hostile gateway: no Content-Length, emits 256-byte chunks "forever".
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        bytesRead += 256;
        controller.enqueue(new Uint8Array(256));
        // Guard the test from running unbounded if the cap regresses.
        if (bytesRead > 1_000_000) controller.error(new Error('cap regressed'));
      },
    });
    vi.spyOn(globalThis, 'fetch').mockImplementation((async (_url: string, init?: RequestInit) => {
      if (init?.signal) signals.push(init.signal);
      return new Response(body, { status: 200 });
    }) as typeof fetch);
    await expect(
      defaultFetchOutbound('https://gw.example/stream', {
        method: 'GET',
        purpose: 'arweave',
        maxBytes: 1024,
      }),
    ).rejects.toBeInstanceOf(BodyTooLargeError);
    // Bounded: we stop reading shortly after crossing 1024 — never the full
    // (unbounded) stream — and the underlying request is aborted.
    expect(bytesRead).toBeLessThan(4096);
    expect(signals[0]?.aborted).toBe(true);
  });

  it('returns full body when under the cap', async () => {
    const payload = new Uint8Array([10, 20, 30, 40]);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(payload.slice(0, 2));
        controller.enqueue(payload.slice(2));
        controller.close();
      },
    });
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(body, { status: 200 }));
    const result = await defaultFetchOutbound('https://gw.example/ok', {
      method: 'GET',
      purpose: 'arweave',
      maxBytes: 1024,
    });
    expect(result.status).toBe(200);
    expect(Array.from(result.bytes)).toEqual([10, 20, 30, 40]);
  });

  // Arweave gateways 302 `{gw}/{txid}` → `{base32}.{gw}/{txid}` (a sandbox
  // subdomain of the SAME registrable domain). The arweave content-fetch
  // purpose follows that redirect — but ONLY when the target is an absolute
  // https URL on the same domain (or a subdomain) and not deny-listed.
  it('arweave purpose follows a same-domain sandbox 302 to the final 200 body', async () => {
    const sandboxBody = new Uint8Array([7, 8, 9]);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((async (input: string) => {
      const u = typeof input === 'string' ? input : (input as Request).url;
      if (u === 'https://arweave.net/abc') {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://base32hash.arweave.net/abc' },
        });
      }
      if (u === 'https://base32hash.arweave.net/abc') {
        return new Response(sandboxBody, { status: 200 });
      }
      throw new Error(`unexpected url ${u}`);
    }) as typeof fetch);
    const result = await defaultFetchOutbound('https://arweave.net/abc', {
      method: 'GET',
      purpose: 'arweave',
    });
    // Two requests: the 302 and the followed sandbox GET; the final 200 body
    // is returned. `redirect: 'manual'` on every hop (the transport, not the
    // runtime, chose to follow).
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect((fetchSpy.mock.calls[0]![1] as RequestInit).redirect).toBe('manual');
    expect(result.status).toBe(200);
    expect(Array.from(result.bytes)).toEqual([7, 8, 9]);
  });

  it('arweave purpose does NOT follow a cross-domain 302 (fails this gateway)', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
        new Response(null, { status: 302, headers: { location: 'https://evil.com/steal' } }),
      );
    await expect(
      defaultFetchOutbound('https://arweave.net/abc', { method: 'GET', purpose: 'arweave' }),
    ).rejects.toThrow(/redirect refused/);
    // The cross-domain target is never contacted.
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it('arweave purpose does NOT follow a 302 → loopback metadata IP (SSRF pivot blocked)', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: { location: 'https://169.254.169.254/latest/meta-data' },
      }),
    );
    await expect(
      defaultFetchOutbound('https://arweave.net/abc', { method: 'GET', purpose: 'arweave' }),
    ).rejects.toThrow(/redirect refused/);
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it('arweave purpose rejects a same-domain redirect whose target is deny-listed', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: { location: 'https://sandbox.arweave.net/abc' },
      }),
    );
    await expect(
      defaultFetchOutbound('https://arweave.net/abc', {
        method: 'GET',
        purpose: 'arweave',
        // The transport re-applies the deny-host check to the redirect target:
        // the original host (arweave.net) is allowed, but the sandbox subdomain
        // it redirects to is deny-listed, so the follow is refused.
        denyHosts: ['*.arweave.net'],
      }),
    ).rejects.toThrow(/redirect refused/);
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it('arweave purpose fails the gateway once the redirect hop cap (3) is exceeded', async () => {
    // A gateway that keeps redirecting deeper into the same domain — each hop
    // is a subdomain of the host it came from, so every hop passes the
    // same-domain check and only the hop cap can stop the loop.
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((async (input: string) => {
      const u = typeof input === 'string' ? input : (input as Request).url;
      const host = new URL(u).hostname;
      return new Response(null, {
        status: 302,
        headers: { location: `https://x.${host}/abc` },
      });
    }) as typeof fetch);
    await expect(
      defaultFetchOutbound('https://arweave.net/abc', { method: 'GET', purpose: 'arweave' }),
    ).rejects.toThrow(/redirect limit exceeded/);
    // Initial request + 3 followed hops = 4 fetches, then the cap trips.
    expect(fetchSpy).toHaveBeenCalledTimes(4);
  });

  // A multi-hop chain must be validated against the host of the URL the fetch
  // STARTED from, not against the previous hop's (drifting) host. This matches
  // the Rust twin's `gateway_redirect_allowed(origin, …)`: `origin` is fixed
  // for the whole chain.
  it('arweave purpose follows a multi-hop chain whose every hop is a subdomain of the ORIGINAL host', async () => {
    // arweave.net → a.arweave.net → b.arweave.net: each hop is a subdomain of
    // the ORIGINAL arweave.net, so the chain is followed to the 200 body.
    // b.arweave.net is NOT a subdomain of a.arweave.net (the previous hop), so
    // per-hop anchoring would have wrongly refused the final hop.
    const payload = new Uint8Array([4, 2]);
    const visited: string[] = [];
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((async (input: string) => {
      const u = typeof input === 'string' ? input : (input as Request).url;
      const host = new URL(u).hostname;
      visited.push(host);
      if (host === 'arweave.net') {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://a.arweave.net/abc' },
        });
      }
      if (host === 'a.arweave.net') {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://b.arweave.net/abc' },
        });
      }
      if (host === 'b.arweave.net') {
        return new Response(payload, { status: 200 });
      }
      throw new Error(`unexpected url ${u}`);
    }) as typeof fetch);
    const result = await defaultFetchOutbound('https://arweave.net/abc', {
      method: 'GET',
      purpose: 'arweave',
    });
    expect(result.status).toBe(200);
    expect(Array.from(result.bytes)).toEqual([4, 2]);
    expect(visited).toEqual(['arweave.net', 'a.arweave.net', 'b.arweave.net']);
    expect(fetchSpy).toHaveBeenCalledTimes(3);
  });

  it('arweave purpose refuses a multi-hop chain that drifts off the ORIGINAL domain', async () => {
    // arweave.net → a.arweave.net → c.other.com: the final hop leaves the
    // ORIGINAL registrable domain and is refused; the cross-domain target is
    // never contacted.
    const visited: string[] = [];
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((async (input: string) => {
      const u = typeof input === 'string' ? input : (input as Request).url;
      const host = new URL(u).hostname;
      visited.push(host);
      if (host === 'arweave.net') {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://a.arweave.net/abc' },
        });
      }
      if (host === 'a.arweave.net') {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://c.other.com/steal' },
        });
      }
      throw new Error(`unexpected url ${u}`);
    }) as typeof fetch);
    await expect(
      defaultFetchOutbound('https://arweave.net/abc', { method: 'GET', purpose: 'arweave' }),
    ).rejects.toThrow(/redirect refused/);
    expect(visited).toEqual(['arweave.net', 'a.arweave.net']);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('non-arweave purpose never follows a 3xx: it surfaces as a non-2xx status', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
        new Response(null, { status: 302, headers: { location: 'https://elsewhere.example/' } }),
      );
    const result = await defaultFetchOutbound('https://gw.example/blob', {
      method: 'GET',
      purpose: 'https',
    });
    // Exactly one request: a non-storage purpose keeps the refuse-all-redirects
    // behaviour, returning the readable 3xx verbatim like a 5xx.
    expect(fetchSpy).toHaveBeenCalledOnce();
    expect((fetchSpy.mock.calls[0]![1] as RequestInit).redirect).toBe('manual');
    expect(result.status).toBe(302);
  });

  it("treats the browser's opaqueredirect (status 0, unreadable) as a transport failure", async () => {
    const opaque = {
      type: 'opaqueredirect',
      status: 0,
      headers: new Headers(),
      body: null,
    } as unknown as Response;
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(opaque);
    await expect(
      defaultFetchOutbound('https://gw.example/blob', { method: 'GET', purpose: 'https' }),
    ).rejects.toThrow(/opaqueredirect/);
  });

  it('audit trail: a non-arweave readable 3xx records its real status, opaqueredirect records null', async () => {
    const audit: HttpCallRecord[] = [];
    const wrapped = wrapFetchOutbound(defaultFetchOutbound, audit);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(null, { status: 307, headers: { location: 'https://elsewhere.example/' } }),
    );
    const r = await wrapped('https://gw.example/a', { method: 'GET', purpose: 'https' });
    expect(r.status).toBe(307);

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      type: 'opaqueredirect',
      status: 0,
      headers: new Headers(),
      body: null,
    } as unknown as Response);
    await expect(
      wrapped('https://gw.example/b', { method: 'GET', purpose: 'https' }),
    ).rejects.toThrow(/opaqueredirect/);

    expect(audit.map((a) => a.status)).toEqual([307, null]);
  });

  it('honours an exactly-at-cap body (boundary: total === maxBytes is allowed)', async () => {
    const payload = new Uint8Array(1024).fill(7);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(payload);
        controller.close();
      },
    });
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(body, { status: 200 }));
    const result = await defaultFetchOutbound('https://gw.example/exact', {
      method: 'GET',
      purpose: 'arweave',
      maxBytes: 1024,
    });
    expect(result.bytes.byteLength).toBe(1024);
  });
});

describe('fetchOutbound (high-level)', () => {
  it('composes default + wrap and produces an audit row on success', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(new Uint8Array([1]), { status: 200 }),
    );
    const audit: HttpCallRecord[] = [];
    const result = await fetchOutbound(
      'https://example.com/',
      { method: 'GET', purpose: 'https' },
      audit,
    );
    expect(result.status).toBe(200);
    expect(audit).toHaveLength(1);
  });

  it('rejects purpose=webhook with a guidance message; audit row is still recorded', async () => {
    const audit: HttpCallRecord[] = [];
    await expect(
      fetchOutbound('https://example.com/', { method: 'POST', purpose: 'webhook' }, audit),
    ).rejects.toThrow(/fetchWebhook/);
    expect(audit).toHaveLength(1);
    expect(audit[0]?.purpose).toBe('webhook');
    expect(audit[0]?.status).toBeNull();
  });
});
