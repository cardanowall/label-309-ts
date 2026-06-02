import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  defaultFetchOutbound as canonicalDefaultFetchOutbound,
  wrapFetchOutbound as canonicalWrapFetchOutbound,
} from '../fetch/fetch-outbound';

import { defaultFetchOutbound, wrapFetchOutbound } from './fetch';
import type { FetchOutbound, HttpCallRecord } from './types';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('verifier/fetch — canonical re-export', () => {
  it('wrapFetchOutbound is the canonical primitive (pointer identity)', () => {
    expect(wrapFetchOutbound).toBe(canonicalWrapFetchOutbound);
  });
  it('defaultFetchOutbound is the canonical primitive (pointer identity)', () => {
    expect(defaultFetchOutbound).toBe(canonicalDefaultFetchOutbound);
  });
});

describe('defaultFetchOutbound', () => {
  it('invokes globalThis.fetch and returns shape {status, bytes, durationMs}', async () => {
    const body = new Uint8Array([1, 2, 3, 4]);
    const fakeResponse = new Response(body, { status: 200 });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(fakeResponse);

    const result = await defaultFetchOutbound('https://example.com/x', {
      method: 'GET',
      purpose: 'cardano',
    });

    expect(fetchSpy).toHaveBeenCalledOnce();
    expect(result.status).toBe(200);
    expect(result.bytes).toBeInstanceOf(Uint8Array);
    expect(Array.from(result.bytes)).toEqual([1, 2, 3, 4]);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('forwards method, headers, body to fetch', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(new Uint8Array(0), { status: 200 }));
    await defaultFetchOutbound('https://example.com/x', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"x":1}',
      purpose: 'cardano',
    });
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(init.body).toBe('{"x":1}');
    expect((init.headers as Record<string, string>)['content-type']).toBe('application/json');
  });
});

describe('wrapFetchOutbound — success path', () => {
  it('records exactly one audit row per call', async () => {
    const audit: HttpCallRecord[] = [];
    const inner: FetchOutbound = async () => ({
      status: 200,
      bytes: new Uint8Array([7, 7, 7]),
      durationMs: 5,
    });
    const wrapped = wrapFetchOutbound(inner, audit, undefined);
    const r = await wrapped('https://example.com/x', { method: 'GET', purpose: 'arweave' });
    expect(r.status).toBe(200);
    expect(audit.length).toBe(1);
    expect(audit[0]!.status).toBe(200);
    expect(audit[0]!.bytes).toBe(3);
    expect(audit[0]!.purpose).toBe('arweave');
    expect(audit[0]!.url).toBe('https://example.com/x');
  });

  it('preserves audit ordering across multiple calls', async () => {
    const audit: HttpCallRecord[] = [];
    const inner: FetchOutbound = async (url) => ({
      status: 200,
      bytes: new TextEncoder().encode(url),
      durationMs: 0,
    });
    const wrapped = wrapFetchOutbound(inner, audit, undefined);
    await wrapped('https://a/', { method: 'GET', purpose: 'cardano' });
    await wrapped('https://b/', { method: 'GET', purpose: 'cardano' });
    expect(audit.map((a) => a.url)).toEqual(['https://a/', 'https://b/']);
  });
});

describe('wrapFetchOutbound — failure path', () => {
  it('pushes status:0 row and re-throws original error when inner throws', async () => {
    const audit: HttpCallRecord[] = [];
    const original = new Error('network down');
    const inner: FetchOutbound = async () => {
      throw original;
    };
    const wrapped = wrapFetchOutbound(inner, audit, undefined);
    await expect(
      wrapped('https://example.com/x', { method: 'GET', purpose: 'cardano' }),
    ).rejects.toBe(original);
    expect(audit.length).toBe(1);
    expect(audit[0]!.status).toBe(0);
    expect(audit[0]!.bytes).toBe(0);
    expect(audit[0]!.duration_ms).toBeGreaterThanOrEqual(0);
  });
});

describe('wrapFetchOutbound — denyHosts', () => {
  it('exact match: pushes audit row + throws SERVICE_INDEPENDENCE_VIOLATION; inner not called', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>().mockResolvedValue({
      status: 200,
      bytes: new Uint8Array(0),
      durationMs: 0,
    });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, ['cardanowall.com']);
    await expect(
      wrapped('https://cardanowall.com/anything', { method: 'GET', purpose: 'https' }),
    ).rejects.toThrow(/SERVICE_INDEPENDENCE_VIOLATION/);
    expect(inner).not.toHaveBeenCalled();
    expect(audit.length).toBe(1);
    expect(audit[0]!.status).toBe(0);
  });

  it('wildcard match: *.cardanowall.com matches viewer.cardanowall.com but not bare cardanowall.com', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>().mockResolvedValue({
      status: 200,
      bytes: new Uint8Array(0),
      durationMs: 0,
    });
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, ['*.cardanowall.com']);
    await expect(
      wrapped('https://viewer.cardanowall.com/x', { method: 'GET', purpose: 'https' }),
    ).rejects.toThrow(/SERVICE_INDEPENDENCE_VIOLATION/);
    // bare host is NOT matched by wildcard
    await wrapped('https://cardanowall.com/x', { method: 'GET', purpose: 'https' });
    expect(inner).toHaveBeenCalledOnce();
  });

  it('case-insensitive + trailing-dot tolerant', async () => {
    const audit: HttpCallRecord[] = [];
    const inner: FetchOutbound = async () => ({
      status: 200,
      bytes: new Uint8Array(0),
      durationMs: 0,
    });
    const wrapped = wrapFetchOutbound(inner, audit, ['cardanowall.com']);
    // URL.hostname lowercases automatically; trailing dot stays in the URL but
    // the wrap normalises it. Test both via URLs that would survive parsing.
    await expect(
      wrapped('https://CardanoWall.com./x', { method: 'GET', purpose: 'https' }),
    ).rejects.toThrow(/SERVICE_INDEPENDENCE_VIOLATION/);
  });
});
