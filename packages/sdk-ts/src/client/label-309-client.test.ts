// Unit tests for Label309Client + namespace wiring.

import { describe, expect, it, vi } from 'vitest';

import { Label309Client } from './label-309-client';
import { InvalidClientConfigError } from './invalid-client-config-error';
import { PoeNamespace } from './poe';
import { RecordsNamespace } from './records';
import type { FetchImpl } from './types';

const RECORDS_LIST_BODY = JSON.stringify({
  object: 'list',
  data: [],
  has_more: false,
  next_cursor: null,
  url: '/api/v1/records?sealed=true',
});

function recordsListFetchMock(): ReturnType<typeof vi.fn> & FetchImpl {
  return vi.fn().mockResolvedValue(
    new Response(RECORDS_LIST_BODY, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  ) as unknown as ReturnType<typeof vi.fn> & FetchImpl;
}

function authHeader(fetchMock: ReturnType<typeof vi.fn>): string | null {
  const init = fetchMock.mock.calls[0]![1] as RequestInit;
  return (init.headers as Headers).get('authorization');
}

describe('Label309Client', () => {
  it('wires up poe + records namespaces against an explicit base URL', () => {
    const client = new Label309Client({
      baseUrl: 'https://gateway.example.com',
      fetch: vi.fn(),
    });
    expect(client.poe).toBeInstanceOf(PoeNamespace);
    expect(client.records).toBeInstanceOf(RecordsNamespace);
  });

  it('uses the base URL verbatim and strips a trailing slash', () => {
    const fetchMock = recordsListFetchMock();
    const client = new Label309Client({ baseUrl: 'http://localhost:3000/', fetch: fetchMock });
    void client.records.list({ sealed: true });
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('http://localhost:3000/api/v1/records?sealed=true'),
      expect.anything(),
    );
  });

  it('threads the API key into Authorization header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'poe_06bqrjg0csvqfanaqexvqexvqc',
          tx_hash: null,
          status: 'submitting',
          items_count: 1,
          signed: false,
          sealed: false,
          items: [],
          conformance_profile: 'core',
          balance_after_usd_micros: '4500000',
        }),
        {
          status: 202,
          headers: { 'content-type': 'application/json' },
        },
      ),
    );
    const apiKey = 'opaque-bearer-token';
    const client = new Label309Client({
      baseUrl: 'https://gateway.example.com',
      apiKey,
      fetch: fetchMock,
    });
    await client.poe.publish({ record: 'aa', quoteId: '01956b41-7c00-7000-8000-000000000001' });
    const callArgs = fetchMock.mock.calls[0]!;
    const init = callArgs[1] as RequestInit;
    const headers = init.headers as Headers;
    expect(headers.get('authorization')).toBe(`Bearer ${apiKey}`);
  });

  it('uses globalThis.fetch when no fetch is provided', () => {
    // Should not throw — globalThis.fetch exists in Vitest environment.
    expect(() => new Label309Client({ baseUrl: 'https://gateway.example.com' })).not.toThrow();
  });

  it('throws when no fetch impl is available', () => {
    const original = globalThis.fetch;
    // @ts-expect-error — deliberately blanking globalThis.fetch for the test
    globalThis.fetch = undefined;
    try {
      expect(() => new Label309Client({ baseUrl: 'https://gateway.example.com' })).toThrow(
        /no fetch implementation/,
      );
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe('Label309Client — config resolution contract', () => {
  it('accepts an arbitrary opaque bearer key against any base URL', () => {
    // A vendor key in some unknown format — the SDK never inspects it.
    const client = new Label309Client({
      baseUrl: 'https://gateway.example.com',
      apiKey: 'whatever-format-the-vendor-likes',
      fetch: vi.fn(),
    });
    expect(client.poe).toBeInstanceOf(PoeNamespace);
  });

  it('forwards the opaque key verbatim as a Bearer token', async () => {
    const fetchMock = recordsListFetchMock();
    const opaque = 'opaque-vendor-token-123';
    const client = new Label309Client({
      baseUrl: 'https://gateway.example.com',
      apiKey: opaque,
      fetch: fetchMock,
    });
    await client.records.list({ sealed: true });
    expect(authHeader(fetchMock)).toBe(`Bearer ${opaque}`);
  });

  it('targets the supplied base URL regardless of key shape', async () => {
    const fetchMock = recordsListFetchMock();
    const client = new Label309Client({
      baseUrl: 'https://gw.test.example',
      apiKey: 'some-key',
      fetch: fetchMock,
    });
    await client.records.list({ sealed: true });
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('https://gw.test.example/api/v1/records'),
      expect.anything(),
    );
  });

  it('stays anonymous (no Authorization header) when no key is given', async () => {
    const fetchMock = recordsListFetchMock();
    const client = new Label309Client({
      baseUrl: 'https://gateway.example.com',
      fetch: fetchMock,
    });
    await client.records.list({ sealed: true });
    expect(authHeader(fetchMock)).toBeNull();
  });

  it('throws InvalidClientConfigError when baseUrl is missing', () => {
    expect(
      // @ts-expect-error — baseUrl is required; exercising the runtime guard
      () => new Label309Client({ apiKey: 'some-key', fetch: vi.fn() }),
    ).toThrow(InvalidClientConfigError);
  });

  it('throws InvalidClientConfigError when baseUrl is empty/whitespace', () => {
    expect(() => new Label309Client({ baseUrl: '   ', fetch: vi.fn() })).toThrow(
      InvalidClientConfigError,
    );
  });
});
