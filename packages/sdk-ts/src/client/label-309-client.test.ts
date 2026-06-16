// Unit tests for Label309Client + namespace wiring.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

  it('uses the base URL verbatim and strips a single trailing slash', () => {
    const fetchMock = recordsListFetchMock();
    // Base carries the version segment; a trailing slash is stripped so the
    // appended `/records` suffix does not produce a double slash.
    const client = new Label309Client({
      baseUrl: 'http://localhost:3000/api/v1/',
      fetch: fetchMock,
    });
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
      baseUrl: 'https://gw.test.example/api/v1',
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

// Shared cross-SDK base_url-join parity matrix — loaded from a fixture that is
// mirrored BYTE-IDENTICALLY across the three Label 309 SDKs (label-309-ts,
// label-309-py, label-309-rs), each carrying its own self-contained copy because
// they publish to separate repositories. The matrix pins the one normalization
// rule and the one append rule the three clients must agree on:
//
//   final URL = strip-at-most-one-trailing-slash(trim(baseUrl)) + suffix
//
// where the suffix always begins with `/`, never contains a version segment,
// and the join is a plain string concat (no URL() recomposition, no
// double-slash collapse). Because the version segment lives entirely in the
// configured base, the SAME (base, suffix) pair yields the SAME bytes in every
// language. The `base + "//"` multi-slash rows are load-bearing: only ONE
// trailing slash is stripped, so the surviving slash appears verbatim in the
// path. The whitespace rows pin the trim-before-join. The `origin-only` rows
// prove the client injects no `/api/v1` of its own. Every suffix is driven
// through the real namespace call so the assertion exercises the production
// join path. Any edit to the matrix MUST be mirrored to all three SDK copies.
describe('Label309Client — base_url-join parity matrix', () => {
  interface ParityCase {
    readonly name: string;
    readonly base_url: string;
    readonly suffix: string;
    readonly expected_url: string;
  }
  const here = path.dirname(fileURLToPath(import.meta.url));
  const vectors = JSON.parse(
    fs.readFileSync(
      path.resolve(here, '../../tests/fixtures/client-url-join/base-url-join-vectors.json'),
      'utf8',
    ),
  ) as { readonly cases: ReadonlyArray<ParityCase> };

  // A 64-char hex tx hash, matching the `/records/<tx_hash>` suffixes the shared
  // matrix pins. The same literal is baked into the fixture, so each driver MUST
  // call with this exact value for the joined URL to match byte-for-byte.
  const TX = 'a'.repeat(64);

  function jsonResponse(body: unknown): Response {
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }

  const PUBLISH_BODY = {
    id: 'poe_06bqrjg0csvqfanaqexvqexvqc',
    tx_hash: null,
    status: 'submitting',
    items_count: 1,
    signed: false,
    sealed: false,
    items: [],
    conformance_profile: 'core',
    balance_after_usd_micros: '4500000',
  };

  // Maps each resource suffix in the shared matrix to (real namespace call, stub
  // response body) so the test drives the ACTUAL client join path (resolve base
  // + concat) for every suffix. The set is exactly the suffixes present in all
  // three SDK client modules.
  const DRIVERS: ReadonlyMap<
    string,
    { readonly call: (c: Label309Client) => Promise<unknown>; readonly body: unknown }
  > = new Map([
    ['/records', { call: (c) => c.records.list(), body: JSON.parse(RECORDS_LIST_BODY) }],
    [`/records/${TX}`, { call: (c) => c.records.get(TX), body: {} }],
    ['/account/balance', { call: (c) => c.account.balance(), body: { balance_usd_micros: '0' } }],
    [
      '/poe/quote',
      {
        call: (c) => c.poe.quote({ recordBytes: 1, recipientCount: 0, fileBytesTotal: 0 }),
        body: { quote_id: 'q', amount: '1', currency: 'USD', expires_at: '2026-01-01T00:00:00Z' },
      },
    ],
    [
      '/poe/publish',
      { call: (c) => c.poe.publish({ record: 'aa', quoteId: 'q' }), body: PUBLISH_BODY },
    ],
    [
      '/poe/publish-batch',
      {
        call: (c) => c.poe.publishBatch({ records: [{ record: 'aa', quoteId: 'q' }] }),
        body: { results: [], balance_after_usd_micros: '4500000' },
      },
    ],
    [
      '/poe/uploads',
      {
        call: (c) => c.poe.uploads({ target: 'arweave', data: [new Uint8Array([0xaa])] }),
        body: {
          uploads: [
            { idx: 0, ok: true, uri: `ar://${'A'.repeat(43)}`, sha256: '00'.repeat(32), bytes: 1 },
          ],
        },
      },
    ],
  ]);

  // Every suffix in the matrix must have a real driver, and vice versa — a
  // divergence means a suffix was added/removed on one side.
  it('drives every matrix suffix and no extras', () => {
    expect(new Set(vectors.cases.map((c) => c.suffix))).toEqual(new Set(DRIVERS.keys()));
  });

  for (const c of vectors.cases) {
    it(`joins ${JSON.stringify(c.base_url)} + ${JSON.stringify(c.suffix)} by plain concat`, async () => {
      const driver = DRIVERS.get(c.suffix);
      if (driver === undefined) throw new Error(`no driver for suffix ${c.suffix}`);
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse(driver.body));
      const client = new Label309Client({
        baseUrl: c.base_url,
        apiKey: 'opaque',
        fetch: fetchMock as unknown as FetchImpl,
      });
      await driver.call(client);
      // The driver calls append no query string, so the request URL equals
      // normalize(base) + suffix byte-for-byte.
      expect(String(fetchMock.mock.calls[0]![0])).toBe(c.expected_url);
    });
  }
});
