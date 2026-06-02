// Unit tests for the low-level client.poe.* surface — quote(), uploads(),
// publish(), publishBatch().

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it, vi } from 'vitest';

import { BatchTooLargeError } from './batch-too-large-error';
import { Cip309Client } from './cip309-client';
import { IdempotencyConflictError } from './idempotency-conflict-error';
import { InsufficientFundsError } from './insufficient-funds-error';
import { InsufficientScopeError } from './insufficient-scope-error';
import { InternalServerError } from './internal-server-error';
import { InvalidBodyError } from './invalid-body-error';
import { MalformedCborError } from './malformed-cbor-error';
import { QuoteAlreadyConsumedError } from './quote-already-consumed-error';
import { QuoteExpiredError } from './quote-expired-error';
import { QuoteNotFoundError } from './quote-not-found-error';
import { RateLimitedError } from './rate-limited-error';
import { ServiceUnavailableError } from './service-unavailable-error';
import { UnauthorizedError } from './unauthorized-error';

const PROBLEM_CT = 'application/problem+json';
const JSON_CT = 'application/json';

const QUOTE_ID = '01956b41-7c00-7000-8000-000000000001';

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': JSON_CT, ...headers },
  });
}

function problemResponse(
  body: Record<string, unknown>,
  status: number,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': PROBLEM_CT, ...headers },
  });
}

function problemBody(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    type: 'https://cardanowall.com/problems/example',
    title: 'Example',
    status: 400,
    detail: 'Example failure.',
    code: 'example',
    trace_id: '01977c00-0000-7000-8000-000000000000',
    ...overrides,
  };
}

function makeClient(fetchMock: ReturnType<typeof vi.fn>): Cip309Client {
  return new Cip309Client({
    baseUrl: 'https://cardanowall.com',
    apiKey: 'opaque-bearer-token',
    fetch: fetchMock as unknown as typeof globalThis.fetch,
  });
}

const PUBLISH_SUCCESS_BODY = {
  id: 'poe_06bqrjg0csvqfanaqexvqexvqc',
  tx_hash: null,
  status: 'submitting' as const,
  items_count: 1,
  signed: false,
  sealed: false,
  items: [],
  conformance_profile: 'core' as const,
  balance_after_usd_micros: '4500000',
};

const UPLOADS_SUCCESS_BODY = {
  uploads: [
    {
      idx: 0,
      ok: true as const,
      uri: `ar://${'A'.repeat(43)}`,
      sha256: '00'.repeat(32),
      bytes: 1,
    },
  ],
};

// Opaque price lock: an id, the locked total `amount` in `currency`, and an
// expiry — no pricing breakdown on the public surface.
const QUOTE_SUCCESS_BODY = {
  quote_id: QUOTE_ID,
  amount: '180000',
  currency: 'USD',
  expires_at: '2026-05-26T12:15:00.000Z',
};

describe('PoeNamespace.quote', () => {
  it('POSTs JSON {record_bytes, recipient_count, file_bytes_total} and returns quote', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(QUOTE_SUCCESS_BODY, 200));
    const client = makeClient(fetchMock);
    const out = await client.poe.quote({
      recordBytes: 256,
      recipientCount: 1,
      fileBytesTotal: 1_048_576,
    });

    expect(out.quote_id).toBe(QUOTE_ID);
    expect(out.amount).toBe('180000');
    expect(out.currency).toBe('USD');
    expect(out.expires_at).toBe('2026-05-26T12:15:00.000Z');
    // The opaque price lock exposes no pricing internals.
    expect(out).not.toHaveProperty('breakdown');
    expect(out).not.toHaveProperty('margin_pct');
    expect(out).not.toHaveProperty('fx_age_seconds');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://cardanowall.com/api/v1/poe/quote');
    const body = JSON.parse((init as { body: string }).body) as Record<string, number>;
    expect(body).toEqual({
      record_bytes: 256,
      recipient_count: 1,
      file_bytes_total: 1_048_576,
    });
  });

  it('maps a 503 pricing outage to ServiceUnavailableError', async () => {
    // A gateway that prices on a live oracle may return `fx-stale`; the
    // vendor-neutral client surfaces it as the generic service-unavailable.
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'fx-stale',
          status: 503,
          title: 'Service Unavailable',
          detail: 'Pricing temporarily unavailable.',
        }),
        503,
      ),
    );
    const client = makeClient(fetchMock);
    const err = await client.poe
      .quote({ recordBytes: 256, recipientCount: 0, fileBytesTotal: 0 })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('PoeNamespace.uploads', () => {
  it('POSTs multipart with target + file_<idx> fields, returns {uploads}', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(UPLOADS_SUCCESS_BODY));
    const client = makeClient(fetchMock);
    const out = await client.poe.uploads({
      target: 'arweave',
      data: [new Uint8Array([0xaa]), new Uint8Array([0xbb])],
    });
    expect(out.uploads).toHaveLength(1);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://cardanowall.com/api/v1/poe/uploads');
    const body = (init as { body: FormData }).body;
    expect(body).toBeInstanceOf(FormData);
    expect(body.get('target')).toBe('arweave');
    expect(body.has('file_0')).toBe(true);
    expect(body.has('file_1')).toBe(true);
    expect(body.has('file_2')).toBe(false);
  });

  it('threads idempotencyKey into the Idempotency-Key header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(UPLOADS_SUCCESS_BODY));
    const client = makeClient(fetchMock);
    await client.poe.uploads({
      target: 'arweave',
      data: [new Uint8Array([0xaa])],
      idempotencyKey: 'idem-u-1',
    });
    const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Headers;
    expect(headers.get('idempotency-key')).toBe('idem-u-1');
  });

  it('returns a partial-failure response verbatim (per-file failures not thrown)', async () => {
    const mixed = {
      uploads: [
        { idx: 0, ok: true, uri: `ar://${'A'.repeat(43)}`, sha256: '00'.repeat(32), bytes: 1 },
        { idx: 1, ok: false, error: { code: 'upload-failed', detail: 'arweave timeout' } },
      ],
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(mixed));
    const client = makeClient(fetchMock);
    const out = await client.poe.uploads({
      target: 'arweave',
      data: [new Uint8Array([0xaa]), new Uint8Array([0xbb])],
    });
    expect(out.uploads).toHaveLength(2);
    expect(out.uploads[0]!.ok).toBe(true);
    expect(out.uploads[1]!.ok).toBe(false);
  });
});

describe('PoeNamespace.publish', () => {
  it('hex-encodes a Uint8Array record + posts JSON with quote_id', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_SUCCESS_BODY, 202));
    const client = makeClient(fetchMock);
    const out = await client.poe.publish({
      record: new Uint8Array([0xaa, 0xbb]),
      quoteId: QUOTE_ID,
    });
    expect(out.id).toBe(PUBLISH_SUCCESS_BODY.id);
    expect(out.balance_after_usd_micros).toBe('4500000');
    expect(out.dedup_hit).toBe(false);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://cardanowall.com/api/v1/poe/publish');
    const body = JSON.parse((init as { body: string }).body) as {
      record: string;
      quote_id: string;
    };
    expect(body.record).toBe('aabb');
    expect(body.quote_id).toBe(QUOTE_ID);
  });

  it('accepts a hex-string record verbatim', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_SUCCESS_BODY, 202));
    const client = makeClient(fetchMock);
    await client.poe.publish({ record: 'deadbeef', quoteId: QUOTE_ID });
    const body = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body) as {
      record: string;
      quote_id: string;
    };
    expect(body.record).toBe('deadbeef');
    expect(body.quote_id).toBe(QUOTE_ID);
  });

  it('reports dedup_hit=true when the server returns 200', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_SUCCESS_BODY, 200));
    const client = makeClient(fetchMock);
    const out = await client.poe.publish({ record: 'aa', quoteId: QUOTE_ID });
    expect(out.dedup_hit).toBe(true);
  });

  it('reports dedup_hit=false when the server returns 202', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_SUCCESS_BODY, 202));
    const client = makeClient(fetchMock);
    const out = await client.poe.publish({ record: 'aa', quoteId: QUOTE_ID });
    expect(out.dedup_hit).toBe(false);
  });

  it('threads idempotencyKey into the Idempotency-Key header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_SUCCESS_BODY, 202));
    const client = makeClient(fetchMock);
    await client.poe.publish({ record: 'aa', quoteId: QUOTE_ID, idempotencyKey: 'idem-p-1' });
    const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Headers;
    expect(headers.get('idempotency-key')).toBe('idem-p-1');
  });

  it('forwards signatures verbatim', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_SUCCESS_BODY, 202));
    const client = makeClient(fetchMock);
    await client.poe.publish({
      record: 'aa',
      quoteId: QUOTE_ID,
      signatures: [{ cose_sign1: 'beef', cose_key: 'cafe' }],
    });
    const body = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body) as {
      record: string;
      quote_id: string;
      signatures: ReadonlyArray<{ cose_sign1: string; cose_key?: string }>;
    };
    expect(body.signatures).toEqual([{ cose_sign1: 'beef', cose_key: 'cafe' }]);
  });

  it('throws InsufficientFundsError on 402 with typed bigint USD-micro fields', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'insufficient-funds',
          status: 402,
          title: 'Payment Required',
          detail: 'Required $0.18; balance $0.00.',
          balance_usd_micros: '0',
          required_usd_micros: '180000',
          top_up_url: '/billing/top-up',
        }),
        402,
      ),
    );
    const client = makeClient(fetchMock);
    const err = await client.poe
      .publish({ record: 'aa', quoteId: QUOTE_ID })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(InsufficientFundsError);
    expect((err as InsufficientFundsError).balanceUsdMicros).toBe(0n);
    expect((err as InsufficientFundsError).requiredUsdMicros).toBe(180_000n);
    expect((err as InsufficientFundsError).topUpUrl).toBe('/billing/top-up');
  });

  it('throws QuoteExpiredError on 410 quote-expired with the projected quoteId', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'quote-expired',
          status: 410,
          title: 'Gone',
          detail: 'Quote expired.',
          quote_id: QUOTE_ID,
        }),
        410,
      ),
    );
    const client = makeClient(fetchMock);
    const err = await client.poe
      .publish({ record: 'aa', quoteId: QUOTE_ID })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(QuoteExpiredError);
    expect((err as QuoteExpiredError).quoteId).toBe(QUOTE_ID);
  });

  it('throws QuoteAlreadyConsumedError on 409 quote-already-consumed', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'quote-already-consumed',
          status: 409,
          title: 'Conflict',
          detail: 'Quote already used.',
          quote_id: QUOTE_ID,
        }),
        409,
      ),
    );
    const client = makeClient(fetchMock);
    await expect(client.poe.publish({ record: 'aa', quoteId: QUOTE_ID })).rejects.toBeInstanceOf(
      QuoteAlreadyConsumedError,
    );
  });

  it('throws QuoteNotFoundError on 404 quote-not-found', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'quote-not-found',
          status: 404,
          title: 'Not Found',
          detail: 'Quote not found.',
          quote_id: QUOTE_ID,
        }),
        404,
      ),
    );
    const client = makeClient(fetchMock);
    await expect(client.poe.publish({ record: 'aa', quoteId: QUOTE_ID })).rejects.toBeInstanceOf(
      QuoteNotFoundError,
    );
  });

  it('throws RateLimitedError on 429 with retryAfterSeconds taken from Retry-After', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'rate-limited',
          status: 429,
          title: 'Too Many Requests',
          detail: 'API-key rate limit exceeded.',
        }),
        429,
        { 'retry-after': '7' },
      ),
    );
    const client = makeClient(fetchMock);
    const err = await client.poe
      .publish({ record: 'aa', quoteId: QUOTE_ID })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RateLimitedError);
    expect((err as RateLimitedError).retryAfterSeconds).toBe(7);
  });

  it('throws IdempotencyConflictError on 409', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'idempotency-key-conflict',
          status: 409,
          title: 'Idempotency Key Conflict',
          detail: 'Reuse with different body.',
        }),
        409,
      ),
    );
    await expect(
      makeClient(fetchMock).poe.publish({ record: 'aa', quoteId: QUOTE_ID }),
    ).rejects.toBeInstanceOf(IdempotencyConflictError);
  });

  it('throws UnauthorizedError on 401', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'unauthorized',
          status: 401,
          title: 'Unauthorized',
          detail: 'Auth required.',
        }),
        401,
      ),
    );
    await expect(
      makeClient(fetchMock).poe.publish({ record: 'aa', quoteId: QUOTE_ID }),
    ).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it('throws InsufficientScopeError on 403', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'insufficient-scope',
          status: 403,
          title: 'Insufficient Scope',
          detail: 'API key lacks poe:create.',
          required: ['poe:create'],
          granted: ['poe:read'],
        }),
        403,
      ),
    );
    await expect(
      makeClient(fetchMock).poe.publish({ record: 'aa', quoteId: QUOTE_ID }),
    ).rejects.toBeInstanceOf(InsufficientScopeError);
  });

  it('throws InvalidBodyError on 400 invalid-body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'invalid-body',
          status: 400,
          title: 'Invalid Request Body',
          detail: 'Body not JSON.',
        }),
        400,
      ),
    );
    await expect(
      makeClient(fetchMock).poe.publish({ record: 'aa', quoteId: QUOTE_ID }),
    ).rejects.toBeInstanceOf(InvalidBodyError);
  });

  it('throws MalformedCborError on 400 malformed-cbor', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'malformed-cbor',
          status: 400,
          title: 'Malformed CBOR',
          detail: 'record is not canonical CBOR.',
        }),
        400,
      ),
    );
    await expect(
      makeClient(fetchMock).poe.publish({ record: 'zz', quoteId: QUOTE_ID }),
    ).rejects.toBeInstanceOf(MalformedCborError);
  });

  it('throws InternalServerError on 500', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'internal-error',
          status: 500,
          title: 'Internal Server Error',
          detail: 'Boom.',
        }),
        500,
      ),
    );
    await expect(
      makeClient(fetchMock).poe.publish({ record: 'aa', quoteId: QUOTE_ID }),
    ).rejects.toBeInstanceOf(InternalServerError);
  });

  it('threads X-Request-Id onto err.requestId for log correlation', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'internal-error',
          status: 500,
          title: 'Internal Server Error',
          detail: 'Boom.',
        }),
        500,
        { 'x-request-id': 'req-correlate' },
      ),
    );
    const err = await makeClient(fetchMock)
      .poe.publish({ record: 'aa', quoteId: QUOTE_ID })
      .catch((e: unknown) => e);
    expect((err as InternalServerError).requestId).toBe('req-correlate');
  });
});

describe('PoeNamespace.publishBatch', () => {
  it('POSTs JSON {records: [...]} with quote_id per record, hex-encodes Uint8Array records', async () => {
    const responseBody = {
      results: [
        {
          record_idx: 0,
          id: 'poe_06bqrjg0csvqfanaqexvqexvqc',
          tx_hash: null,
          status: 'submitting',
          items_count: 1,
          signed: false,
          sealed: false,
          items: [],
          conformance_profile: 'core',
        },
        {
          record_idx: 1,
          error: { code: 'malformed-cbor', detail: 'record is not canonical CBOR.' },
        },
      ],
      balance_after_usd_micros: '4320000',
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(responseBody, 200));
    const client = makeClient(fetchMock);
    const out = await client.poe.publishBatch({
      records: [
        { record: new Uint8Array([0xaa]), quoteId: QUOTE_ID },
        { record: 'bbcc', quoteId: '01956b41-7c00-7000-8000-000000000002' },
      ],
    });
    expect(out.results).toHaveLength(2);
    expect(out.balance_after_usd_micros).toBe('4320000');

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://cardanowall.com/api/v1/poe/publish-batch');
    const body = JSON.parse((init as { body: string }).body) as {
      records: ReadonlyArray<{ record: string; quote_id: string }>;
    };
    expect(body.records[0]!.record).toBe('aa');
    expect(body.records[0]!.quote_id).toBe(QUOTE_ID);
    expect(body.records[1]!.record).toBe('bbcc');
    expect(body.records[1]!.quote_id).toBe('01956b41-7c00-7000-8000-000000000002');
  });

  it('throws BatchTooLargeError when the server rejects an oversize batch', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        problemBody({
          code: 'batch-too-large',
          status: 400,
          title: 'Batch Too Large',
          detail: 'Batch carries 73 record(s); the maximum is 50.',
          max: 50,
          got: 73,
        }),
        400,
      ),
    );
    const err = await makeClient(fetchMock)
      .poe.publishBatch({ records: [{ record: 'aa', quoteId: QUOTE_ID }] })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BatchTooLargeError);
    const typed = err as BatchTooLargeError;
    expect(typed.max).toBe(50);
    expect(typed.got).toBe(73);
  });
});

describe('PoeNamespace request-shape parity fixture', () => {
  // Capture the exact HTTP request shape both SDKs (TS + Py) must produce for
  // the canonical client.poe.publish({record: <16 bytes>, quoteId}) call. The
  // fixture JSON at tests/fixtures/poe-request/poe-publish-request.json is the
  // single source of truth and is mirrored byte-identically by the Python SDK
  // — both languages load it from disk and assert their captured request
  // against it, so a divergence between the two SDKs OR a stale local fixture
  // surfaces as a test failure on at least one side.
  //
  // The body comparison is parsed-then-canonicalised (sort keys, no
  // whitespace) rather than raw-byte: the Py SDK emits `json.dumps(...)` with
  // its default `": "` / `", "` whitespace, while TS `JSON.stringify` emits
  // compact. Both encode the same logical payload. Structural equality holds
  // the wire contract (field names + values) without forcing a same-PR
  // touch-up of the Py serialiser.
  function canonicaliseJsonBody(raw: string): string {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const sortedKeys = Object.keys(parsed).sort();
    const ordered: Record<string, unknown> = {};
    for (const k of sortedKeys) ordered[k] = parsed[k];
    return JSON.stringify(ordered);
  }

  it('TS produces the canonical /poe/publish request shape', async () => {
    const fixturePath = join(
      fileURLToPath(new URL('.', import.meta.url)),
      '..',
      '..',
      'tests',
      'fixtures',
      'poe-request',
      'poe-publish-request.json',
    );
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
      readonly method: string;
      readonly url: string;
      readonly authorization: string;
      readonly content_type: string;
      readonly accept: string;
      readonly body: string;
    };

    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_SUCCESS_BODY, 202));
    const client = new Cip309Client({
      apiKey: `sk-cw-live-${'b'.repeat(52)}`,
      baseUrl: 'http://test.example',
      fetch: fetchMock as unknown as typeof globalThis.fetch,
    });
    // 16 bytes of canonical-CBOR-shaped placeholder — the fixture only pins
    // the wire shape, not record contents.
    await client.poe.publish({ record: 'aa'.repeat(16), quoteId: QUOTE_ID });

    const [url, init] = fetchMock.mock.calls[0]!;
    const headers = (init as RequestInit).headers as Headers;
    expect(String(url)).toBe(fixture.url);
    expect((init as RequestInit).method).toBe(fixture.method);
    expect(headers.get('authorization')).toBe(fixture.authorization);
    expect(headers.get('content-type')).toBe(fixture.content_type);
    expect(headers.get('accept')).toBe(fixture.accept);
    const sentBody = String((init as RequestInit).body);
    expect(canonicaliseJsonBody(sentBody)).toBe(canonicaliseJsonBody(fixture.body));
  });
});
