// Unit tests for client.records.* — the records read namespace that wraps
// `GET /api/v1/records`, `GET /api/v1/records/{tx_hash}`, and
// `POST /api/v1/records/{tx_hash}/verify`.
//
// Test shape mirrors the server fixture: we assert on the actual HTTP request
// shape (URL, method, headers, body) AND on the response being parsed into
// the typed `RecordResource` / `VerifyReport`. The previous incarnation of
// these tests (under `client.poe.get/verify`) was mock-asserts-input — it
// would have continued to pass even when the methods hit a non-existent
// URL. The fixtures below come from the real server response shapes
// (the server's RecordResource schema; VerifyReport in
// `src/verifier/types.ts`).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it, vi } from 'vitest';

import { Label309Client } from './label-309-client';
import { RecordNotFoundError } from './record-not-found-error';
import type { RecordResource } from './types';
import type { VerifyReport } from '../verifier/types';

const TX_HASH = 'a'.repeat(64);
const ACCOUNT_ID = 'acct_06bqrjg0csvqfanaqexvqexvqc';

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function problemResponse(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/problem+json' },
  });
}

function makeClient(fetchMock: ReturnType<typeof vi.fn>): Label309Client {
  return new Label309Client({
    apiKey: `sk-cw-live-${'a'.repeat(52)}`,
    baseUrl: 'http://test.example',
    fetch: fetchMock as unknown as typeof globalThis.fetch,
  });
}

// Realistic RecordResource fixture — fields match the server projection
// (chain-anchored row at the confirmation threshold). Owner sees account_id;
// stripped from the non-owner / anonymous fixture.
function recordFixture(overrides: Partial<RecordResource> = {}): RecordResource {
  return {
    tx_hash: TX_HASH,
    status: 'confirmed',
    block_height: 12_345_678,
    block_time: '2026-01-01T00:00:00.000Z',
    num_confirmations: 100,
    scheme: 0,
    item_count: 1,
    signer_ed25519: null,
    metadata_cbor_base64: 'oWNmb29jYmFy',
    ...overrides,
  };
}

// Realistic VerifyReport fixture — mirrors the shape `verifyReportToDict`
// emits and the server returns verbatim.
function verifyReportFixture(overrides: Partial<VerifyReport> = {}): VerifyReport {
  return {
    txHash: TX_HASH,
    network: 'cardano:mainnet',
    verdict: 'valid',
    exitCode: 0,
    profile: 'core',
    confirmationDepth: 100,
    confirmationThreshold: 12,
    block_time: 1767225600,
    issues: [],
    items: [{ contentCheck: 'not_checked' }],
    merkle: [],
    auditTrail: [],
    ...overrides,
  };
}

describe('RecordsNamespace.list', () => {
  it('GETs /api/v1/records?sealed=true&... and returns RecordResource page entries', async () => {
    const page = {
      object: 'list',
      data: [recordFixture(), recordFixture({ tx_hash: 'b'.repeat(64) })],
      has_more: true,
      next_cursor: 'opaque-next',
      url: '/api/v1/records?sealed=true',
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(page));
    const out = await makeClient(fetchMock).records.list({
      sealed: true,
      cursor: 'eyJjdXIiOjF9',
      limit: 25,
    });

    // Page projects to the same RecordResource shape records.get returns —
    // assert on the data, not just a label.
    expect(out.object).toBe('list');
    expect(out.data).toHaveLength(2);
    expect(out.data[0]!.tx_hash).toBe(TX_HASH);
    expect(out.data[0]!.metadata_cbor_base64).toBe('oWNmb29jYmFy');
    expect(out.data[1]!.tx_hash).toBe('b'.repeat(64));
    expect(out.next_cursor).toBe('opaque-next');
    expect(out.has_more).toBe(true);
    // The gateway omits `tip_block_height`, so the SDK derives it from the page
    // as max(block_height + num_confirmations - 1) = 12_345_678 + 100 - 1.
    expect(out.tip_block_height).toBe(12_345_777);

    const callUrl = String(fetchMock.mock.calls[0]![0]);
    expect(callUrl).toContain('http://test.example/api/v1/records?');
    expect(callUrl).toContain('sealed=true');
    expect(callUrl).toContain('limit=25');
    expect(callUrl).toContain('cursor=eyJjdXIiOjF9');
    expect(String(callUrl)).not.toContain('/api/v1/poe/');
  });

  it('omits the sealed filter and query string entirely when no input is given', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        object: 'list',
        data: [],
        has_more: false,
        next_cursor: null,
        url: '/api/v1/records',
      }),
    );
    const out = await makeClient(fetchMock).records.list();
    expect(out.data).toHaveLength(0);
    // An empty page has no anchored rows to derive a tip from.
    expect(out.tip_block_height).toBeNull();
    const callUrl = String(fetchMock.mock.calls[0]![0]);
    expect(callUrl).toBe('http://test.example/api/v1/records');
    expect(callUrl).not.toContain('sealed');
  });

  it('honours a gateway-supplied tip_block_height over the page-derived value', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        object: 'list',
        data: [recordFixture()],
        has_more: false,
        next_cursor: null,
        url: '/api/v1/records',
        tip_block_height: 9000,
      }),
    );
    const out = await makeClient(fetchMock).records.list();
    // Gateway-reported tip wins over the derived 12_345_678 + 100 - 1.
    expect(out.tip_block_height).toBe(9000);
  });

  it('throws UnauthorizedError on 401 (auth required for the sealed view)', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        {
          type: 'about:blank',
          title: 'Unauthorized',
          status: 401,
          detail: 'Authentication required.',
          code: 'unauthorized',
          trace_id: '01977c00-0000-7000-8000-000000000000',
        },
        401,
      ),
    );
    await expect(makeClient(fetchMock).records.list({ sealed: true })).rejects.toMatchObject({
      code: 'unauthorized',
    });
  });
});

describe('RecordsNamespace.get', () => {
  it('GETs /api/v1/records/{tx_hash} with Bearer auth and returns the parsed RecordResource', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(recordFixture()));
    const client = makeClient(fetchMock);

    const out = await client.records.get(TX_HASH);

    // Response is the typed RecordResource shape, not the deleted PoeRecordResponse.
    expect(out.tx_hash).toBe(TX_HASH);
    expect(out.status).toBe('confirmed');
    expect(out.scheme).toBe(0);
    expect(out.metadata_cbor_base64).toBe('oWNmb29jYmFy');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`http://test.example/api/v1/records/${TX_HASH}`);
    // The dead /api/v1/poe/{tx_hash} URL must never appear on the wire.
    expect(String(url)).not.toContain('/api/v1/poe/');
    expect((init as RequestInit).method).toBe('GET');
    const headers = (init as RequestInit).headers as Headers;
    expect(headers.get('authorization')).toMatch(/^Bearer sk-cw-live-/);
    expect(headers.get('accept')).toBe('application/json');
  });

  it('surfaces the owner-only account_id field when the server includes it', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(recordFixture({ account_id: ACCOUNT_ID })));
    const out = await makeClient(fetchMock).records.get(TX_HASH);
    expect(out.account_id).toBe(ACCOUNT_ID);
  });

  it('parses `confirming` (chain-anchored, below threshold) and nullable block_* fields', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        recordFixture({
          status: 'confirming',
          num_confirmations: 1,
          // RecordResource permits null block_height/time on un-anchored
          // owner-window rows. Non-owner callers should never see these,
          // but the SDK type still accepts them — the field IS nullable
          // on the wire schema.
        }),
      ),
    );
    const out = await makeClient(fetchMock).records.get(TX_HASH);
    expect(out.status).toBe('confirming');
    expect(out.num_confirmations).toBe(1);
  });

  it('throws RecordNotFoundError on 404 record-not-found problem+json', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        {
          type: 'https://cardanowall.com/problems/record-not-found',
          title: 'Record Not Found',
          status: 404,
          detail: 'No record is indexed under that transaction hash.',
          code: 'record-not-found',
          trace_id: '01977c00-0000-7000-8000-000000000000',
        },
        404,
      ),
    );
    await expect(makeClient(fetchMock).records.get(TX_HASH)).rejects.toBeInstanceOf(
      RecordNotFoundError,
    );
  });
});

describe('RecordsNamespace.verify', () => {
  it('POSTs /api/v1/records/{tx_hash}/verify with the JSON body and parses VerifyReport', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(verifyReportFixture()));
    const client = makeClient(fetchMock);

    const out = await client.records.verify(TX_HASH, { fetch_content: false });

    // Response is parsed into the typed VerifyReport.
    expect(out.txHash).toBe(TX_HASH);
    expect(out.verdict).toBe('valid');
    expect(out.exitCode).toBe(0);
    expect(out.issues).toEqual([]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`http://test.example/api/v1/records/${TX_HASH}/verify`);
    expect(String(url)).not.toContain('/api/v1/poe/');
    expect((init as RequestInit).method).toBe('POST');
    // Body MUST contain the caller-supplied fetch_content flag — proves the
    // body is round-tripped (not just an input mock-assert against itself).
    // The endpoint is the hosted PUBLIC verifier: `fetch_content` is the ONLY
    // accepted field, so this also pins that the client wire body carries no
    // decryption credentials.
    const body = JSON.parse(String((init as RequestInit).body));
    expect(body).toEqual({ fetch_content: false });
  });

  it('sends an empty JSON body when no input is provided', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(verifyReportFixture()));
    await makeClient(fetchMock).records.verify(TX_HASH);
    const body = JSON.parse(String((fetchMock.mock.calls[0]![1] as RequestInit).body));
    expect(body).toEqual({});
  });

  it('throws RecordNotFoundError on 404', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        {
          type: 'https://cardanowall.com/problems/record-not-found',
          title: 'Record Not Found',
          status: 404,
          detail: 'No record is indexed under that transaction hash.',
          code: 'record-not-found',
          trace_id: '01977c00-0000-7000-8000-000000000000',
        },
        404,
      ),
    );
    await expect(makeClient(fetchMock).records.verify(TX_HASH)).rejects.toBeInstanceOf(
      RecordNotFoundError,
    );
  });
});

describe('RecordsNamespace request-shape parity fixture', () => {
  // Capture the exact HTTP request shape both SDKs (TS + Py) must produce for
  // the canonical client.records.get(TX_HASH) call. The fixture JSON at
  // tests/fixtures/records-request/records-get-request.json is the single
  // source of truth and is mirrored byte-identically by the Python SDK —
  // both languages load it from disk and assert their captured request
  // against it, so a divergence between the two SDKs OR a stale local fixture
  // surfaces as a test failure on at least one side.
  it('TS produces the canonical records.get request shape', async () => {
    const fixturePath = join(
      fileURLToPath(new URL('.', import.meta.url)),
      '..',
      '..',
      'tests',
      'fixtures',
      'records-request',
      'records-get-request.json',
    );
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
      readonly method: string;
      readonly url: string;
      readonly authorization: string;
      readonly accept: string;
    };

    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(recordFixture()));
    const client = new Label309Client({
      apiKey: `sk-cw-live-${'b'.repeat(52)}`,
      baseUrl: 'http://test.example',
      fetch: fetchMock as unknown as typeof globalThis.fetch,
    });
    await client.records.get(TX_HASH);

    const [url, init] = fetchMock.mock.calls[0]!;
    const headers = (init as RequestInit).headers as Headers;
    expect(String(url)).toBe(fixture.url);
    expect((init as RequestInit).method).toBe(fixture.method);
    expect(headers.get('authorization')).toBe(fixture.authorization);
    expect(headers.get('accept')).toBe(fixture.accept);
  });
});
