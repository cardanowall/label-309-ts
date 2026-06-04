// Unit tests for client.account.* — the account read namespace that wraps
// `GET /api/v1/account/balance`.
//
// Asserts on the actual HTTP request shape (URL, method, auth header) AND on
// the response being parsed into the typed `AccountBalance`, with the wire
// `balance_usd_micros` mapped to `balanceUsdMicros` and kept as a STRING so
// the bigint micro-cents value survives without precision loss.

import { describe, expect, it, vi } from 'vitest';

import { Label309Client } from './label-309-client';
import { InsufficientScopeError } from './insufficient-scope-error';
import { UnauthorizedError } from './unauthorized-error';

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

describe('AccountNamespace.balance', () => {
  it('GETs /api/v1/account/balance with Bearer auth and maps balance_usd_micros to a string', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ balance_usd_micros: '1234567' }));
    const client = makeClient(fetchMock);

    const out = await client.account.balance();

    expect(out).toEqual({ balanceUsdMicros: '1234567' });
    // The value MUST stay a string — never coerced to a number.
    expect(typeof out.balanceUsdMicros).toBe('string');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('http://test.example/api/v1/account/balance');
    expect((init as RequestInit).method).toBe('GET');
    const headers = (init as RequestInit).headers as Headers;
    expect(headers.get('authorization')).toMatch(/^Bearer sk-cw-live-/);
    expect(headers.get('accept')).toBe('application/json');
  });

  it('preserves a value past 2^53 verbatim (no Number coercion)', async () => {
    // 9_007_199_254_740_993 = 2^53 + 1 — the first integer a JS number cannot
    // represent exactly. The string must survive byte-for-byte.
    const huge = '9007199254740993';
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ balance_usd_micros: huge }));
    const out = await makeClient(fetchMock).account.balance();
    expect(out.balanceUsdMicros).toBe(huge);
  });

  it('reads "0" for an account with no ledger activity', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ balance_usd_micros: '0' }));
    const out = await makeClient(fetchMock).account.balance();
    expect(out.balanceUsdMicros).toBe('0');
  });

  it('throws InsufficientScopeError on 403 insufficient-scope problem+json', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        {
          type: 'https://cardanowall.com/api/v1/errors#insufficient-scope',
          title: 'Insufficient Scope',
          status: 403,
          detail: 'The API key does not grant the account:read scope.',
          code: 'insufficient-scope',
          required: ['account:read'],
          granted: ['poe:read'],
          trace_id: '01977c00-0000-7000-8000-000000000000',
        },
        403,
      ),
    );
    await expect(makeClient(fetchMock).account.balance()).rejects.toBeInstanceOf(
      InsufficientScopeError,
    );
  });

  it('throws UnauthorizedError on 401 unauthorized problem+json', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      problemResponse(
        {
          type: 'https://cardanowall.com/api/v1/errors#unauthorized',
          title: 'Unauthorized',
          status: 401,
          detail: 'This endpoint requires authentication.',
          code: 'unauthorized',
          trace_id: '01977c00-0000-7000-8000-000000000000',
        },
        401,
      ),
    );
    await expect(makeClient(fetchMock).account.balance()).rejects.toBeInstanceOf(UnauthorizedError);
  });
});
