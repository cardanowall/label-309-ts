// Decoder tests for the RFC 7807 problem+json envelope. The contract under
// test is: given a real on-the-wire body emitted by the API server,
// parseHttpError() returns the most-specific typed error subclass with
// extension members projected onto camelCase getters.

import { describe, expect, it } from 'vitest';

import { BatchEmptyError } from './batch-empty-error';
import { BatchTooLargeError } from './batch-too-large-error';
import { ForbiddenError } from './forbidden-error';
import { Label309HttpError } from './http-error';
import { IdempotencyConflictError } from './idempotency-conflict-error';
import { InsufficientFundsError } from './insufficient-funds-error';
import { InsufficientScopeError } from './insufficient-scope-error';
import { InternalServerError } from './internal-server-error';
import { InvalidBodyError } from './invalid-body-error';
import { MalformedCborError } from './malformed-cbor-error';
import { NotFoundError } from './not-found-error';
import { parseHttpError } from './parse-http-error';
import { QuoteAlreadyConsumedError } from './quote-already-consumed-error';
import { QuoteExpiredError } from './quote-expired-error';
import { QuoteNotFoundError } from './quote-not-found-error';
import { RateLimitedError } from './rate-limited-error';
import { RecordNotFoundError } from './record-not-found-error';
import { ServiceUnavailableError } from './service-unavailable-error';
import { UnauthorizedError } from './unauthorized-error';
import { ValidationFailedError } from './validation-failed-error';

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

describe('Label309HttpError envelope projection', () => {
  it('preserves the verbatim problem document and projects canonical fields', () => {
    const body = problemBody({
      type: 'https://cardanowall.com/problems/insufficient-funds',
      title: 'Payment Required',
      status: 402,
      detail: 'Required $0.18 for this publish; balance is $0.05.',
      code: 'insufficient-funds',
      balance_usd_micros: '50000',
      required_usd_micros: '180000',
      top_up_url: '/billing/top-up',
    });
    const err = parseHttpError({ httpStatus: 402, body, requestId: 'req-1' });

    expect(err.problem).toEqual(body);
    expect(err.code).toBe('insufficient-funds');
    expect(err.httpStatus).toBe(402);
    expect(err.title).toBe('Payment Required');
    expect(err.detail).toBe('Required $0.18 for this publish; balance is $0.05.');
    expect(err.type).toBe('https://cardanowall.com/problems/insufficient-funds');
    expect(err.traceId).toBe('01977c00-0000-7000-8000-000000000000');
    expect(err.requestId).toBe('req-1');
    // Extension members are split out (non-canonical RFC 7807 fields):
    expect(err.extensions).toEqual({
      balance_usd_micros: '50000',
      required_usd_micros: '180000',
      top_up_url: '/billing/top-up',
    });
    // The Error message defaults to the problem detail:
    expect(err.message).toBe('Required $0.18 for this publish; balance is $0.05.');
  });

  it('falls back to trace_id when X-Request-Id header is absent', () => {
    const err = parseHttpError({
      httpStatus: 500,
      body: problemBody({ code: 'internal-error', status: 500, trace_id: 'trace-xyz' }),
    });
    expect(err.requestId).toBe('trace-xyz');
  });

  it('synthesises a minimal problem document for non-RFC-7807 bodies', () => {
    const err = parseHttpError({ httpStatus: 418, body: null });
    expect(err).toBeInstanceOf(Label309HttpError);
    // Synthesised; falls back to a stable surrogate code so consumers can
    // dispatch without crashing on missing fields:
    expect(err.code).toBe('http-418');
    expect(err.httpStatus).toBe(418);
    expect(err.problem.type).toBe('about:blank');
  });

  it('forwards Retry-After header to err.retryAfterSeconds', () => {
    const err = parseHttpError({
      httpStatus: 429,
      body: problemBody({ code: 'rate-limited', status: 429 }),
      retryAfterSeconds: 42,
    });
    expect(err).toBeInstanceOf(RateLimitedError);
    expect(err.retryAfterSeconds).toBe(42);
  });
});

describe('parseHttpError dispatch by code', () => {
  it('unauthorized → UnauthorizedError', () => {
    const err = parseHttpError({
      httpStatus: 401,
      body: problemBody({ code: 'unauthorized', status: 401 }),
    });
    expect(err).toBeInstanceOf(UnauthorizedError);
    expect(err).toBeInstanceOf(Label309HttpError);
  });

  it('forbidden → ForbiddenError; csrf-invalid → ForbiddenError', () => {
    const a = parseHttpError({
      httpStatus: 403,
      body: problemBody({ code: 'forbidden', status: 403 }),
    });
    const b = parseHttpError({
      httpStatus: 403,
      body: problemBody({ code: 'csrf-invalid', status: 403 }),
    });
    expect(a).toBeInstanceOf(ForbiddenError);
    expect(b).toBeInstanceOf(ForbiddenError);
    expect(b.code).toBe('csrf-invalid');
  });

  it('insufficient-scope → InsufficientScopeError with required/granted scope arrays', () => {
    const err = parseHttpError({
      httpStatus: 403,
      body: problemBody({
        code: 'insufficient-scope',
        status: 403,
        required: ['poe:create'],
        granted: ['poe:read', 'account:read'],
      }),
    });
    expect(err).toBeInstanceOf(InsufficientScopeError);
    const typed = err as InsufficientScopeError;
    expect(typed.requiredScopes).toEqual(['poe:create']);
    expect(typed.grantedScopes).toEqual(['poe:read', 'account:read']);
    expect(typed.requiredScope).toBe('poe:create');
  });

  it('insufficient-funds → InsufficientFundsError with typed bigint USD-micro fields', () => {
    const err = parseHttpError({
      httpStatus: 402,
      body: problemBody({
        code: 'insufficient-funds',
        status: 402,
        balance_usd_micros: '50000',
        required_usd_micros: '180000',
        top_up_url: '/billing/top-up',
      }),
    });
    expect(err).toBeInstanceOf(InsufficientFundsError);
    const typed = err as InsufficientFundsError;
    expect(typed.balanceUsdMicros).toBe(50_000n);
    expect(typed.requiredUsdMicros).toBe(180_000n);
    expect(typed.topUpUrl).toBe('/billing/top-up');
  });

  it('quote-expired → QuoteExpiredError with quoteId projection', () => {
    const err = parseHttpError({
      httpStatus: 410,
      body: problemBody({
        code: 'quote-expired',
        status: 410,
        quote_id: '01956b41-7c00-7000-8000-000000000001',
      }),
    });
    expect(err).toBeInstanceOf(QuoteExpiredError);
    expect((err as QuoteExpiredError).quoteId).toBe('01956b41-7c00-7000-8000-000000000001');
  });

  it('quote-already-consumed → QuoteAlreadyConsumedError with quoteId projection', () => {
    const err = parseHttpError({
      httpStatus: 409,
      body: problemBody({
        code: 'quote-already-consumed',
        status: 409,
        quote_id: '01956b41-7c00-7000-8000-000000000002',
      }),
    });
    expect(err).toBeInstanceOf(QuoteAlreadyConsumedError);
    expect((err as QuoteAlreadyConsumedError).quoteId).toBe('01956b41-7c00-7000-8000-000000000002');
  });

  it('quote-not-found → QuoteNotFoundError with quoteId projection', () => {
    const err = parseHttpError({
      httpStatus: 404,
      body: problemBody({
        code: 'quote-not-found',
        status: 404,
        quote_id: '01956b41-7c00-7000-8000-000000000003',
      }),
    });
    expect(err).toBeInstanceOf(QuoteNotFoundError);
    expect((err as QuoteNotFoundError).quoteId).toBe('01956b41-7c00-7000-8000-000000000003');
  });

  it('fx-stale (gateway pricing outage) → ServiceUnavailableError', () => {
    // A vendor-neutral client has no pricing-model vocabulary: a gateway whose
    // live FX oracle is momentarily stale is, to the client, simply
    // service-unavailable.
    const err = parseHttpError({
      httpStatus: 503,
      body: problemBody({ code: 'fx-stale', status: 503 }),
    });
    expect(err).toBeInstanceOf(ServiceUnavailableError);
  });

  it('not-found → NotFoundError; record-not-found → RecordNotFoundError', () => {
    const generic = parseHttpError({
      httpStatus: 404,
      body: problemBody({ code: 'not-found', status: 404 }),
    });
    const record = parseHttpError({
      httpStatus: 404,
      body: problemBody({ code: 'record-not-found', status: 404 }),
    });
    expect(generic).toBeInstanceOf(NotFoundError);
    expect(record).toBeInstanceOf(RecordNotFoundError);
    // Both share the parent — instanceof on RecordNotFoundError must NOT
    // match the generic NotFoundError instance:
    expect(generic).not.toBeInstanceOf(RecordNotFoundError);
  });

  it('idempotency-key-conflict → IdempotencyConflictError', () => {
    const err = parseHttpError({
      httpStatus: 409,
      body: problemBody({ code: 'idempotency-key-conflict', status: 409 }),
    });
    expect(err).toBeInstanceOf(IdempotencyConflictError);
  });

  it('rate-limited → RateLimitedError (retry hint comes from Retry-After header, not body)', () => {
    const err = parseHttpError({
      httpStatus: 429,
      body: problemBody({ code: 'rate-limited', status: 429 }),
      retryAfterSeconds: 7,
    });
    expect(err).toBeInstanceOf(RateLimitedError);
    expect(err.retryAfterSeconds).toBe(7);
  });

  it('validation-failed → ValidationFailedError carrying errors[]', () => {
    const errors = [
      { field: 'items.0.hashes', code: 'invalid_type', detail: 'Expected object, got string' },
      { field: '', code: 'custom', detail: 'Body-level rule failed' },
    ];
    const err = parseHttpError({
      httpStatus: 400,
      body: problemBody({ code: 'validation-failed', status: 400, errors }),
    });
    expect(err).toBeInstanceOf(ValidationFailedError);
    expect(err.errors).toEqual(errors);
  });

  it('invalid-body → InvalidBodyError', () => {
    const err = parseHttpError({
      httpStatus: 400,
      body: problemBody({ code: 'invalid-body', status: 400 }),
    });
    expect(err).toBeInstanceOf(InvalidBodyError);
  });

  it('malformed-cbor → MalformedCborError', () => {
    const err = parseHttpError({
      httpStatus: 400,
      body: problemBody({ code: 'malformed-cbor', status: 400 }),
    });
    expect(err).toBeInstanceOf(MalformedCborError);
  });

  it('batch-too-large → BatchTooLargeError with max/got extension fields', () => {
    const err = parseHttpError({
      httpStatus: 400,
      body: problemBody({ code: 'batch-too-large', status: 400, max: 50, got: 73 }),
    });
    expect(err).toBeInstanceOf(BatchTooLargeError);
    const typed = err as BatchTooLargeError;
    expect(typed.max).toBe(50);
    expect(typed.got).toBe(73);
  });

  it('batch-empty → BatchEmptyError', () => {
    const err = parseHttpError({
      httpStatus: 400,
      body: problemBody({ code: 'batch-empty', status: 400 }),
    });
    expect(err).toBeInstanceOf(BatchEmptyError);
  });

  it('internal-error → InternalServerError', () => {
    const err = parseHttpError({
      httpStatus: 500,
      body: problemBody({ code: 'internal-error', status: 500 }),
    });
    expect(err).toBeInstanceOf(InternalServerError);
  });

  it('service-unavailable → ServiceUnavailableError with Retry-After', () => {
    const err = parseHttpError({
      httpStatus: 503,
      body: problemBody({ code: 'service-unavailable', status: 503 }),
      retryAfterSeconds: 30,
    });
    expect(err).toBeInstanceOf(ServiceUnavailableError);
    expect(err.retryAfterSeconds).toBe(30);
  });

  it('unknown code falls through to Label309HttpError with the verbatim body', () => {
    const err = parseHttpError({
      httpStatus: 451,
      body: problemBody({ code: 'unavailable-for-legal-reasons', status: 451 }),
    });
    expect(err).toBeInstanceOf(Label309HttpError);
    // Subclass-specific instanceof check: NOT one of the typed subclasses
    expect(err).not.toBeInstanceOf(InternalServerError);
    expect(err.code).toBe('unavailable-for-legal-reasons');
  });
});
