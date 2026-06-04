// Decodes an RFC 7807 `application/problem+json` body into the most-specific
// `Label309HttpError` subclass.
//
// Dispatch order:
//   1. By `code` (lowercase-kebab) — preferred. Each registered code maps to a
//      named subclass with typed projections of its extension members.
//   2. By HTTP status, when the body is missing/non-conforming. In that case
//      we synthesise a minimal `ProblemDetails` so consumers always see a
//      well-formed `err.problem`.
//
// The dispatcher is intentionally exhaustive over the codes the API emits;
// codes the SDK doesn't recognise fall through to the parent
// `Label309HttpError` with the verbatim problem document.
// Forward-compatibility: a server can introduce new codes without breaking
// older SDKs — consumers either catch the parent class or dispatch on
// `err.code` directly.

import { BatchEmptyError } from './batch-empty-error';
import { BatchTooLargeError } from './batch-too-large-error';
import { ForbiddenError } from './forbidden-error';
import {
  Label309HttpError,
  extractProblemExtensions,
  type ProblemDetails,
  type ProblemErrorEntry,
} from './http-error';
import { IdempotencyConflictError } from './idempotency-conflict-error';
import { InsufficientFundsError } from './insufficient-funds-error';
import { InsufficientScopeError } from './insufficient-scope-error';
import { InternalServerError } from './internal-server-error';
import { InvalidBodyError } from './invalid-body-error';
import { MalformedCborError } from './malformed-cbor-error';
import { NotFoundError } from './not-found-error';
import { QuoteAlreadyConsumedError } from './quote-already-consumed-error';
import { QuoteExpiredError } from './quote-expired-error';
import { QuoteNotFoundError } from './quote-not-found-error';
import { RateLimitedError } from './rate-limited-error';
import { RecordNotFoundError } from './record-not-found-error';
import { ServiceUnavailableError } from './service-unavailable-error';
import { UnauthorizedError } from './unauthorized-error';
import { ValidationFailedError } from './validation-failed-error';

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function asProblemErrorEntries(value: unknown): readonly ProblemErrorEntry[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: ProblemErrorEntry[] = [];
  for (const entry of value) {
    if (entry === null || typeof entry !== 'object') continue;
    const e = entry as Record<string, unknown>;
    out.push({
      field: typeof e['field'] === 'string' ? e['field'] : '',
      code: typeof e['code'] === 'string' ? e['code'] : '',
      detail: typeof e['detail'] === 'string' ? e['detail'] : '',
    });
  }
  return out;
}

/** Synthesise a minimal `ProblemDetails` for non-conforming bodies. */
function synthesiseProblem(httpStatus: number, requestId: string | undefined): ProblemDetails {
  const code = `http-${httpStatus}`;
  return {
    type: `about:blank`,
    title: `HTTP ${httpStatus}`,
    status: httpStatus,
    detail: `Server returned HTTP ${httpStatus} without a problem+json body.`,
    code,
    trace_id: requestId ?? '',
  };
}

function toProblemDetails(
  httpStatus: number,
  body: unknown,
  requestId: string | undefined,
): ProblemDetails {
  if (body === null || typeof body !== 'object') {
    return synthesiseProblem(httpStatus, requestId);
  }
  const b = body as Record<string, unknown>;
  // Heuristic: a real RFC 7807 body has at minimum `code` and `status` or
  // `title`. If neither is present we treat the body as non-conforming.
  const code = asString(b['code']);
  const status = asNumber(b['status']) ?? httpStatus;
  const title = asString(b['title']);
  if (code === undefined && title === undefined) {
    return synthesiseProblem(httpStatus, requestId);
  }
  const errors = asProblemErrorEntries(b['errors']);
  // Preserve every top-level field. `code`/`title`/`status` fall back when
  // the server omitted them; everything else flows through verbatim as
  // RFC 7807 §3.2 extension members.
  const base: Record<string, unknown> = {
    ...b,
    // RFC 7807 §4.2: `about:blank` is the default when no type URI is supplied.
    // The client is gateway-agnostic, so it must not invent a vendor-specific
    // problem-type namespace; the machine-readable discriminator is `code`.
    type: asString(b['type']) ?? 'about:blank',
    title: title ?? `HTTP ${status}`,
    status,
    detail: asString(b['detail']) ?? '',
    code: code ?? `http-${status}`,
    trace_id: asString(b['trace_id']) ?? requestId ?? '',
  };
  if (errors !== undefined) base['errors'] = errors;
  return base as ProblemDetails;
}

export interface ParseHttpErrorArgs {
  readonly httpStatus: number;
  readonly body: unknown;
  /** `X-Request-Id` header from the response, when available. */
  readonly requestId?: string | undefined;
  /** `Retry-After` header from the response, parsed as integer seconds. */
  readonly retryAfterSeconds?: number | undefined;
}

export function parseHttpError(args: ParseHttpErrorArgs): Label309HttpError {
  const problem = toProblemDetails(args.httpStatus, args.body, args.requestId);
  const extensions = extractProblemExtensions(problem);
  const init = {
    problem,
    extensions,
    requestId: args.requestId,
    retryAfterSeconds: args.retryAfterSeconds,
  } as const;

  switch (problem.code) {
    case 'unauthorized':
      return new UnauthorizedError(init);
    case 'forbidden':
    case 'csrf-invalid':
      return new ForbiddenError(init);
    case 'insufficient-scope':
      return new InsufficientScopeError(init);
    case 'insufficient-funds':
      return new InsufficientFundsError(init);
    case 'quote-expired':
      return new QuoteExpiredError(init);
    case 'quote-not-found':
      return new QuoteNotFoundError(init);
    case 'quote-already-consumed':
      return new QuoteAlreadyConsumedError(init);
    case 'not-found':
      return new NotFoundError(init);
    case 'record-not-found':
      return new RecordNotFoundError(init);
    case 'idempotency-key-conflict':
      return new IdempotencyConflictError(init);
    case 'rate-limited':
      return new RateLimitedError(init);
    case 'validation-failed':
      return new ValidationFailedError(init);
    case 'invalid-body':
      return new InvalidBodyError(init);
    case 'malformed-cbor':
      return new MalformedCborError(init);
    case 'batch-too-large':
      return new BatchTooLargeError(init);
    case 'batch-empty':
      return new BatchEmptyError(init);
    case 'internal-error':
      return new InternalServerError(init);
    // A gateway that prices on a live FX oracle may surface a transient
    // `fx-stale` pricing outage; to a vendor-neutral client that is just a
    // temporary inability to serve, i.e. a service-unavailable condition.
    case 'service-unavailable':
    case 'fx-stale':
      return new ServiceUnavailableError(init);
    default:
      return new Label309HttpError(init);
  }
}
