// Shared response-handling helpers for the HTTP client namespaces (poe,
// records, account). They parse the body, lift `X-Request-Id` /
// `Retry-After`, and throw a typed `Label309HttpError` on non-2xx the same
// way, so the logic lives here once.

import { parseHttpError } from './parse-http-error';

/** Parse a JSON response body; returns `null` for empty or non-JSON bodies. */
export async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Parse the `Retry-After` header as integer seconds; `undefined` when absent or non-numeric. */
export function parseRetryAfter(header: string | null): number | undefined {
  if (header === null) return undefined;
  const parsed = Number(header);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * Throw the most-specific `Label309HttpError` subclass on a non-2xx
 * response (decoding the RFC 7807 body, request id, and retry-after); no-op on
 * 2xx so callers can `await throwIfNotOk(res)` before reading the success body.
 */
export async function throwIfNotOk(response: Response): Promise<void> {
  if (response.ok) return;
  const body = await readJson(response);
  const requestId = response.headers.get('x-request-id') ?? undefined;
  const retryAfterSeconds = parseRetryAfter(response.headers.get('retry-after'));
  throw parseHttpError({ httpStatus: response.status, body, requestId, retryAfterSeconds });
}
