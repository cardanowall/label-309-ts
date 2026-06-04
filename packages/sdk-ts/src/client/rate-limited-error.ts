// 429 rate-limited — the caller exceeded the per-key request quota.
//
// The retry hint lives on the standard `Retry-After` HTTP response header
// (RFC 9110 §10.2.3). The SDK parses it into `retryAfterSeconds` on the
// thrown error; the value is undefined if the header is absent or
// non-numeric. Per RFC 7807, no retry hint appears in the problem body.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class RateLimitedError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'RateLimitedError';
  }
}
