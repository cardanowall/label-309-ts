// 503 service-unavailable — temporary inability to serve the request. The
// retry hint, if any, is on the standard `Retry-After` header — surfaced on
// `err.retryAfterSeconds`.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class ServiceUnavailableError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'ServiceUnavailableError';
  }
}
