// 503 service-unavailable — temporary inability to serve the request. The
// retry hint, if any, is on the standard `Retry-After` header — surfaced on
// `err.retryAfterSeconds`.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class ServiceUnavailableError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'ServiceUnavailableError';
  }
}
