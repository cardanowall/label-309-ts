// 500 internal-error — unexpected server-side failure. The detail message
// is deliberately generic; correlate the failure via `err.traceId` in
// server logs.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class InternalServerError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'InternalServerError';
  }
}
