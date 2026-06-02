// 500 internal-error — unexpected server-side failure. The detail message
// is deliberately generic; correlate the failure via `err.traceId` in
// server logs.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class InternalServerError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'InternalServerError';
  }
}
