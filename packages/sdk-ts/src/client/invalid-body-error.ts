// 400 invalid-body — the request body was structurally malformed (e.g. not
// valid JSON, or a higher-level shape check failed before Zod ran). Schema
// validation failures emit `validation-failed` (→ `ValidationFailedError`)
// instead.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class InvalidBodyError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'InvalidBodyError';
  }
}
