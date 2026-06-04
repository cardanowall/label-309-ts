// 400 invalid-body — the request body was structurally malformed (e.g. not
// valid JSON, or a higher-level shape check failed before Zod ran). Schema
// validation failures emit `validation-failed` (→ `ValidationFailedError`)
// instead.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class InvalidBodyError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'InvalidBodyError';
  }
}
