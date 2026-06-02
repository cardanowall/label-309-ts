// 400 validation-failed — the request body parsed as JSON but failed the
// route's schema check. The per-field issues live on `err.errors[]` (Zod
// issue codes; e.g. `invalid_type`, `too_small`, `custom`).

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class ValidationFailedError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'ValidationFailedError';
  }
}
