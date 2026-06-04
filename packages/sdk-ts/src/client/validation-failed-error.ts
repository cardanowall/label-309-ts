// 400 validation-failed — the request body parsed as JSON but failed the
// route's schema check. The per-field issues live on `err.errors[]` (Zod
// issue codes; e.g. `invalid_type`, `too_small`, `custom`).

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class ValidationFailedError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'ValidationFailedError';
  }
}
