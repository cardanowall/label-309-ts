// 409 idempotency-key-conflict — the supplied `Idempotency-Key` has been
// seen before with a different request body within its 24h TTL window.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class IdempotencyConflictError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'IdempotencyConflictError';
  }
}
