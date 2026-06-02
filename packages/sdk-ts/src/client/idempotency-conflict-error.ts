// 409 idempotency-key-conflict — the supplied `Idempotency-Key` has been
// seen before with a different request body within its 24h TTL window.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class IdempotencyConflictError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'IdempotencyConflictError';
  }
}
