// 404 record-not-found — no CIP-309 record is registered for the requested
// tx_hash.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class RecordNotFoundError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'RecordNotFoundError';
  }
}
