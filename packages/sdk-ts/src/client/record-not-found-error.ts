// 404 record-not-found — no Label 309 record is registered for the requested
// tx_hash.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class RecordNotFoundError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'RecordNotFoundError';
  }
}
