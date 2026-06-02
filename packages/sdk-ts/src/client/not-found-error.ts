// 404 not-found — generic missing-resource response. Domain-specific 404s
// (notably `record-not-found`) deserialise to their own subclass.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class NotFoundError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'NotFoundError';
  }
}
