// 404 not-found — generic missing-resource response. Domain-specific 404s
// (notably `record-not-found`) deserialise to their own subclass.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class NotFoundError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'NotFoundError';
  }
}
