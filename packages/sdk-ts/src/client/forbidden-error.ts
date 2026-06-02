// 403 Forbidden — the caller is authenticated but lacks permission. Covers
// the generic `forbidden` code plus the edge-proxy `csrf-invalid` flavour;
// scope-specific failures surface as `InsufficientScopeError` instead.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class ForbiddenError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'ForbiddenError';
  }
}
