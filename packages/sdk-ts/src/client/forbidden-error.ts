// 403 Forbidden — the caller is authenticated but lacks permission. Covers
// the generic `forbidden` code plus the edge-proxy `csrf-invalid` flavour;
// scope-specific failures surface as `InsufficientScopeError` instead.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class ForbiddenError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'ForbiddenError';
  }
}
