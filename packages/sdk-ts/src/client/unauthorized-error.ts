// 401 Unauthorized — caller is not authenticated. The server emits this when
// the `Authorization: Bearer` header is missing, malformed, or names a
// revoked / unknown API key.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class UnauthorizedError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'UnauthorizedError';
  }
}
