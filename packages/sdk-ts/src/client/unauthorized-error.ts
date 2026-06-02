// 401 Unauthorized — caller is not authenticated. The server emits this when
// the `Authorization: Bearer` header is missing, malformed, or names a
// revoked / unknown API key.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class UnauthorizedError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'UnauthorizedError';
  }
}
