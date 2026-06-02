// 400 batch-empty — the `records[]` array on `/api/v1/poe/publish-batch` was
// empty. The batch endpoint requires at least one record.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class BatchEmptyError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'BatchEmptyError';
  }
}
