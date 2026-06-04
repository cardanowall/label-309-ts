// 400 batch-empty — the `records[]` array on `/api/v1/poe/publish-batch` was
// empty. The batch endpoint requires at least one record.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class BatchEmptyError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'BatchEmptyError';
  }
}
