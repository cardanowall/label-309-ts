// 400 batch-too-large — the `records[]` array on `/api/v1/poe/publish-batch`
// carries more entries than the per-call ceiling (max 50).
//
// Wire-format extension members:
//   { "max": <int>, "got": <int> }

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

function readInt(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

export class BatchTooLargeError extends Cip309HttpError {
  public readonly max: number | undefined;
  public readonly got: number | undefined;

  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'BatchTooLargeError';
    this.max = readInt(this.extensions['max']);
    this.got = readInt(this.extensions['got']);
  }
}
