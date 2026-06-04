// 400 malformed-cbor — the `record_bytes` payload could not be parsed as
// canonical CBOR per the Label 309 deterministic encoding rules.

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

export class MalformedCborError extends Label309HttpError {
  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'MalformedCborError';
  }
}
