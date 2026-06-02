// 400 malformed-cbor — the `record_bytes` payload could not be parsed as
// canonical CBOR per the CIP-309 deterministic encoding rules.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

export class MalformedCborError extends Cip309HttpError {
  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'MalformedCborError';
  }
}
