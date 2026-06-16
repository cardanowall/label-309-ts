// 409 quote-already-consumed — the publish quote referenced by `quote_id`
// has already been used by a prior /publish call. Quotes are single-use; a
// freshly-issued quote covers exactly one PoE submission. The caller should
// request a fresh quote via POST /poe/quote and retry.
//
// Wire-format extension members (RFC 7807 §3.2):
//   { "quote_id": "<uuid>" }

import { Label309HttpError, type Label309HttpErrorInit } from './http-error';

function readString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export class QuoteAlreadyConsumedError extends Label309HttpError {
  public readonly quoteId: string | undefined;

  constructor(init: Label309HttpErrorInit) {
    super(init);
    this.name = 'QuoteAlreadyConsumedError';
    this.quoteId = readString(this.extensions['quote_id']);
  }
}
