// 404 quote-not-found — the supplied `quote_id` does not exist for the
// authenticated account. Either the UUID is wrong, or the quote belongs to
// a different account (the server enforces account scoping on quote rows).
//
// Wire-format extension members (RFC 7807 §3.2):
//   { "quote_id": "<uuid>" }

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

function readString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export class QuoteNotFoundError extends Cip309HttpError {
  public readonly quoteId: string | undefined;

  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'QuoteNotFoundError';
    this.quoteId = readString(this.extensions['quote_id']);
  }
}
