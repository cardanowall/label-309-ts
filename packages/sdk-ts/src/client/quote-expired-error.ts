// 410 quote-expired — the publish quote referenced by `quote_id` exceeded
// its TTL (15 minutes from issuance) before /publish consumed it. The
// caller should request a fresh quote via POST /api/v1/poe/quote and retry.
//
// Wire-format extension members (RFC 7807 §3.2):
//   { "quote_id": "<uuid>" }

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

function readString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export class QuoteExpiredError extends Cip309HttpError {
  public readonly quoteId: string | undefined;

  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'QuoteExpiredError';
    this.quoteId = readString(this.extensions['quote_id']);
  }
}
