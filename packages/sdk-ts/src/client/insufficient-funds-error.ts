// 402 insufficient-funds — the caller's balance with the gateway is below the
// cost of the requested operation. This is the generic paid-gateway "balance
// too low" signal; how a particular gateway prices operations and tops up
// balances is its own concern.
//
// Wire-format extension members (RFC 7807 §3.2). Money fields land as decimal
// strings so JSON parsing preserves bigint precision in callers that parse to
// Number by default:
//
//   {
//     "balance_usd_micros":  "<decimal string>",
//     "required_usd_micros": "<decimal string>",
//     "top_up_url":          "<gateway-provided URL, optional>"
//   }
//
// Field-name mapping (wire → SDK):
//   balance_usd_micros  → balanceUsdMicros  (string → bigint)
//   required_usd_micros → requiredUsdMicros (string → bigint)
//   top_up_url          → topUpUrl          (snake_case → camelCase)
//
// Idempotency contract: a 402 is "non-committing" — the gateway does NOT cache
// the response under the request's Idempotency-Key. After raising the balance,
// the SDK consumer MAY retry with the SAME Idempotency-Key within the gateway's
// TTL window; the handler runs fresh and (assuming the balance now suffices)
// the retry returns 202 with a freshly assigned `id`.

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

function readBigIntString(value: unknown): bigint | undefined {
  if (typeof value !== 'string') return undefined;
  if (!/^-?[0-9]+$/.test(value)) return undefined;
  try {
    return BigInt(value);
  } catch {
    return undefined;
  }
}

function readString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export class InsufficientFundsError extends Cip309HttpError {
  public readonly balanceUsdMicros: bigint | undefined;
  public readonly requiredUsdMicros: bigint | undefined;
  public readonly topUpUrl: string | undefined;

  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'InsufficientFundsError';
    this.balanceUsdMicros = readBigIntString(this.extensions['balance_usd_micros']);
    this.requiredUsdMicros = readBigIntString(this.extensions['required_usd_micros']);
    this.topUpUrl = readString(this.extensions['top_up_url']);
  }
}
