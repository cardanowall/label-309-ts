// `client.account.*` wraps the account read surface:
//
//   GET /api/v1/account/balance → account.balance()
//
// Auth is required (Bearer with `account:read` scope, or a session cookie when
// the gateway is browser-fronted). The configured API key is forwarded as
// `Authorization: Bearer …`.
//
// The balance is USD micro-cents carried as a decimal string on the wire
// (`balance_usd_micros`). The SDK preserves it verbatim as a string —
// `AccountBalance.balanceUsdMicros` — and never coerces it to a JS number, so
// the bigint value survives without precision loss.

import { readJson, throwIfNotOk } from './http-helpers';
import type { AccountBalance, FetchImpl } from './types';

interface ResolvedConfig {
  readonly apiKey: string | undefined;
  readonly baseUrl: string;
  readonly fetch: FetchImpl;
}

function buildHeaders(apiKey: string | undefined): Headers {
  const headers = new Headers({
    'content-type': 'application/json',
    accept: 'application/json',
  });
  if (apiKey !== undefined) headers.set('authorization', `Bearer ${apiKey}`);
  return headers;
}

interface AccountBalanceWire {
  readonly balance_usd_micros: string;
}

export class AccountNamespace {
  private readonly config: ResolvedConfig;

  constructor(config: ResolvedConfig) {
    this.config = config;
  }

  /**
   * Fetch the caller's current prepaid USD balance.
   *
   * Returns `{ balanceUsdMicros }`, the gateway's `balance_usd_micros` field
   * (USD micro-cents as a decimal string). The string is preserved verbatim —
   * never parsed into a number — so no precision is lost. An account with no
   * ledger activity yet reads `"0"`.
   *
   * Requires authentication: 401 (UnauthorizedError) when anonymous, 403
   * (InsufficientScopeError) when the Bearer key lacks the `account:read`
   * scope.
   */
  async balance(): Promise<AccountBalance> {
    const response = await this.config.fetch(`${this.config.baseUrl}/api/v1/account/balance`, {
      method: 'GET',
      headers: buildHeaders(this.config.apiKey),
    });
    await throwIfNotOk(response);
    const body = (await readJson(response)) as AccountBalanceWire;
    return { balanceUsdMicros: body.balance_usd_micros };
  }
}
