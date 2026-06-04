import { AccountNamespace } from './account';
import { InvalidClientConfigError } from './invalid-client-config-error';
import { PoeNamespace } from './poe';
import { RecordsNamespace } from './records';
import type { Label309ClientConfig, FetchImpl } from './types';

function resolveFetch(provided: FetchImpl | undefined): FetchImpl {
  if (provided !== undefined) return provided;
  if (typeof globalThis.fetch === 'function') {
    // Bind to preserve `this` inside Node/browser fetch implementations.
    return globalThis.fetch.bind(globalThis);
  }
  throw new Error(
    'Label309Client: no fetch implementation available. Pass `fetch` in the config or run on a platform with globalThis.fetch.',
  );
}

/**
 * Resolves the gateway base URL the client targets.
 *
 * `baseUrl` is REQUIRED and is used verbatim — the client is gateway-agnostic
 * and binds to no particular deployment. A missing or empty `baseUrl` is a
 * configuration error: there is nowhere to send requests. Trailing slashes are
 * stripped so callers may pass `https://gw.example.com/` or
 * `https://gw.example.com` interchangeably.
 *
 * The `apiKey`, when present, is an OPAQUE bearer token forwarded verbatim as
 * `Authorization: Bearer <apiKey>`. It is never parsed, validated, or used to
 * infer the URL — any Label 309 gateway may issue keys in its own format. Omit it
 * for anonymous read-only usage.
 */
function resolveBaseUrl(config: Label309ClientConfig): string {
  const baseUrl = config.baseUrl?.trim();
  if (baseUrl === undefined || baseUrl === '') {
    throw new InvalidClientConfigError(
      'Label309Client: baseUrl is required. Pass the base URL of the Label 309 ' +
        'gateway you are targeting (e.g. https://gateway.example.com).',
    );
  }
  return baseUrl.replace(/\/$/, '');
}

export class Label309Client {
  public readonly poe: PoeNamespace;
  public readonly records: RecordsNamespace;
  public readonly account: AccountNamespace;

  /**
   * Construct a client against a Label 309 gateway.
   *
   * `config.baseUrl` is required — there is no default deployment. The
   * `config.apiKey`, when supplied, is an opaque bearer token sent verbatim as
   * `Authorization: Bearer <apiKey>`; omit it for anonymous read-only access.
   *
   * PoE submissions debit the gateway's own balance model. Acquire a price lock
   * via `client.poe.quote(...)` first; the resulting `quote_id` is consumed by
   * the publish call.
   */
  constructor(config: Label309ClientConfig) {
    const fetchImpl = resolveFetch(config.fetch);
    const baseUrl = resolveBaseUrl(config);
    const resolved = { apiKey: config.apiKey, baseUrl, fetch: fetchImpl };
    this.poe = new PoeNamespace(resolved);
    this.records = new RecordsNamespace(resolved);
    this.account = new AccountNamespace(resolved);
  }
}
