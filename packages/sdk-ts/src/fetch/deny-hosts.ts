// Public denyHostsFetch surface — thin adapter over the canonical
// fetchOutbound primitive in ./fetch-outbound.ts.

import {
  DenyHostError,
  type FetchOutbound,
  type FetchOutboundOptions,
  type HttpCallRecord,
  type HttpMethod,
  UnsupportedMethodError,
  UnsupportedProtocolError,
  wrapFetchOutbound,
} from './fetch-outbound';

export { DenyHostError, UnsupportedMethodError, UnsupportedProtocolError };

export type HttpCall = HttpCallRecord;

export type DenyHostsFetchOptions = {
  readonly denyHosts: readonly string[];
  readonly audit: HttpCall[];
  readonly purpose: HttpCall['purpose'];
  readonly fetchImpl?: typeof fetch;
};

export async function denyHostsFetch(
  url: string,
  init: RequestInit | undefined,
  opts: DenyHostsFetchOptions,
): Promise<Response> {
  // Forward the raw method so the canonical wrap surfaces
  // UnsupportedMethodError instead of silently rewriting to GET.
  const rawMethod = (init?.method ?? 'GET') as HttpMethod;
  const headers = init?.headers as Record<string, string> | undefined;
  const bodyValue = init?.body;
  const body: string | undefined = typeof bodyValue === 'string' ? bodyValue : undefined;
  const fetchImpl: typeof fetch = opts.fetchImpl ?? globalThis.fetch;

  const innerOpts: FetchOutboundOptions = headers
    ? body !== undefined
      ? { method: rawMethod, purpose: opts.purpose, headers, body }
      : { method: rawMethod, purpose: opts.purpose, headers }
    : body !== undefined
      ? { method: rawMethod, purpose: opts.purpose, body }
      : { method: rawMethod, purpose: opts.purpose };

  let storedResponse: Response | null = null;
  const inner: FetchOutbound = async (innerUrl, innerOptsArg) => {
    const t0 = Date.now();
    const reqInit: RequestInit = { method: innerOptsArg.method };
    if (innerOptsArg.headers) reqInit.headers = { ...innerOptsArg.headers };
    if (innerOptsArg.body !== undefined) reqInit.body = innerOptsArg.body;
    const response = await fetchImpl(innerUrl, reqInit);
    storedResponse = response;
    const buf = await response.clone().arrayBuffer();
    return {
      status: response.status,
      bytes: new Uint8Array(buf),
      durationMs: Date.now() - t0,
    };
  };

  const wrapped = wrapFetchOutbound(inner, opts.audit, { denyHosts: opts.denyHosts });
  await wrapped(url, innerOpts);
  return storedResponse!;
}
