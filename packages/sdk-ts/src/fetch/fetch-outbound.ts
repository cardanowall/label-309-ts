// Canonical outbound HTTP wrapper: deny-list short-circuit, protocol/method
// allowlist, bounded timeout, exp-backoff retry with jitter, audit trail.

// Universal loopback deny-host list a service-independent verifier MUST reject
// so a record can never be made to "verify" only because it reached a loopback
// address. This default carries no operator-specific entries: a deployment that
// wants to forbid its own gateway/viewer hosts appends those at construction
// time. Producers SHOULD pass this through `denyHosts` on every verifier
// invocation; the wrapper accepts arbitrary lists but exports the canonical
// loopback set so callers don't duplicate it inline. (RFC-1918 / link-local IP
// ranges are blocked separately by the SSRF guard, not by this name list.)
export const DENY_HOSTS_DEFAULT: ReadonlyArray<string> = ['localhost', '127.0.0.1'];

// Every outbound call carries a purpose tag from the closed set
// `{cardano, arweave, ipfs}` (the three v1 gateway-chain purposes).
// `https` is a transitional legacy tag for non-storage HTTPS
// auxiliaries; new code SHOULD pick one of the three normative purposes.
// `webhook` tags a fetch whose target URL came from end-user input. Safe
// egress to such a URL needs a DNS-pinning SSRF guard — resolve the host,
// range-check every A/AAAA record against the private/reserved blocklist,
// and pin the TCP connection to the checked IP — which this generic wrapper
// deliberately does not implement, so the purpose is rejected up front
// rather than letting a user-supplied URL ride the ordinary fetch path.
export type HttpPurpose = 'cardano' | 'arweave' | 'ipfs' | 'https' | 'webhook';
export type HttpMethod = 'GET' | 'POST';

export interface FetchOutboundOptions {
  readonly method: HttpMethod;
  readonly purpose: HttpPurpose;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
  // Hard cap on the response body the primitive will buffer. Gateway content
  // (ar:// / ipfs:// / https) is producer-chosen and therefore UNTRUSTED — the
  // verifier never trusts the producer — so a malicious gateway could otherwise
  // stream unbounded bytes into memory. Omit to use DEFAULT_OUTBOUND_MAX_BYTES.
  readonly maxBytes?: number;
  // Deny-host list forwarded by `wrapFetchOutbound` so the transport can
  // re-apply it to a same-domain redirect target (arweave purpose only). The
  // wrapper validated the ORIGINAL url against this list before dispatch; the
  // transport re-validates each redirect hop it chooses to follow so a 3xx can
  // never pivot the fetch onto a denied host behind the wrapper's back.
  readonly denyHosts?: ReadonlyArray<string>;
}

export interface FetchOutboundResult {
  readonly status: number;
  readonly bytes: Uint8Array;
  readonly durationMs: number;
}

export type FetchOutbound = (
  url: string,
  opts: FetchOutboundOptions,
) => Promise<FetchOutboundResult>;

// Audit-log entry for one outbound HTTP fetch. The field set and names match
// the verifier report's audit-trail entry exactly, so the record lands on
// `VerifyReport.auditTrail[]` without a key-renaming pass. `status` is the
// HTTP status when a response was received and `null` when none was (refused
// call, transport failure).
export interface HttpCallRecord {
  readonly url: string;
  readonly method: HttpMethod;
  readonly status: number | null;
  readonly bytes: number;
  readonly durationMs: number;
  readonly purpose: HttpPurpose;
}

export interface RetryConfig {
  readonly timeoutMs?: number;
  readonly retries?: number;
  readonly retryableStatuses?: ReadonlyArray<number>;
}

export interface WrapFetchOutboundConfig extends RetryConfig {
  readonly denyHosts?: ReadonlyArray<string>;
}

export class DenyHostError extends Error {
  readonly code = 'SERVICE_INDEPENDENCE_VIOLATION';
  readonly host: string;
  readonly url: string;
  constructor(host: string, url: string) {
    super(`SERVICE_INDEPENDENCE_VIOLATION: host "${host}" is in denyHosts (url=${url})`);
    this.name = 'DenyHostError';
    this.host = host;
    this.url = url;
  }
}

// The typed errors discriminate on their stable `code` property, never on
// class identity: the package ships several entry points in two module
// formats, so a consumer's `BodyTooLargeError` (thrown by a custom transport
// that imported it from another entry) is a different class object than the
// verifier's. `instanceof` is kept as the fast path for the common
// same-module case.

/** Whether `e` is a deny-host refusal (`SERVICE_INDEPENDENCE_VIOLATION`). */
export function isDenyHostError(e: unknown): e is DenyHostError {
  return (
    e instanceof DenyHostError ||
    (typeof e === 'object' &&
      e !== null &&
      (e as { code?: unknown }).code === 'SERVICE_INDEPENDENCE_VIOLATION')
  );
}

/** Whether `e` is a body-cap abort (`OUTBOUND_BODY_TOO_LARGE`). */
export function isBodyTooLargeError(e: unknown): e is BodyTooLargeError {
  return (
    e instanceof BodyTooLargeError ||
    (typeof e === 'object' &&
      e !== null &&
      (e as { code?: unknown }).code === 'OUTBOUND_BODY_TOO_LARGE')
  );
}

export class UnsupportedProtocolError extends Error {
  readonly code = 'UNSUPPORTED_PROTOCOL';
  readonly protocol: string;
  readonly url: string;
  constructor(protocol: string, url: string) {
    super(`UNSUPPORTED_PROTOCOL: "${protocol}" not in {http:, https:} (url=${url})`);
    this.name = 'UnsupportedProtocolError';
    this.protocol = protocol;
    this.url = url;
  }
}

export class UnsupportedMethodError extends Error {
  readonly code = 'UNSUPPORTED_METHOD';
  readonly method: string;
  readonly url: string;
  constructor(method: string, url: string) {
    super(`UNSUPPORTED_METHOD: "${method}" not in {GET, POST} (url=${url})`);
    this.name = 'UnsupportedMethodError';
    this.method = method;
    this.url = url;
  }
}

export class BodyTooLargeError extends Error {
  readonly code = 'OUTBOUND_BODY_TOO_LARGE';
  readonly url: string;
  readonly limitBytes: number;
  constructor(url: string, limitBytes: number) {
    super(`OUTBOUND_BODY_TOO_LARGE: response exceeded ${limitBytes} bytes (url=${url})`);
    this.name = 'BodyTooLargeError';
    this.url = url;
    this.limitBytes = limitBytes;
  }
}

export class OutboundExhaustedError extends Error {
  readonly code = 'OUTBOUND_EXHAUSTED';
  readonly url: string;
  readonly attempts: number;
  readonly lastStatus: number | undefined;
  readonly lastError: Error | undefined;
  constructor(args: {
    url: string;
    attempts: number;
    lastStatus?: number | undefined;
    lastError?: Error | undefined;
  }) {
    super(
      `OUTBOUND_EXHAUSTED: ${args.attempts} attempts exhausted (url=${args.url}, lastStatus=${args.lastStatus ?? '-'})`,
    );
    this.name = 'OutboundExhaustedError';
    this.url = args.url;
    this.attempts = args.attempts;
    this.lastStatus = args.lastStatus;
    this.lastError = args.lastError;
  }
}

export const DEFAULT_TIMEOUT_MS = 10_000;
// Default response-body cap for the verifier's gateway fetches. 64 MiB sits
// well above any single sealed-PoE ciphertext or merkle-leaf payload a verifier
// would realistically recompute a hash over, while bounding the memory a hostile
// gateway can force the verifier to allocate for one request. Callers that
// legitimately handle larger content raise it per-call via `opts.maxBytes`.
export const DEFAULT_OUTBOUND_MAX_BYTES = 64 * 1024 * 1024;
export const DEFAULT_RETRYABLE_STATUSES: ReadonlyArray<number> = [502, 503, 504];
const BACKOFF_BASE_MS: ReadonlyArray<number> = [1000, 2000, 4000];
const JITTER_RATIO = 0.25;

function canonicaliseHost(host: string): string {
  return host.replace(/^\[/, '').replace(/\]$/, '').replace(/\.$/, '').toLowerCase();
}

// Maximum redirect hops the arweave-gateway content fetch will follow before
// treating the gateway as failed. Arweave gateways 302 once
// (`{gw}/{txid}` → sandbox subdomain); the small ceiling tolerates a gateway
// that chains a couple of internal hops while bounding the work.
const MAX_REDIRECT_HOPS = 3;

// Decide whether a 3xx Location may be followed for the arweave content-fetch
// purpose. Arweave gateways 302 `{gw}/{txid}` → `{base32}.{gw}/{txid}` (a
// sandbox subdomain of the SAME registrable domain); following same-domain
// redirects is REQUIRED to fetch content. Cross-domain redirects stay blocked
// to prevent SSRF pivots (e.g. a 302 → 169.254.169.254 or → evil.com): the
// SDK runs server-side (Node), so the browser is not a boundary and the
// validation must live here in code.
//
// Every hop of a multi-hop chain is anchored against the ORIGINAL gateway host
// — the host of the URL the fetch STARTED from — not the previous hop's host.
// Anchoring on the previous hop would let the allowed host drift as the chain
// is followed (`a.arweave.net` → `evil.com` would pass once the comparison
// host had already drifted to `a.arweave.net`'s domain), and would also wrongly
// refuse a legitimate sibling sandbox (`a.arweave.net` → `b.arweave.net`).
// `originalGwHost` is canonicalised once by the caller before the follow-loop.
//
// Returns the absolute, same-domain, non-denied target URL to re-issue the GET
// against, or `null` to fail this gateway.
function resolveSameDomainRedirect(
  fromUrl: string,
  location: string | null,
  originalGwHost: string,
  denyHosts: ReadonlyArray<string>,
): string | null {
  if (location === null) return null;
  let target: URL;
  try {
    target = new URL(location, fromUrl);
  } catch {
    return null;
  }
  // 1. The Location must resolve to an absolute https URL.
  if (target.protocol !== 'https:') return null;
  // 2. The Location host must equal the ORIGINAL gateway's host or be a
  //    subdomain of it: `host === originalGwHost || host.endsWith("." + originalGwHost)`.
  const host = canonicaliseHost(target.hostname);
  if (host !== originalGwHost && !host.endsWith('.' + originalGwHost)) return null;
  // 3. The redirect target must not be in the deny-host list — the same check
  //    the wrapper applied to the original url, re-applied to the new target.
  if (denyHosts.length > 0 && matchesDenyList(host, denyHosts)) return null;
  return target.toString();
}

export function matchesDenyList(host: string, denyHosts: ReadonlyArray<string>): boolean {
  const h = canonicaliseHost(host);
  for (const raw of denyHosts) {
    const pattern = raw.replace(/\.$/, '').toLowerCase();
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      if (h.endsWith('.' + suffix)) return true;
      continue;
    }
    if (h === pattern) return true;
    if (pattern === 'localhost') {
      if (h === '::1' || h === '0.0.0.0' || h === '169.254.169.254') return true;
    }
    if (pattern === '127.0.0.1') {
      if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    }
  }
  return false;
}

function parseProtocol(url: string): string | null {
  try {
    return new URL(url).protocol;
  } catch {
    return null;
  }
}

function isAllowedMethod(method: string): method is HttpMethod {
  return method === 'GET' || method === 'POST';
}

function backoffJitteredMs(attemptIndex: number): number {
  const idx = Math.min(attemptIndex, BACKOFF_BASE_MS.length - 1);
  const base = BACKOFF_BASE_MS[idx] ?? BACKOFF_BASE_MS[BACKOFF_BASE_MS.length - 1]!;
  const jitter = 1 + (Math.random() - 0.5) * 2 * JITTER_RATIO;
  return base * jitter;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export const defaultFetchOutbound: FetchOutbound = async (url, opts) => {
  const t0 = Date.now();
  const maxBytes = opts.maxBytes ?? DEFAULT_OUTBOUND_MAX_BYTES;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  try {
    let currentUrl = url;
    // Anchor every redirect hop against the host of the URL the fetch STARTED
    // from, captured once here. As the chain is followed, `currentUrl` drifts
    // onto the (validated) sandbox subdomains; the same-domain test must keep
    // comparing against this fixed original host, never the per-hop host.
    let originalGwHost: string | null;
    try {
      originalGwHost = canonicaliseHost(new URL(url).hostname);
    } catch {
      originalGwHost = null;
    }
    for (let hop = 0; ; hop++) {
      // The arweave content-fetch purpose follows same-domain sandbox
      // redirects manually (see below); every other purpose keeps the
      // refuse-all-redirects behaviour, surfacing a readable 3xx as a non-2xx
      // status (like a 5xx) so the caller's attempt handling fails the
      // gateway. The webhook purpose never reaches here — the wrapper rejects
      // it before dispatch (see `wrapFetchOutbound`).
      const res = await issueRequest(currentUrl, opts, controller.signal);

      // For the arweave purpose only, decide whether to follow a 3xx to a
      // validated same-domain target. Arweave gateways 302
      // `{gw}/{txid}` → `{base32}.{gw}/{txid}` (a sandbox subdomain of the
      // SAME registrable domain); following same-domain redirects is REQUIRED
      // to fetch content, while cross-domain redirects stay blocked to prevent
      // SSRF pivots (e.g. a 302 → 169.254.169.254). The SDK runs server-side
      // (Node), so the browser is not a boundary — the validation runs in code.
      if (opts.purpose === 'arweave' && res.status >= 300 && res.status < 400) {
        if (hop >= MAX_REDIRECT_HOPS) {
          throw new Error(
            `redirect limit exceeded (${MAX_REDIRECT_HOPS} hops): ${url} kept redirecting`,
          );
        }
        const next =
          originalGwHost === null
            ? null
            : resolveSameDomainRedirect(
                currentUrl,
                res.headers.get('location'),
                originalGwHost,
                opts.denyHosts ?? [],
              );
        if (next === null) {
          // Not an absolute https same-domain non-denied target: treat this
          // gateway as failed and let the caller move to the next gateway.
          throw new Error(
            `redirect refused: ${currentUrl} → ${res.headers.get('location') ?? '(no Location)'} is not a same-domain https target`,
          );
        }
        // Drain/cancel the 3xx body so the socket can be reused, then re-issue.
        await res.body?.cancel().catch(() => undefined);
        currentUrl = next;
        continue;
      }

      // Browser runtimes surface a refused redirect as an opaque response
      // (type 'opaqueredirect', status 0) with no readable status or body;
      // there is nothing to report from it, so it fails like a transport error.
      if (res.type === 'opaqueredirect') {
        throw new Error(`redirect refused (opaqueredirect): ${url} answered with a redirect`);
      }

      // Fast path: a truthful Content-Length over the cap lets us bail before
      // reading a single body byte. A lying/absent header is still caught by the
      // streaming counter below — the header is an optimisation, not the guard.
      const declared = res.headers.get('content-length');
      if (declared !== null) {
        const declaredLen = Number(declared);
        if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
          controller.abort();
          throw new BodyTooLargeError(currentUrl, maxBytes);
        }
      }

      const bytes = await readBodyCapped(res, currentUrl, maxBytes, controller);
      return { status: res.status, bytes, durationMs: Date.now() - t0 };
    }
  } finally {
    clearTimeout(timeout);
  }
};

// Issue one request with manual redirect handling. `redirect: 'manual'` means
// a 3xx is returned verbatim — the transport, not the runtime, decides whether
// to follow it (same-domain arweave sandbox redirects only; see
// `defaultFetchOutbound`). The body/Content-Length guards run on the response
// the caller ultimately consumes, not on intermediate 3xx hops.
async function issueRequest(
  url: string,
  opts: FetchOutboundOptions,
  signal: AbortSignal,
): Promise<Response> {
  const init: RequestInit = {
    method: opts.method,
    signal,
    redirect: 'manual',
  };
  if (opts.headers) init.headers = { ...opts.headers };
  if (opts.body !== undefined) init.body = opts.body;
  // allow-raw-fetch: canonical defaultFetchOutbound — single egress point
  return fetch(url, init);
}

// Stream the response body, aborting the underlying request the instant the
// running byte count exceeds `maxBytes`. This is the actual OOM guard: a
// gateway that withholds or lies about Content-Length still cannot make us
// buffer more than the cap, because we stop reading and tear the socket down.
async function readBodyCapped(
  res: Response,
  url: string,
  maxBytes: number,
  controller: AbortController,
): Promise<Uint8Array> {
  const body = res.body;
  if (body === null) {
    // No stream (e.g. a 204, or a fetch polyfill that buffered eagerly). Fall
    // back to arrayBuffer but still enforce the cap on the materialised length.
    const buf = await res.arrayBuffer();
    if (buf.byteLength > maxBytes) {
      throw new BodyTooLargeError(url, maxBytes);
    }
    return new Uint8Array(buf);
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        controller.abort();
        throw new BodyTooLargeError(url, maxBytes);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export function wrapFetchOutbound(
  inner: FetchOutbound,
  audit: HttpCallRecord[],
  config: WrapFetchOutboundConfig | ReadonlyArray<string> | undefined = undefined,
): FetchOutbound {
  // Accept either a denyHosts array (positional) or the full config object.
  const normConfig: WrapFetchOutboundConfig =
    config === undefined
      ? {}
      : Array.isArray(config)
        ? { denyHosts: config as ReadonlyArray<string> }
        : (config as WrapFetchOutboundConfig);

  const denyHosts = normConfig.denyHosts ?? [];
  // Default retries=0 (single attempt). Callers opt in via explicit `retries`;
  // the top-level `fetchOutbound` entrypoint forwards caller config.
  const retries = normConfig.retries ?? 0;
  const retryableStatuses = normConfig.retryableStatuses ?? DEFAULT_RETRYABLE_STATUSES;

  return async (url, opts) => {
    // Safe egress to a user-supplied (webhook-style) URL needs a bespoke
    // DNS-pinning SSRF guard: resolve the host, range-check every A/AAAA
    // record against the private/reserved blocklist, and pin the TCP
    // connection to the checked IP so a rebinding resolver cannot swap the
    // target after the check. This generic wrapper deliberately provides
    // none of that, so it refuses the purpose instead of silently treating
    // the URL as an ordinary fetch.
    if (opts.purpose === 'webhook') {
      audit.push({
        url,
        method: 'GET',
        status: null,
        bytes: 0,
        durationMs: 0,
        purpose: opts.purpose,
      });
      throw new Error(
        `webhook purpose rejected: user-supplied URLs require a DNS-pinning SSRF guard, which the generic fetchOutbound deliberately does not provide (url=${url})`,
      );
    }

    // Protocol allowlist.
    const protocol = parseProtocol(url);
    if (protocol !== 'http:' && protocol !== 'https:') {
      audit.push({
        url,
        method: 'GET',
        status: null,
        bytes: 0,
        durationMs: 0,
        purpose: opts.purpose,
      });
      throw new UnsupportedProtocolError(protocol ?? '', url);
    }

    // Method allowlist.
    if (!isAllowedMethod(opts.method)) {
      audit.push({
        url,
        method: 'GET',
        status: null,
        bytes: 0,
        durationMs: 0,
        purpose: opts.purpose,
      });
      throw new UnsupportedMethodError(opts.method, url);
    }

    // Deny-list short-circuit.
    if (denyHosts.length > 0) {
      const host = new URL(url).hostname;
      if (matchesDenyList(host, denyHosts)) {
        audit.push({
          url,
          method: opts.method,
          status: null,
          bytes: 0,
          durationMs: 0,
          purpose: opts.purpose,
        });
        throw new DenyHostError(canonicaliseHost(host), url);
      }
    }

    // Forward the deny-host list to the transport so it can re-apply the same
    // check to any same-domain redirect target it chooses to follow (arweave
    // purpose). The wrapper already validated the original url above; the
    // transport re-validates each redirect hop.
    const innerOpts: FetchOutboundOptions = denyHosts.length > 0 ? { ...opts, denyHosts } : opts;

    // Retry loop. retries=0 → single attempt, return-or-rethrow original.
    let lastStatus: number | undefined;
    let lastError: Error | undefined;
    const totalAttempts = retries + 1;
    for (let attempt = 1; attempt <= totalAttempts; attempt++) {
      const t0 = Date.now();
      try {
        const result = await inner(url, innerOpts);
        audit.push({
          url,
          method: opts.method,
          status: result.status,
          bytes: result.bytes.byteLength,
          durationMs: result.durationMs,
          purpose: opts.purpose,
        });
        if (retryableStatuses.includes(result.status) && retries > 0) {
          lastStatus = result.status;
          if (attempt < totalAttempts) {
            await sleep(backoffJitteredMs(attempt - 1));
            continue;
          }
          break;
        }
        return result;
      } catch (e) {
        const durationMs = Date.now() - t0;
        if (
          e instanceof DenyHostError ||
          e instanceof UnsupportedProtocolError ||
          e instanceof UnsupportedMethodError
        ) {
          audit.push({
            url,
            method: opts.method,
            status: null,
            bytes: 0,
            durationMs,
            purpose: opts.purpose,
          });
          throw e;
        }
        audit.push({
          url,
          method: opts.method,
          status: null,
          bytes: 0,
          durationMs,
          purpose: opts.purpose,
        });
        lastError = e as Error;
        if (attempt < totalAttempts) {
          await sleep(backoffJitteredMs(attempt - 1));
          continue;
        }
        break;
      }
    }
    // Single-attempt mode re-throws the original verbatim so callers can match
    // by identity; retry mode wraps the terminal failure in OutboundExhaustedError.
    if (retries === 0 && lastError !== undefined) {
      throw lastError;
    }
    throw new OutboundExhaustedError({ url, attempts: totalAttempts, lastStatus, lastError });
  };
}

export async function fetchOutbound(
  url: string,
  opts: FetchOutboundOptions,
  audit: HttpCallRecord[],
  config: WrapFetchOutboundConfig = {},
): Promise<FetchOutboundResult> {
  const wrapped = wrapFetchOutbound(defaultFetchOutbound, audit, config);
  return wrapped(url, opts);
}
