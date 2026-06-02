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
// `webhook` is the user-supplied-URL purpose: it triggers the SSRF guard
// (DNS resolution + IP range check + connection pinning + redirect-chain
// re-checking + body-size cap), and MUST be used for any fetch where the
// target URL came from end-user input.
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

// Audit-log entry for one outbound HTTP fetch. Field names are snake_case so
// the record can land directly on `VerifyReport.http_calls[]` (which IS the
// wire shape) without a key-renaming pass.
export interface HttpCallRecord {
  readonly url: string;
  readonly method: HttpMethod;
  readonly status: number;
  readonly bytes: number;
  readonly duration_ms: number;
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
  const init: RequestInit = {
    method: opts.method,
    signal: controller.signal,
  };
  if (opts.headers) init.headers = { ...opts.headers };
  if (opts.body !== undefined) init.body = opts.body;
  try {
    // allow-raw-fetch: canonical defaultFetchOutbound — single egress point
    const res = await fetch(url, init);

    // Fast path: a truthful Content-Length over the cap lets us bail before
    // reading a single body byte. A lying/absent header is still caught by the
    // streaming counter below — the header is an optimisation, not the guard.
    const declared = res.headers.get('content-length');
    if (declared !== null) {
      const declaredLen = Number(declared);
      if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
        controller.abort();
        throw new BodyTooLargeError(url, maxBytes);
      }
    }

    const bytes = await readBodyCapped(res, url, maxBytes, controller);
    return { status: res.status, bytes, durationMs: Date.now() - t0 };
  } finally {
    clearTimeout(timeout);
  }
};

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
    // The `webhook` purpose has bespoke requirements (DNS pinning,
    // per-hop redirect re-checking, body-size cap) that the generic
    // wrapper cannot satisfy. Force callers to use `fetchWebhook`
    // instead of silently accepting the call here.
    if (opts.purpose === 'webhook') {
      audit.push({
        url,
        method: 'GET',
        status: 0,
        bytes: 0,
        duration_ms: 0,
        purpose: opts.purpose,
      });
      throw new Error(
        `webhook purpose must be sent via fetchWebhook, not fetchOutbound (url=${url})`,
      );
    }

    // Protocol allowlist.
    const protocol = parseProtocol(url);
    if (protocol !== 'http:' && protocol !== 'https:') {
      audit.push({
        url,
        method: 'GET',
        status: 0,
        bytes: 0,
        duration_ms: 0,
        purpose: opts.purpose,
      });
      throw new UnsupportedProtocolError(protocol ?? '', url);
    }

    // Method allowlist.
    if (!isAllowedMethod(opts.method)) {
      audit.push({
        url,
        method: 'GET',
        status: 0,
        bytes: 0,
        duration_ms: 0,
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
          status: 0,
          bytes: 0,
          duration_ms: 0,
          purpose: opts.purpose,
        });
        throw new DenyHostError(canonicaliseHost(host), url);
      }
    }

    // Retry loop. retries=0 → single attempt, return-or-rethrow original.
    let lastStatus: number | undefined;
    let lastError: Error | undefined;
    const totalAttempts = retries + 1;
    for (let attempt = 1; attempt <= totalAttempts; attempt++) {
      const t0 = Date.now();
      try {
        const result = await inner(url, opts);
        audit.push({
          url,
          method: opts.method,
          status: result.status,
          bytes: result.bytes.byteLength,
          duration_ms: result.durationMs,
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
            status: 0,
            bytes: 0,
            duration_ms: durationMs,
            purpose: opts.purpose,
          });
          throw e;
        }
        audit.push({
          url,
          method: opts.method,
          status: 0,
          bytes: 0,
          duration_ms: durationMs,
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
