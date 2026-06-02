// RFC 7807 `application/problem+json` envelope and the typed error class
// hierarchy the SDK throws on every non-2xx response.
//
// Every CIP-309 gateway `/api/v1/*` route emits the canonical shape:
//
//   Content-Type: application/problem+json
//   {
//     "type":     "about:blank",
//     "title":    "Payment Required",
//     "status":   402,
//     "detail":   "Required $0.18 for this publish; balance is $0.05.",
//     "code":     "insufficient-funds",
//     "trace_id": "01977c...",
//     "errors":   [{"field": "items.0.hashes", "code": "invalid_type", "detail": "..."}],
//     <extension members per RFC 7807 §3.2, e.g. balance_usd_micros / required_usd_micros>
//   }
//
// Field semantics:
//   - `code` is lowercase-kebab. Consumers dispatch on `code`; the SDK already
//     dispatches on `code` to pick the most-specific subclass.
//   - `status` matches the HTTP status. `httpStatus` is a convenience alias.
//   - `errors[]` carries per-field validation errors (Zod-derived on the
//     server). `field` is the dotted JSON path; empty string denotes a
//     body-level issue.
//   - `trace_id` is echoed on the `X-Request-Id` response header for log
//     correlation. Use `err.traceId` when filing bug reports (the SDK
//     surfaces it as the camelCase `traceId` property — only the wire field
//     is snake_case, to match the rest of the API surface).
//   - Extension members (anything outside the canonical seven fields) are
//     surfaced on `err.extensions`. Typed subclasses project the relevant
//     extension fields onto camelCase getters (e.g. `top_up_url` → `topUpUrl`).

/** RFC 7807 per-field error entry. */
export interface ProblemErrorEntry {
  /** Dotted JSON path of the offending field; empty for body-level errors. */
  readonly field: string;
  /** Stable lowercase-kebab (or Zod issue) code for the specific failure. */
  readonly code: string;
  /** Human-readable explanation of this individual field error. */
  readonly detail: string;
}

/**
 * RFC 7807 `application/problem+json` document as emitted by every CIP-309
 * gateway `/api/v1/*` route.
 *
 * Canonical fields (`type`, `title`, `status`, `detail`, `code`, `trace_id`)
 * are always present. `errors` is present on validation responses.
 * `instance` is optional per RFC 7807 §3.1.
 *
 * Additional top-level fields are RFC 7807 §3.2 extension members and are
 * preserved verbatim on `Cip309HttpError.extensions`.
 */
export interface ProblemDetails {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly detail: string;
  readonly code: string;
  readonly trace_id: string;
  readonly errors?: ReadonlyArray<ProblemErrorEntry>;
  readonly instance?: string;
  /** RFC 7807 §3.2 extension members. */
  readonly [extension: string]: unknown;
}

/** The set of canonical RFC 7807 fields, used to split extensions cleanly. */
const CANONICAL_PROBLEM_KEYS: ReadonlySet<string> = new Set([
  'type',
  'title',
  'status',
  'detail',
  'code',
  'trace_id',
  'errors',
  'instance',
]);

/**
 * Pull RFC 7807 §3.2 extension members out of a problem document. The result
 * is a fresh object containing every top-level key that is NOT one of the
 * canonical fields above.
 */
export function extractProblemExtensions(problem: ProblemDetails): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(problem)) {
    if (!CANONICAL_PROBLEM_KEYS.has(key)) {
      out[key] = value;
    }
  }
  return out;
}

export interface Cip309HttpErrorInit {
  /** The verbatim problem document. */
  readonly problem: ProblemDetails;
  /** Pre-split extension members. Computed from `problem` when omitted. */
  readonly extensions?: Record<string, unknown>;
  /** Value of the `X-Request-Id` response header. Falls back to `problem.trace_id`. */
  readonly requestId?: string | undefined;
  /** Value of the `Retry-After` response header (seconds), if present. */
  readonly retryAfterSeconds?: number | undefined;
}

/**
 * Parent class for every typed SDK HTTP error. Carries the full RFC 7807
 * problem document plus headers (`X-Request-Id`, `Retry-After`) relevant for
 * retry logic and log correlation.
 *
 * Consumers can dispatch on:
 *   - `err.code`        — lowercase-kebab problem code
 *   - `err.httpStatus`  — HTTP status (= `err.problem.status`)
 *   - `instanceof <SpecificError>` — see the subclasses re-exported from
 *     `@cardanowall/sdk-ts`
 */
export class Cip309HttpError extends Error {
  public readonly problem: ProblemDetails;
  public readonly code: string;
  public readonly httpStatus: number;
  public readonly title: string;
  public readonly detail: string;
  public readonly type: string;
  public readonly traceId: string;
  public readonly instance: string | undefined;
  public readonly errors: ReadonlyArray<ProblemErrorEntry> | undefined;
  public readonly extensions: Record<string, unknown>;
  public readonly requestId: string;
  public readonly retryAfterSeconds: number | undefined;

  constructor(init: Cip309HttpErrorInit) {
    super(init.problem.detail || `${init.problem.title} (HTTP ${init.problem.status})`);
    this.name = 'Cip309HttpError';
    this.problem = init.problem;
    this.code = init.problem.code;
    this.httpStatus = init.problem.status;
    this.title = init.problem.title;
    this.detail = init.problem.detail;
    this.type = init.problem.type;
    this.traceId = init.problem.trace_id;
    this.instance = init.problem.instance;
    this.errors = init.problem.errors;
    this.extensions = init.extensions ?? extractProblemExtensions(init.problem);
    // X-Request-Id falls back to the in-body trace_id so callers always have a
    // correlation handle even when the header is stripped by a proxy.
    this.requestId = init.requestId ?? init.problem.trace_id;
    this.retryAfterSeconds = init.retryAfterSeconds;
  }
}
