// Threshold-gated resumable upload driver.
//
// A file at or below `threshold` is sent with the existing single-shot
// `uploads()` call, unchanged. A larger file is uploaded as a content-addressed
// session: the helper hashes the whole file once (streaming, so a multi-GB file
// is never buffered), creates a session, PUTs each fixed-size chunk (several in
// parallel, retrying a failed chunk), then completes — polling the shared
// attempt endpoint if completion is accepted asynchronously. Both paths converge
// on one `ar://` URI.
//
// The chunk size is the server's call: the create response returns the
// authoritative `chunk_bytes` and a `max_chunk_bytes` ceiling, and the helper
// recomputes its grid from those rather than from what it requested. So a
// deployment behind a stricter proxy cap is honoured without an SDK release.

import { sha256, sha256Stream } from '@cardanowall/crypto-core/hash';

import { Label309HttpError } from './http-error';
import { readJson, throwIfNotOk } from './http-helpers';
import { toResumableSource, type ResumableSource } from './resumable-source';
import type {
  FetchImpl,
  StorageTarget,
  UploadResumableInput,
  UploadResumableResult,
  UploadSessionChunkResponse,
  UploadSessionCompleteResponse,
  UploadSessionCreateResponse,
  UploadSessionDeduplicatedResponse,
  UploadSessionStatus,
  UploadAttemptStatus,
  UploadAttemptCommitted,
  UploadAttemptReleased,
} from './types';

interface ResolvedConfig {
  readonly apiKey: string | undefined;
  readonly baseUrl: string;
  readonly fetch: FetchImpl;
}

// Single-shot uploads() of one blob, returning the resolved URI. Imported as a
// callback so the driver does not depend on the PoeNamespace class shape.
export type SingleShotUpload = (args: {
  readonly target: StorageTarget;
  readonly bytes: Uint8Array;
  readonly idempotencyKey?: string;
  readonly signal?: AbortSignal;
}) => Promise<{ readonly uri: string; readonly sha256: string; readonly bytes: number }>;

// ~48 MiB. Sits comfortably under a 100 MB CDN body cap AND under stricter
// nginx/proxy defaults below it, so a single chunk PUT clears the smallest
// common single-request ceiling. Both the switch-to-chunked threshold and the
// requested chunk size default here; the server's max_chunk_bytes always wins.
export const DEFAULT_RESUMABLE_THRESHOLD_BYTES = 50_331_648;
export const DEFAULT_RESUMABLE_CHUNK_BYTES = 50_331_648;
const DEFAULT_PARALLELISM = 4;
const DEFAULT_MAX_CHUNK_RETRIES = 4;
const DEFAULT_CONTENT_TYPE = 'application/octet-stream';
const DEFAULT_TARGET: StorageTarget = 'arweave';
const ATTEMPT_POLL_INTERVAL_MS = 1000;
const ATTEMPT_POLL_MAX_ATTEMPTS = 600;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Standards-only base64 (RFC 4648) over raw bytes, used for the per-chunk
// `Digest: sha-256=<base64>` header. A hand-rolled encoder keeps the helper free
// of any runtime-specific path (`btoa` is DOM-only, `Buffer` is Node-only).
const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      B64_ALPHABET[(n >> 18) & 63]! +
      B64_ALPHABET[(n >> 12) & 63]! +
      B64_ALPHABET[(n >> 6) & 63]! +
      B64_ALPHABET[n & 63]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += B64_ALPHABET[(n >> 18) & 63]! + B64_ALPHABET[(n >> 12) & 63]! + '==';
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      B64_ALPHABET[(n >> 18) & 63]! +
      B64_ALPHABET[(n >> 12) & 63]! +
      B64_ALPHABET[(n >> 6) & 63]! +
      '=';
  }
  return out;
}

function jsonHeaders(config: ResolvedConfig, idempotencyKey?: string): Headers {
  const headers = new Headers({ 'content-type': 'application/json', accept: 'application/json' });
  if (config.apiKey !== undefined) headers.set('authorization', `Bearer ${config.apiKey}`);
  if (idempotencyKey !== undefined) headers.set('idempotency-key', idempotencyKey);
  return headers;
}

function octetHeaders(config: ResolvedConfig, length: number, digestBase64: string): Headers {
  const headers = new Headers({
    'content-type': 'application/octet-stream',
    accept: 'application/json',
    'content-length': String(length),
    digest: `sha-256=${digestBase64}`,
  });
  if (config.apiKey !== undefined) headers.set('authorization', `Bearer ${config.apiKey}`);
  return headers;
}

const SESSIONS_PATH = '/api/v1/poe/uploads/sessions';

function chunkRange(index: number, chunkBytes: number, totalBytes: number): [number, number] {
  const start = index * chunkBytes;
  return [start, Math.min(start + chunkBytes, totalBytes)];
}

function missingIndices(received: ReadonlyArray<number>, chunkCount: number): number[] {
  const have = new Set(received);
  const out: number[] = [];
  for (let i = 0; i < chunkCount; i++) if (!have.has(i)) out.push(i);
  return out;
}

/**
 * The authoritative set of chunk indices to send for a resumed session. The
 * server's `missing` set is the source of truth; `received` is only a progress
 * signal. A gateway that omits `missing` (older deployments) falls back to the
 * gap derived from `received` so resume still works.
 */
function serverMissing(status: UploadSessionStatus): ReadonlyArray<number> {
  if (Array.isArray(status.missing)) return status.missing;
  return missingIndices(status.received, status.chunk_count);
}

/** Whole-file SHA-256 (hex) over the source, streamed so a large file is never buffered. */
async function hashWholeFile(source: ResumableSource): Promise<string> {
  return bytesToHex(await sha256Stream(source.stream()));
}

async function createSession(
  config: ResolvedConfig,
  body: {
    target: StorageTarget;
    sha256: string;
    total_bytes: number;
    chunk_bytes: number;
    content_type: string;
  },
  signal: AbortSignal | undefined,
): Promise<UploadSessionCreateResponse | UploadSessionDeduplicatedResponse> {
  const response = await config.fetch(`${config.baseUrl}${SESSIONS_PATH}`, {
    method: 'POST',
    headers: jsonHeaders(config),
    body: JSON.stringify(body),
    ...(signal ? { signal } : {}),
  });
  // A 402 funding error is surfaced through the typed-error path like any other
  // non-2xx; the dedup short-circuit arrives as a 200 and is read below.
  await throwIfNotOk(response);
  return (await readJson(response)) as
    | UploadSessionCreateResponse
    | UploadSessionDeduplicatedResponse;
}

async function getSessionStatus(
  config: ResolvedConfig,
  sessionId: string,
  signal: AbortSignal | undefined,
): Promise<UploadSessionStatus> {
  const response = await config.fetch(
    `${config.baseUrl}${SESSIONS_PATH}/${encodeURIComponent(sessionId)}`,
    {
      method: 'GET',
      headers: jsonHeaders(config),
      ...(signal ? { signal } : {}),
    },
  );
  await throwIfNotOk(response);
  return (await readJson(response)) as UploadSessionStatus;
}

async function putChunk(
  config: ResolvedConfig,
  sessionId: string,
  index: number,
  bytes: Uint8Array,
  signal: AbortSignal | undefined,
): Promise<UploadSessionChunkResponse> {
  const digest = bytesToBase64(sha256(bytes));
  const response = await config.fetch(
    `${config.baseUrl}${SESSIONS_PATH}/${encodeURIComponent(sessionId)}/chunks/${index}`,
    {
      method: 'PUT',
      headers: octetHeaders(config, bytes.byteLength, digest),
      // A Blob body streams without copying; a matching-digest re-PUT is an
      // idempotent 200 server-side, so a retried chunk is always safe.
      body: new Blob([bytes as unknown as ArrayBuffer], { type: 'application/octet-stream' }),
      ...(signal ? { signal } : {}),
    },
  );
  await throwIfNotOk(response);
  return (await readJson(response)) as UploadSessionChunkResponse;
}

async function completeSession(
  config: ResolvedConfig,
  sessionId: string,
  idempotencyKey: string,
  signal: AbortSignal | undefined,
): Promise<UploadSessionCompleteResponse> {
  const response = await config.fetch(
    `${config.baseUrl}${SESSIONS_PATH}/${encodeURIComponent(sessionId)}/complete`,
    {
      method: 'POST',
      headers: jsonHeaders(config, idempotencyKey),
      ...(signal ? { signal } : {}),
    },
  );
  await throwIfNotOk(response);
  return (await readJson(response)) as UploadSessionCompleteResponse;
}

async function pollAttempt(
  config: ResolvedConfig,
  attemptId: string,
  signal: AbortSignal | undefined,
): Promise<UploadAttemptCommitted | UploadAttemptReleased> {
  for (let attempt = 0; attempt < ATTEMPT_POLL_MAX_ATTEMPTS; attempt++) {
    const response = await config.fetch(
      `${config.baseUrl}/api/v1/poe/uploads/attempts/${encodeURIComponent(attemptId)}`,
      {
        method: 'GET',
        headers: jsonHeaders(config),
        ...(signal ? { signal } : {}),
      },
    );
    await throwIfNotOk(response);
    const status = (await readJson(response)) as UploadAttemptStatus;
    // `reserved` is the only in-flight state; `committed` and `released` are
    // terminal and returned to the caller to resolve.
    if (status.state !== 'reserved') return status;
    await delay(ATTEMPT_POLL_INTERVAL_MS, signal);
  }
  throw new ResumableUploadError(
    'ATTEMPT_POLL_TIMEOUT',
    `upload attempt ${attemptId} did not reach a terminal state in time`,
  );
}

function delay(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signalReason(signal));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signalReason(signal));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function signalReason(signal: AbortSignal | undefined): Error {
  const reason = signal?.reason;
  return reason instanceof Error ? reason : new ResumableUploadError('ABORTED', 'upload aborted');
}

export class ResumableUploadError extends Error {
  readonly code:
    | 'SHA256_MISMATCH'
    | 'SESSION_FAILED'
    | 'ATTEMPT_FAILED'
    | 'ATTEMPT_POLL_TIMEOUT'
    | 'CHUNK_UPLOAD_FAILED'
    | 'ABORTED';

  constructor(code: ResumableUploadError['code'], message: string) {
    super(message);
    this.name = 'ResumableUploadError';
    this.code = code;
  }
}

/** Upload `missing` chunk indices with bounded parallelism, retrying each on failure. */
async function uploadChunks(
  config: ResolvedConfig,
  sessionId: string,
  source: ResumableSource,
  chunkBytes: number,
  totalBytes: number,
  missing: ReadonlyArray<number>,
  parallelism: number,
  maxRetries: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  let cursor = 0;
  const workers: Promise<void>[] = [];
  const lanes = Math.max(1, Math.min(parallelism, missing.length || 1));
  for (let lane = 0; lane < lanes; lane++) {
    workers.push(
      (async () => {
        for (;;) {
          if (signal?.aborted) throw signalReason(signal);
          const next = cursor++;
          if (next >= missing.length) return;
          const index = missing[next]!;
          const [start, end] = chunkRange(index, chunkBytes, totalBytes);
          const bytes = await source.slice(start, end);
          await putChunkWithRetry(config, sessionId, index, bytes, maxRetries, signal);
        }
      })(),
    );
  }
  await Promise.all(workers);
}

async function putChunkWithRetry(
  config: ResolvedConfig,
  sessionId: string,
  index: number,
  bytes: Uint8Array,
  maxRetries: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (signal?.aborted) throw signalReason(signal);
    try {
      await putChunk(config, sessionId, index, bytes, signal);
      return;
    } catch (err) {
      if (signal?.aborted) throw signalReason(signal);
      // A deterministic client-side 4xx (e.g. 400 chunk-size-mismatch, 400
      // chunk-digest-mismatch, 409 chunk-conflict) cannot be fixed by resending
      // the same bytes: fail fast and surface the real problem rather than
      // burning retries and masking it as CHUNK_UPLOAD_FAILED. Only transient
      // failures (network errors, 5xx, 429, 408) are worth a retry. A
      // matching-digest re-PUT is an idempotent 200 server-side, so a retried
      // transient chunk is always safe.
      if (isTerminalChunkError(err)) throw err;
      lastError = err;
      if (attempt < maxRetries) {
        // Exponential backoff (250ms, 500ms, 1s, ...) capped at 8s.
        await delay(Math.min(250 * 2 ** attempt, 8000), signal);
      }
    }
  }
  throw new ResumableUploadError(
    'CHUNK_UPLOAD_FAILED',
    `chunk ${index} failed after ${maxRetries + 1} attempt(s): ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

/**
 * Drive a single-file upload, choosing single-shot vs the chunked session flow
 * by size. See {@link UploadResumableInput} for the options.
 */
export async function uploadResumable(
  config: ResolvedConfig,
  singleShot: SingleShotUpload,
  input: UploadResumableInput,
): Promise<UploadResumableResult> {
  const source = await toResumableSource(input.source);
  const target = input.target ?? DEFAULT_TARGET;
  const threshold = input.threshold ?? DEFAULT_RESUMABLE_THRESHOLD_BYTES;
  const totalBytes = source.size;

  // Small file (or no resume requested): the unchanged single-shot path. The
  // whole file is small enough to read once into memory for the multipart body.
  if (totalBytes <= threshold && input.sessionId === undefined) {
    const bytes = await source.slice(0, totalBytes);
    const result = await singleShot({
      target,
      bytes,
      ...(input.idempotencyKey !== undefined ? { idempotencyKey: input.idempotencyKey } : {}),
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return {
      uri: result.uri,
      sha256: result.sha256,
      bytes: result.bytes,
      deduplicated: false,
      mode: 'single-shot',
    };
  }

  return runSession(config, source, target, totalBytes, input);
}

async function runSession(
  config: ResolvedConfig,
  source: ResumableSource,
  target: StorageTarget,
  totalBytes: number,
  input: UploadResumableInput,
): Promise<UploadResumableResult> {
  const signal = input.signal;

  let sessionId: string;
  let chunkBytes: number;
  let missing: ReadonlyArray<number>;
  // The declared whole-file SHA-256 (hex) the session is content-addressed by.
  // On a fresh create it is computed once over the local source; on resume it is
  // ADOPTED from the server status, never recomputed. It drives both the
  // completion idempotency key and the result `sha256`.
  let declaredSha256: string;
  // The total the chunk grid is sliced against. On a fresh create this is the
  // local source size (which the gateway echoes back, since we just declared it).
  // On resume it is the server's `total_bytes`: a source that grew between
  // attempts must not redraw the grid, or the final chunk would over-read past
  // the originally declared length and contradict the digest.
  let gridTotalBytes: number;

  if (input.sessionId !== undefined) {
    // Resume: a session is content-addressed, so its declared digest, total, and
    // chunk grid all live server-side. Adopt the server status as authoritative
    // and NEVER re-hash the local source — re-reading a multi-GB file on every
    // resume defeats the point, and a local file that changed since create would
    // yield a digest that disagrees with the actually-uploaded bounded bytes.
    const status = await getSessionStatus(config, input.sessionId, signal);
    if (status.state === 'completed' && status.uri !== null) {
      return {
        uri: status.uri,
        sha256: status.sha256,
        bytes: status.total_bytes,
        deduplicated: false,
        mode: 'chunked',
      };
    }
    if (status.state === 'failed' || status.state === 'expired') {
      throw new ResumableUploadError(
        'SESSION_FAILED',
        `cannot resume session ${input.sessionId} in state '${status.state}'`,
      );
    }
    sessionId = status.session_id;
    declaredSha256 = status.sha256;
    chunkBytes = status.chunk_bytes;
    // The server's declared total is authoritative for the chunk grid, not the
    // live local source size. The original create fixed `total_bytes`, the whole-
    // file digest, and the index<->offset mapping together; bounding the final
    // chunk against the server total keeps the last slice the exact declared
    // remainder even if the underlying source has since grown.
    gridTotalBytes = status.total_bytes;
    // The server's `missing` set is authoritative for which indices to send: it
    // is the source of truth for what the gateway holds, where `received` is
    // only a progress signal. Re-deriving the gap from `received` would diverge
    // if the server's grid ever differs from ours (e.g. a chunk it dropped after
    // acking, or a window it expresses differently).
    missing = serverMissing(status);
  } else {
    // Fresh create: this is the only path that reads the whole source to compute
    // the declared digest, streamed so a multi-GB file is never buffered.
    declaredSha256 = await hashWholeFile(source);
    const requestedChunkBytes = input.chunkBytes ?? DEFAULT_RESUMABLE_CHUNK_BYTES;
    const created = await createSession(
      config,
      {
        target,
        sha256: declaredSha256,
        total_bytes: totalBytes,
        chunk_bytes: requestedChunkBytes,
        content_type: input.contentType ?? DEFAULT_CONTENT_TYPE,
      },
      signal,
    );
    // Create-time dedup: the bytes already exist; nothing is uploaded.
    if ('deduplicated' in created) {
      return {
        uri: created.uri,
        sha256: created.sha256,
        bytes: created.bytes,
        deduplicated: true,
        mode: 'chunked',
      };
    }
    sessionId = created.session_id;
    // Honour the server's authoritative chunk size (it may clamp to its ceiling).
    chunkBytes = created.chunk_bytes;
    gridTotalBytes = totalBytes;
    // A fresh create has no `missing` field and an empty `received`, so every
    // index is outstanding.
    missing = missingIndices(created.received, created.chunk_count);
  }

  if (missing.length > 0) {
    await uploadChunks(
      config,
      sessionId,
      source,
      chunkBytes,
      gridTotalBytes,
      missing,
      input.parallelism ?? DEFAULT_PARALLELISM,
      input.maxChunkRetries ?? DEFAULT_MAX_CHUNK_RETRIES,
      signal,
    );
  }

  return finishSession(config, sessionId, declaredSha256, input);
}

// Drive /complete to a terminal result. On a 409 incomplete-upload, the server's
// status is re-fetched and the still-missing chunks are resent against the
// server-authoritative grid (`status.chunk_bytes` / `status.total_bytes`), so the
// completion path never trusts a stale local size.
async function finishSession(
  config: ResolvedConfig,
  sessionId: string,
  declaredSha256: string,
  input: UploadResumableInput,
): Promise<UploadResumableResult> {
  const signal = input.signal;
  // The completion key is the caller's promise of sameness; default it to the
  // session's declared digest (computed on create, adopted from server status on
  // resume) so a re-invocation replays the recorded terminal result.
  const idempotencyKey = input.idempotencyKey ?? `resumable-${declaredSha256}`;

  // A 409 incomplete-upload means the server is missing chunks (e.g. a write was
  // dropped after the bit flipped client-side): GET the gap, resend it, retry.
  const COMPLETE_RETRIES = 2;
  for (let attempt = 0; attempt <= COMPLETE_RETRIES; attempt++) {
    try {
      const completion = await completeSession(config, sessionId, idempotencyKey, signal);
      if ('ok' in completion) {
        return {
          uri: completion.uri,
          sha256: completion.sha256,
          bytes: completion.bytes,
          // The server sends the number 0 for a dedup-on-commit (the bytes were
          // already stored, so nothing was charged); compare numerically.
          deduplicated: completion.charged_usd_micros === 0,
          mode: 'chunked',
        };
      }
      return resolveAccepted(config, completion.attempt_id, signal);
    } catch (err) {
      if (attempt < COMPLETE_RETRIES && isIncompleteUpload(err)) {
        const status = await getSessionStatus(config, sessionId, signal);
        const stillMissing = serverMissing(status);
        if (stillMissing.length === 0) continue; // racing assembly; retry complete
        await uploadChunks(
          config,
          sessionId,
          await toResumableSource(input.source),
          status.chunk_bytes,
          // Re-bound the resend grid against the server's declared total too, so a
          // source that grew during the upload cannot over-read the final chunk.
          status.total_bytes,
          stillMissing,
          input.parallelism ?? DEFAULT_PARALLELISM,
          input.maxChunkRetries ?? DEFAULT_MAX_CHUNK_RETRIES,
          signal,
        );
        continue;
      }
      throw err;
    }
  }
  // Loop exhaustion means the gateway kept reporting an incomplete upload
  // despite resending the missing chunks.
  throw new ResumableUploadError(
    'SESSION_FAILED',
    `session ${sessionId} could not be completed after resending missing chunks`,
  );
}

async function resolveAccepted(
  config: ResolvedConfig,
  attemptId: string,
  signal: AbortSignal | undefined,
): Promise<UploadResumableResult> {
  const status = await pollAttempt(config, attemptId, signal);
  // `released` is the terminal failure; surface the server's reason.
  if (status.state === 'released') {
    throw new ResumableUploadError(
      'ATTEMPT_FAILED',
      `upload attempt ${attemptId} was released: ${status.reason}`,
    );
  }
  // `committed` is the terminal success and MUST carry a uri; a committed
  // attempt without one is a server contract violation, not a silent success.
  if (status.uri.length === 0) {
    throw new ResumableUploadError(
      'ATTEMPT_FAILED',
      `upload attempt ${attemptId} committed without a uri`,
    );
  }
  return {
    uri: status.uri,
    sha256: status.sha256,
    bytes: status.bytes,
    // A committed attempt that charged nothing deduped against bytes already
    // stored for this account on this backend.
    deduplicated: status.charged_usd_micros === 0,
    mode: 'chunked',
  };
}

/**
 * Whether a chunk-PUT error is the caller's fault (terminal) rather than a
 * transient server/transport hiccup worth retrying. A definitive client-side
 * 4xx is terminal — a conflicting digest, a size mismatch, an
 * unauthorised/forbidden caller, an expired or missing session — and resending
 * the same bytes cannot fix it. 408 (request timeout) and 429 (rate limited)
 * are transient; any non-HTTP error (a network/egress failure) is transient
 * too, since the request never reached a definitive verdict.
 */
function isTerminalChunkError(err: unknown): boolean {
  if (!(err instanceof Label309HttpError)) return false;
  const status = err.httpStatus;
  return status >= 400 && status < 500 && status !== 408 && status !== 429;
}

function isIncompleteUpload(err: unknown): boolean {
  // The typed HTTP error carries the RFC 7807 `code`; an incomplete upload at
  // /complete is a 409 with code `incomplete-upload`.
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === 'incomplete-upload'
  );
}
