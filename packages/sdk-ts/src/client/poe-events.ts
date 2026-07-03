// Server-Sent-Events driver behind `poe.wait()` — follows a record's live
// status stream (`GET /poe/events/{poe_id}`) until a lifecycle target is
// reached.
//
// The stream is read over the client's injected `fetch` + `ReadableStream`
// (never `EventSource`, which cannot send the `Authorization` header). The
// gateway sends an initial `state` event carrying the record's full projected
// snapshot, then a live event per change (`poe_status_changed`,
// `cardano_submission_failed`) carrying the same snapshot shape, plus a
// keepalive `ping` every ~30s. Every frame's SSE `id` is the record's durable
// event sequence; a reconnect sends it back as `last-event-id` so the gateway
// replays exactly the missed events.
//
// The parser owns the bytes and mirrors the gateway's own safety limits: a
// single line over 64 KiB or an accumulated event over 256 KiB is a protocol
// error that drops the connection (and reconnects) rather than buffering
// without bound.

import { parseRetryAfter, throwIfNotOk } from './http-helpers';
import { PoeFailedError } from './poe-failed-error';
import { PoeWaitTimeoutError } from './poe-wait-timeout-error';
import type { FetchImpl, PoeStatusSnapshot, PoeWaitOptions } from './types';

interface ResolvedConfig {
  readonly apiKey: string | undefined;
  readonly baseUrl: string;
  readonly fetch: FetchImpl;
}

/** Mirror of the gateway's per-line SSE parser cap. */
const MAX_SSE_LINE_BYTES = 65_536;
/** Mirror of the gateway's per-event SSE parser cap. */
const MAX_SSE_EVENT_BYTES = 262_144;

/**
 * Reconnect backoff ladder. The last delay repeats once the ladder is
 * exhausted; the ladder resets after any connection that delivered at least
 * one event frame.
 */
const BACKOFF_DELAYS_MS = [1_000, 2_000, 5_000, 15_000, 30_000] as const;

/**
 * Test-only extension of the public wait options: injectable timers so the
 * reconnect/backoff paths run instantly under test. Deliberately NOT part of
 * the exported client surface.
 */
export interface PoeWaitInternalOptions extends PoeWaitOptions {
  /** Replaces the real backoff sleep (still observes the abort signal). */
  readonly sleep?: (ms: number, signal: AbortSignal | undefined) => Promise<void>;
  /** Replaces the jitter source; must return a factor in `[0.8, 1.2]`. */
  readonly jitter?: () => number;
}

/**
 * Collapse the raw engine statuses a snapshot may carry into the wire
 * lifecycle: `submitted` is the engine's spelling of an already-submitted tx
 * (still confirming), `permanent_failure` is the engine's spelling of the
 * terminal failure. Unknown values pass through untouched so a status a newer
 * gateway introduces still surfaces verbatim.
 */
function normalizePoeStatus(status: string): string {
  if (status === 'submitted') return 'confirming';
  if (status === 'permanent_failure') return 'failed';
  return status;
}

/**
 * Parse one event's `data` JSON into a snapshot, tolerantly: absent optional
 * fields collapse to `null`/`0`; a payload without a string `status` yields
 * `null` (the caller decides whether the event name alone implies failure).
 * The returned snapshot carries the NORMALIZED status.
 */
function parseSnapshot(data: string): PoeStatusSnapshot | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const o = parsed as Record<string, unknown>;
  const status = typeof o['status'] === 'string' ? o['status'] : undefined;
  if (status === undefined) return null;
  return {
    id: typeof o['id'] === 'string' ? o['id'] : '',
    status: normalizePoeStatus(status),
    tx_hash: typeof o['tx_hash'] === 'string' ? o['tx_hash'] : null,
    block_height: typeof o['block_height'] === 'number' ? o['block_height'] : null,
    block_time: typeof o['block_time'] === 'string' ? o['block_time'] : null,
    num_confirmations: typeof o['num_confirmations'] === 'number' ? o['num_confirmations'] : 0,
    request_id: typeof o['request_id'] === 'string' ? o['request_id'] : null,
  };
}

/** One dispatched SSE event: its name and joined data payload. */
interface SseEvent {
  readonly event: string;
  readonly data: string;
}

/**
 * Incremental SSE frame parser over raw bytes. Lines split on `\n` (an
 * optional preceding `\r` is stripped, covering `\r\n`); splitting at the
 * byte level is UTF-8-safe because `0x0A` never occurs inside a multi-byte
 * sequence. `feed()` returns the events completed by the chunk and throws
 * `SseProtocolError` when a line or event exceeds the safety caps.
 */
class SseParser {
  private pending: Uint8Array = new Uint8Array(0);
  private eventName = '';
  private dataLines: string[] = [];
  private eventBytes = 0;
  /** `id:` field buffer — committed to `lastEventId` only at frame dispatch. */
  private idBuffer: string | undefined;
  private readonly decoder = new TextDecoder();
  /** Last COMMITTED SSE id — the value a reconnect resumes from. */
  public lastEventId: string | undefined;

  feed(chunk: Uint8Array): SseEvent[] {
    const events: SseEvent[] = [];
    let buffer = this.pending.length === 0 ? chunk : concatBytes(this.pending, chunk);
    for (;;) {
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) break;
      let end = newline;
      if (end > 0 && buffer[end - 1] === 0x0d) end -= 1;
      if (end > MAX_SSE_LINE_BYTES) throw new SseProtocolError('line exceeds 64 KiB');
      const line = this.decoder.decode(buffer.subarray(0, end));
      buffer = buffer.subarray(newline + 1);
      const event = this.processLine(line, end);
      if (event !== null) events.push(event);
    }
    if (buffer.length > MAX_SSE_LINE_BYTES) throw new SseProtocolError('line exceeds 64 KiB');
    // Copy the residue out of the (possibly huge) chunk so it can be collected.
    this.pending = buffer.length === 0 ? new Uint8Array(0) : buffer.slice();
    return events;
  }

  private processLine(line: string, byteLength: number): SseEvent | null {
    if (line.length === 0) {
      // Blank line terminates the frame. Commit the id buffer FIRST: the SSE
      // spec applies an `id:` field to the last-event-id only when its frame
      // dispatches, so an id from a frame cut off mid-transfer is never
      // resumed past (the interrupted frame must be replayed, not skipped).
      // The commit happens even for data-less frames (an id-only frame, a
      // keepalive) — termination, not payload, is what commits.
      if (this.idBuffer !== undefined) {
        this.lastEventId = this.idBuffer;
        this.idBuffer = undefined;
      }
      // Dispatch the buffered event (if it accumulated any data).
      const event: SseEvent | null =
        this.dataLines.length > 0
          ? { event: this.eventName, data: this.dataLines.join('\n') }
          : null;
      this.eventName = '';
      this.dataLines = [];
      this.eventBytes = 0;
      return event;
    }
    if (line.startsWith(':')) return null; // comment / keepalive filler
    this.eventBytes += byteLength;
    if (this.eventBytes > MAX_SSE_EVENT_BYTES) throw new SseProtocolError('event exceeds 256 KiB');
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') this.eventName = value;
    else if (field === 'data') this.dataLines.push(value);
    else if (field === 'id' && !value.includes('\0')) this.idBuffer = value;
    // Any other field (`retry`, unknown extensions) is ignored.
    return null;
  }
}

/** A connection-fatal SSE framing violation (oversized line/event). */
class SseProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SseProtocolError';
  }
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException('This operation was aborted', 'AbortError');
}

/** Abortable sleep; rejects with the signal's reason when aborted. */
function defaultSleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortReason(signal));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(abortReason(signal!));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** `[0.8, 1.2)` multiplicative jitter so reconnect herds spread out. */
function defaultJitter(): number {
  return 0.8 + Math.random() * 0.4;
}

type Evaluation = 'resolve' | 'failed' | 'continue';

function evaluateSnapshot(
  snapshot: PoeStatusSnapshot,
  target: 'submitted' | 'confirmed',
): Evaluation {
  if (snapshot.status === 'failed') return 'failed';
  if (snapshot.status === 'confirmed') return 'resolve';
  if (target === 'submitted' && snapshot.status === 'confirming') return 'resolve';
  return 'continue';
}

/**
 * Follow the record's SSE status stream until `options.target` (or a terminal
 * state) is reached. Backs `PoeNamespace.wait` — see its TSDoc for the public
 * contract.
 */
export async function waitForPoe(
  config: ResolvedConfig,
  poeId: string,
  options: PoeWaitInternalOptions,
): Promise<PoeStatusSnapshot> {
  const callerSignal = options.signal;
  if (callerSignal?.aborted) throw abortReason(callerSignal);

  // One internal controller fans the caller's abort AND the deadline into the
  // in-flight fetch/read/sleep, so a settled wait never leaves a live stream.
  const controller = new AbortController();
  const onCallerAbort = (): void => controller.abort(abortReason(callerSignal!));
  callerSignal?.addEventListener('abort', onCallerAbort, { once: true });

  const state: { lastSnapshot: PoeStatusSnapshot | null } = { lastSnapshot: null };

  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
  const contenders: Promise<PoeStatusSnapshot>[] = [
    streamUntilTarget(config, poeId, options, controller.signal, state),
    // The abort contender settles the race even when the in-flight read does
    // not observe the signal (a fetch whose body stream is signal-agnostic
    // would otherwise leave the wait hanging on a pending read()).
    new Promise<never>((_, reject) => {
      controller.signal.addEventListener('abort', () => reject(abortReason(controller.signal)), {
        once: true,
      });
    }),
  ];
  if (options.timeoutMs !== undefined) {
    const timeoutMs = options.timeoutMs;
    contenders.push(
      new Promise<never>((_, reject) => {
        timeoutTimer = setTimeout(() => {
          const err = new PoeWaitTimeoutError({
            poeId,
            timeoutMs,
            lastSnapshot: state.lastSnapshot,
          });
          // Reject BEFORE aborting so the deadline (not the abort echo of it)
          // wins the race; the loop's abort rejection is swallowed below.
          reject(err);
          controller.abort(err);
        }, timeoutMs);
      }),
    );
  }

  try {
    return await Promise.race(contenders);
  } finally {
    if (timeoutTimer !== undefined) clearTimeout(timeoutTimer);
    callerSignal?.removeEventListener('abort', onCallerAbort);
    controller.abort();
    // The losing contenders reject on abort; detach them from unhandled-
    // rejection tracking.
    for (const contender of contenders) void contender.catch(() => undefined);
  }
}

/** The reconnect-forever stream loop; resolution/failure settles the race. */
async function streamUntilTarget(
  config: ResolvedConfig,
  poeId: string,
  options: PoeWaitInternalOptions,
  signal: AbortSignal,
  state: { lastSnapshot: PoeStatusSnapshot | null },
): Promise<PoeStatusSnapshot> {
  const sleep = options.sleep ?? defaultSleep;
  const jitter = options.jitter ?? defaultJitter;
  const url = `${config.baseUrl}/poe/events/${encodeURIComponent(poeId)}`;
  let backoffIndex = 0;
  let lastEventId: string | undefined;

  const nextBackoffMs = (): number => {
    const base = BACKOFF_DELAYS_MS[Math.min(backoffIndex, BACKOFF_DELAYS_MS.length - 1)]!;
    backoffIndex += 1;
    return Math.round(base * jitter());
  };

  for (;;) {
    if (signal.aborted) throw abortReason(signal);

    const headers = new Headers({ accept: 'text/event-stream' });
    if (config.apiKey !== undefined) headers.set('authorization', `Bearer ${config.apiKey}`);
    // An empty committed id means "no resume point" — the header is omitted,
    // matching how EventSource treats an empty last event ID string.
    if (lastEventId !== undefined && lastEventId !== '') headers.set('last-event-id', lastEventId);

    let response: Response;
    try {
      response = await config.fetch(url, { method: 'GET', headers, signal });
    } catch {
      if (signal.aborted) throw abortReason(signal);
      // Network / egress failure before any response: transient, back off.
      await sleep(nextBackoffMs(), signal);
      continue;
    }

    if (!response.ok) {
      if (response.status === 429 || response.status >= 500) {
        // 429 is the concurrent-stream cap (honour Retry-After when longer
        // than the ladder step); 5xx is a transient server fault. Both retry.
        const retryAfterSeconds = parseRetryAfter(response.headers.get('retry-after'));
        await response.body?.cancel().catch(() => undefined);
        const backoffMs = nextBackoffMs();
        const waitMs =
          response.status === 429 && retryAfterSeconds !== undefined
            ? Math.max(retryAfterSeconds * 1000, backoffMs)
            : backoffMs;
        await sleep(waitMs, signal);
        continue;
      }
      // Any other non-OK (401/403/404/422, …) is definitive: surface the
      // typed error immediately.
      await throwIfNotOk(response);
    }

    const body = response.body;
    if (body === null) {
      await sleep(nextBackoffMs(), signal);
      continue;
    }

    const parser = new SseParser();
    const reader = body.getReader();
    let deliveredFrame = false;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break; // clean server close without the target: reconnect
        if (value === undefined) continue;
        for (const event of parser.feed(value)) {
          deliveredFrame = true;
          const snapshot = snapshotFromEvent(event, poeId);
          if (snapshot === null) continue; // ping / unknown event
          state.lastSnapshot = snapshot;
          const verdict = evaluateSnapshot(snapshot, options.target);
          if (verdict === 'failed') throw new PoeFailedError(snapshot);
          if (verdict === 'resolve') return snapshot;
        }
        lastEventId = parser.lastEventId ?? lastEventId;
      }
      lastEventId = parser.lastEventId ?? lastEventId;
    } catch (err) {
      if (err instanceof PoeFailedError) throw err;
      if (signal.aborted) throw abortReason(signal);
      // A mid-stream read failure (dropped connection) and an SSE framing
      // violation (SseProtocolError) both fall through to the reconnect
      // backoff below, resuming from the last frame id seen.
      lastEventId = parser.lastEventId ?? lastEventId;
    } finally {
      reader.releaseLock();
      await body.cancel().catch(() => undefined);
    }

    if (deliveredFrame) backoffIndex = 0;
    await sleep(nextBackoffMs(), signal);
  }
}

/**
 * Map a dispatched SSE event to a snapshot, or `null` for events that carry
 * none (`ping`, unknown names). A `cardano_submission_failed` whose payload
 * cannot be parsed still yields a terminal `failed` snapshot — the event name
 * alone is the verdict.
 */
function snapshotFromEvent(event: SseEvent, poeId: string): PoeStatusSnapshot | null {
  if (
    event.event !== 'state' &&
    event.event !== 'poe_status_changed' &&
    event.event !== 'cardano_submission_failed'
  ) {
    return null;
  }
  const snapshot = parseSnapshot(event.data);
  if (snapshot !== null) return snapshot;
  if (event.event === 'cardano_submission_failed') {
    return {
      id: poeId,
      status: 'failed',
      tx_hash: null,
      block_height: null,
      block_time: null,
      num_confirmations: 0,
      request_id: null,
    };
  }
  return null;
}
