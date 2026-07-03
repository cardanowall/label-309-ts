// Behaviour tests for poe.wait() — the SSE status-stream follower. The fetch
// is mocked with streaming Responses (ReadableStream bodies fed SSE frames),
// so the assertions cover the real protocol surface: target resolution,
// terminal-failure rejection, raw-status normalization, reconnect resume via
// `last-event-id`, keepalive/oversized-line handling, deadline expiry, and
// abort.

import { describe, expect, it, vi } from 'vitest';

import { Label309Client } from './label-309-client';
import { NotFoundError } from './not-found-error';
import { PoeFailedError } from './poe-failed-error';
import type { PoeWaitInternalOptions } from './poe-events';
import { PoeWaitTimeoutError } from './poe-wait-timeout-error';
import type { PoeStatusSnapshot, PoeWaitOptions } from './types';

const POE_ID = 'poe_06bqrjg0csvqfanaqexvqexvqc';

function makeClient(fetchMock: ReturnType<typeof vi.fn>): Label309Client {
  return new Label309Client({
    baseUrl: 'https://cardanowall.com/api/v1',
    apiKey: 'opaque-bearer-token',
    fetch: fetchMock as unknown as typeof globalThis.fetch,
  });
}

/** Instant-backoff options so reconnect tests never really sleep. */
function waitOptions(options: PoeWaitOptions): PoeWaitOptions {
  const internal: PoeWaitInternalOptions = {
    ...options,
    sleep: async () => undefined,
    jitter: () => 1,
  };
  return internal;
}

function snapshotBody(
  status: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: POE_ID,
    status,
    tx_hash: null,
    block_height: null,
    block_time: null,
    num_confirmations: 0,
    request_id: 'req-0001',
    ...extra,
  };
}

function sseFrame(event: string, data: unknown, id?: number): string {
  const lines: string[] = [];
  if (id !== undefined) lines.push(`id: ${id}`);
  lines.push(`event: ${event}`);
  lines.push(`data: ${JSON.stringify(data)}`);
  return `${lines.join('\n')}\n\n`;
}

/** A closed event-stream Response replaying `frames` in order. */
function sseResponse(frames: readonly string[], status = 200): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const frame of frames) controller.enqueue(encoder.encode(frame));
      controller.close();
    },
  });
  return new Response(stream, {
    status,
    headers: { 'content-type': 'text/event-stream' },
  });
}

/** An event-stream Response that stays open after replaying `frames`. */
function openSseResponse(frames: readonly string[]): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const frame of frames) controller.enqueue(encoder.encode(frame));
      // Deliberately never closed: the wait must resolve/reject without a
      // server-side close.
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
  });
}

describe('PoeNamespace.wait — happy paths', () => {
  it('follows submitting → confirming → confirmed and resolves the confirmed snapshot', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      openSseResponse([
        sseFrame('state', snapshotBody('submitting'), 1),
        sseFrame('poe_status_changed', snapshotBody('confirming', { tx_hash: 'a'.repeat(64) }), 2),
        sseFrame(
          'poe_status_changed',
          snapshotBody('confirmed', {
            tx_hash: 'a'.repeat(64),
            block_height: 123456,
            block_time: '2026-01-01T00:00:00Z',
            num_confirmations: 3,
          }),
          3,
        ),
      ]),
    );
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));

    expect(snapshot).toEqual<PoeStatusSnapshot>({
      id: POE_ID,
      status: 'confirmed',
      tx_hash: 'a'.repeat(64),
      block_height: 123456,
      block_time: '2026-01-01T00:00:00Z',
      num_confirmations: 3,
      request_id: 'req-0001',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`https://cardanowall.com/api/v1/poe/events/${POE_ID}`);
    const headers = new Headers(init.headers);
    expect(headers.get('accept')).toBe('text/event-stream');
    expect(headers.get('authorization')).toBe('Bearer opaque-bearer-token');
    expect(headers.get('last-event-id')).toBeNull();
  });

  it('resolves instantly when the initial state snapshot is already confirmed', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(openSseResponse([sseFrame('state', snapshotBody('confirmed'), 9)]));
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));
    expect(snapshot.status).toBe('confirmed');
  });

  it("target 'submitted' resolves on confirming without waiting for confirmation", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        openSseResponse([
          sseFrame('state', snapshotBody('submitting'), 1),
          sseFrame('poe_status_changed', snapshotBody('confirming'), 2),
        ]),
      );
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'submitted' }));
    expect(snapshot.status).toBe('confirming');
  });
});

describe('PoeNamespace.wait — terminal failure', () => {
  it("rejects with PoeFailedError when the stream reports status 'failed'", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        openSseResponse([
          sseFrame('state', snapshotBody('submitting'), 1),
          sseFrame('poe_status_changed', snapshotBody('failed'), 2),
        ]),
      );
    const client = makeClient(fetchMock);

    const rejection = client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));
    await expect(rejection).rejects.toBeInstanceOf(PoeFailedError);
    const err = (await rejection.catch((e: unknown) => e)) as PoeFailedError;
    expect(err.snapshot.status).toBe('failed');
    expect(err.snapshot.id).toBe(POE_ID);
  });

  it('normalizes cardano_submission_failed carrying raw permanent_failure to failed', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        openSseResponse([
          sseFrame('state', snapshotBody('submitting'), 1),
          sseFrame('cardano_submission_failed', snapshotBody('permanent_failure'), 2),
        ]),
      );
    const client = makeClient(fetchMock);

    const rejection = client.poe.wait(POE_ID, waitOptions({ target: 'submitted' }));
    await expect(rejection).rejects.toBeInstanceOf(PoeFailedError);
    const err = (await rejection.catch((e: unknown) => e)) as PoeFailedError;
    expect(err.snapshot.status).toBe('failed');
  });
});

describe('PoeNamespace.wait — status normalization', () => {
  it("raw 'submitted' satisfies target 'submitted' and surfaces as 'confirming'", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(openSseResponse([sseFrame('state', snapshotBody('submitted'), 4)]));
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'submitted' }));
    expect(snapshot.status).toBe('confirming');
  });
});

describe('PoeNamespace.wait — reconnect', () => {
  it('resumes with last-event-id after the stream ends without the target', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sseResponse([sseFrame('state', snapshotBody('submitting'), 7)]))
      .mockResolvedValueOnce(sseResponse([sseFrame('state', snapshotBody('confirmed'), 8)]));
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));

    expect(snapshot.status).toBe('confirmed');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, secondInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(new Headers(secondInit.headers).get('last-event-id')).toBe('7');
  });

  it('does not resume from an id whose frame never terminated (uncommitted id buffer)', async () => {
    // The stream drops between `id:` + `data:` and the blank line: the frame
    // was never dispatched, so its id must not be committed — resuming from
    // it would skip the interrupted (here: terminal) frame on replay. The
    // reconnect must carry NO last-event-id, and the cut-off `confirmed`
    // payload must not have resolved the wait.
    const truncated = `id: 42\nevent: poe_status_changed\ndata: ${JSON.stringify(
      snapshotBody('confirmed'),
    )}\n`; // no terminating blank line
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sseResponse([truncated]))
      .mockResolvedValueOnce(sseResponse([sseFrame('state', snapshotBody('confirmed'), 43)]));
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));

    expect(snapshot.status).toBe('confirmed');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, secondInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(new Headers(secondInit.headers).get('last-event-id')).toBeNull();
  });

  it('ignores ping keepalives and still resolves', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        openSseResponse([
          sseFrame('ping', {}),
          sseFrame('state', snapshotBody('submitting'), 1),
          sseFrame('ping', {}),
          sseFrame('poe_status_changed', snapshotBody('confirmed'), 2),
        ]),
      );
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));
    expect(snapshot.status).toBe('confirmed');
  });

  it('drops the connection on an oversized line and reconnects instead of buffering', async () => {
    // A single 70 KiB line (no newline) breaches the 64 KiB per-line cap.
    const oversized = 'data: ' + 'a'.repeat(70_000);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        sseResponse([sseFrame('state', snapshotBody('submitting'), 3), oversized]),
      )
      .mockResolvedValueOnce(sseResponse([sseFrame('state', snapshotBody('confirmed'), 4)]));
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));

    expect(snapshot.status).toBe('confirmed');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    // The pre-overflow frame still resumed the reconnect from its id.
    const [, secondInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(new Headers(secondInit.headers).get('last-event-id')).toBe('3');
  });
});

describe('PoeNamespace.wait — deadline and abort', () => {
  it('rejects with PoeWaitTimeoutError carrying the last snapshot', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(openSseResponse([sseFrame('state', snapshotBody('submitting'), 1)]));
    const client = makeClient(fetchMock);

    const rejection = client.poe.wait(POE_ID, waitOptions({ target: 'confirmed', timeoutMs: 50 }));
    await expect(rejection).rejects.toBeInstanceOf(PoeWaitTimeoutError);
    const err = (await rejection.catch((e: unknown) => e)) as PoeWaitTimeoutError;
    expect(err.lastSnapshot?.status).toBe('submitting');
  });

  it('rejects promptly when the abort signal fires mid-wait', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(openSseResponse([sseFrame('state', snapshotBody('submitting'), 1)]));
    const client = makeClient(fetchMock);
    const controller = new AbortController();

    const rejection = client.poe.wait(
      POE_ID,
      waitOptions({ target: 'confirmed', signal: controller.signal }),
    );
    setTimeout(() => controller.abort(), 10);

    await expect(rejection).rejects.toMatchObject({ name: 'AbortError' });
  });
});

describe('PoeNamespace.wait — connect-time HTTP handling', () => {
  it('throws the typed error immediately on a definitive 404', async () => {
    const problem = {
      type: 'about:blank',
      title: 'not-found',
      status: 404,
      detail: 'no such record',
      code: 'not-found',
      trace_id: '01977c00-0000-7000-8000-000000000000',
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(problem), {
        status: 404,
        headers: { 'content-type': 'application/problem+json' },
      }),
    );
    const client = makeClient(fetchMock);

    await expect(
      client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' })),
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries after a 429 concurrent-stream cap and then resolves', async () => {
    const problem = {
      type: 'about:blank',
      title: 'rate-limited',
      status: 429,
      detail: 'stream cap',
      code: 'rate-limited',
      trace_id: '01977c00-0000-7000-8000-000000000001',
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(problem), {
          status: 429,
          headers: { 'content-type': 'application/problem+json', 'retry-after': '1' },
        }),
      )
      .mockResolvedValueOnce(sseResponse([sseFrame('state', snapshotBody('confirmed'), 1)]));
    const client = makeClient(fetchMock);

    const snapshot = await client.poe.wait(POE_ID, waitOptions({ target: 'confirmed' }));
    expect(snapshot.status).toBe('confirmed');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
