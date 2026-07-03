// Deadline expiry surfaced by `poe.wait()` — the requested lifecycle target
// was not reached within `timeoutMs`. The last snapshot seen before the
// deadline rides on the error (or `null` when no event arrived at all), so a
// caller can render the record's in-flight state and decide whether to keep
// waiting with a fresh call.

import type { PoeStatusSnapshot } from './types';

export class PoeWaitTimeoutError extends Error {
  /** The last snapshot observed before the deadline; `null` if none arrived. */
  public readonly lastSnapshot: PoeStatusSnapshot | null;

  constructor(args: { poeId: string; timeoutMs: number; lastSnapshot: PoeStatusSnapshot | null }) {
    super(`timed out after ${args.timeoutMs}ms waiting on PoE record ${args.poeId}`);
    this.name = 'PoeWaitTimeoutError';
    this.lastSnapshot = args.lastSnapshot;
  }
}
