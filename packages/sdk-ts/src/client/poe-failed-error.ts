// Terminal failure surfaced by `poe.wait()` — the watched record reached the
// `failed` lifecycle status (the Cardano submission failed permanently and
// will not be retried by the gateway). The last projected snapshot rides on
// the error so the caller can inspect the record's final state (tx hash, if
// one was ever assigned, request id, …) without a second call.

import type { PoeStatusSnapshot } from './types';

export class PoeFailedError extends Error {
  /** The record's final projected snapshot (status is always `failed`). */
  public readonly snapshot: PoeStatusSnapshot;

  constructor(snapshot: PoeStatusSnapshot) {
    super(`PoE record ${snapshot.id} reached terminal status 'failed'`);
    this.name = 'PoeFailedError';
    this.snapshot = snapshot;
  }
}
