// Layer 1 NXDOMAIN scaffold: deny-list short-circuit must reject before
// the inner fetch is dispatched.

import { describe, expect, it, vi } from 'vitest';

import {
  DenyHostError,
  wrapFetchOutbound,
  type FetchOutbound,
  type HttpCallRecord,
} from '@cardanowall/sdk-ts/fetch';

const CONFORMANCE_DENY = ['operator.example', '*.operator.example', 'localhost', '127.0.0.1'];

describe('Layer 1 NXDOMAIN scaffold — deny-host short-circuit', () => {
  it('short-circuits with DenyHostError BEFORE inner fetch dispatch', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>();
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, {
      denyHosts: CONFORMANCE_DENY,
    });
    await expect(
      wrapped('https://operator.example/anything', { method: 'GET', purpose: 'https' }),
    ).rejects.toBeInstanceOf(DenyHostError);
    expect(inner).not.toHaveBeenCalled();
    expect(audit).toHaveLength(1);
    expect(audit[0]!.status).toBeNull();
  });

  it('short-circuits wildcard subdomain BEFORE inner fetch dispatch', async () => {
    const audit: HttpCallRecord[] = [];
    const inner = vi.fn<FetchOutbound>();
    const wrapped = wrapFetchOutbound(inner as FetchOutbound, audit, {
      denyHosts: CONFORMANCE_DENY,
    });
    await expect(
      wrapped('https://viewer.operator.example/x', { method: 'GET', purpose: 'https' }),
    ).rejects.toBeInstanceOf(DenyHostError);
    expect(inner).not.toHaveBeenCalled();
  });
});
