// The baked-in Arweave gateway rotation.
//
// This list is the verifier's only network-coupling default: when a caller does
// not supply its own `arweaveGatewayChain`, these gateways are tried in order.
// Pinning the exact membership AND order here is deliberate — the corpus
// report-parity tests pin their own single-gateway chain precisely so they do
// NOT depend on this default, and this is the one test that owns the default's
// shape. Changing the production rotation must be a conscious edit visible in
// this assertion, never an accidental churn of the golden fixtures.

import { describe, expect, it } from 'vitest';

import { ARWEAVE_GATEWAY_DEFAULTS } from './content';

describe('ARWEAVE_GATEWAY_DEFAULTS', () => {
  it('is turbo-gateway.com, then arweave.net, then permagate.io, in that order', () => {
    expect(ARWEAVE_GATEWAY_DEFAULTS).toEqual([
      'https://turbo-gateway.com',
      'https://arweave.net',
      'https://permagate.io',
    ]);
  });
});
