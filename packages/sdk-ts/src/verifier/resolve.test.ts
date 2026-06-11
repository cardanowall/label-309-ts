// Cardano transaction resolution tests: the explorer chain, the per-response
// transaction-reference integrity binding, the three terminal negatives
// (TX_INTEGRITY_MISMATCH / TX_NOT_FOUND / PROVIDER_UNAVAILABLE) and their
// evidence precedence, and the depth = tip − block + 1 arithmetic.

import { describe, expect, it } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import { blake2b256 } from '@cardanowall/crypto-core/hash';

import { wrapFetchOutbound } from '../fetch/fetch-outbound';
import { KOIOS_MAINNET_URL, resolveCardanoTx } from './resolve';
import type {
  FetchOutbound,
  FetchOutboundOptions,
  FetchOutboundResult,
  HttpCallRecord,
} from './types';

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

// A minimal transaction with no auxiliary data: the integrity binding holds
// for the blake2b-256 of the body bytes exactly as encoded.
function buildBoundTx(): { txCbor: Uint8Array; txHash: string } {
  const body = new Map<number, CanonicalCborValue>([
    [0, [[new Uint8Array(32), 0]]],
    [1, []],
    [2, 170000],
  ]) as unknown as CanonicalCborValue;
  const bodyBytes = encodeCanonicalCbor(body);
  const txCbor = encodeCanonicalCbor([
    body,
    new Map<number, CanonicalCborValue>() as unknown as CanonicalCborValue,
    true,
    null,
  ] as readonly CanonicalCborValue[]);
  return { txCbor, txHash: bytesToHex(blake2b256(bodyBytes)) };
}

// A second well-formed transaction with a different fee, so its body hashes
// to a different transaction id than `buildBoundTx`'s.
function buildOtherBoundTx(): { txCbor: Uint8Array; txHash: string } {
  const body = new Map<number, CanonicalCborValue>([
    [0, [[new Uint8Array(32), 1]]],
    [1, []],
    [2, 999999],
  ]) as unknown as CanonicalCborValue;
  const bodyBytes = encodeCanonicalCbor(body);
  const txCbor = encodeCanonicalCbor([
    body,
    new Map<number, CanonicalCborValue>() as unknown as CanonicalCborValue,
    true,
    null,
  ] as readonly CanonicalCborValue[]);
  return { txCbor, txHash: bytesToHex(blake2b256(bodyBytes)) };
}

function jsonResponse(value: unknown, status = 200): FetchOutboundResult {
  return { status, bytes: new TextEncoder().encode(JSON.stringify(value)), durationMs: 1 };
}

function emptyResponse(status: number): FetchOutboundResult {
  return { status, bytes: new Uint8Array(0), durationMs: 1 };
}

type Route = (url: string, opts: FetchOutboundOptions) => FetchOutboundResult | undefined;

function mkStubFetch(routes: Route[]): FetchOutbound {
  return async (url, opts) => {
    for (const r of routes) {
      const res = r(url, opts);
      if (res !== undefined) return res;
    }
    return emptyResponse(500);
  };
}

describe('resolveCardanoTx — Koios happy path', () => {
  it('returns the bound transaction with explorer-asserted chain facts', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const stub = mkStubFetch([
      (u) =>
        u.endsWith('/tx_cbor')
          ? jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(txCbor) }])
          : undefined,
      (u) =>
        u.endsWith('/tx_info')
          ? jsonResponse([{ num_confirmations: 42, tx_timestamp: 1700000000, absolute_slot: 99 }])
          : undefined,
    ]);
    const audit: HttpCallRecord[] = [];
    const wrapped = wrapFetchOutbound(stub, audit, undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.resolved.provider).toBe('koios');
    expect(r.resolved.confirmationDepth).toBe(42);
    expect(r.resolved.blockTime).toBe(1700000000);
    expect(r.resolved.blockSlot).toBe(99);
    expect(bytesToHex(r.resolved.txCbor)).toBe(bytesToHex(txCbor));
    expect(r.resolved.components.auxiliaryData).toBeNull();
    expect(audit.length).toBe(2);
  });

  // Koios v1 `/tx_info` carries `block_height` but no `num_confirmations` on
  // current deployments; depth is computed as tip − block + 1 from `/tip`.
  it('computes depth from /tip when tx_info omits num_confirmations', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const stub = mkStubFetch([
      (u) =>
        u.endsWith('/tx_cbor')
          ? jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(txCbor) }])
          : undefined,
      (u) =>
        u.endsWith('/tx_info')
          ? jsonResponse([
              {
                tx_hash: txHash,
                block_height: 4_730_586,
                tx_timestamp: 1_779_279_325,
                absolute_slot: 123_596_125,
              },
            ])
          : undefined,
      (u) => (u.endsWith('/tip') ? jsonResponse([{ block_height: 4_730_696 }]) : undefined),
    ]);
    const audit: HttpCallRecord[] = [];
    const wrapped = wrapFetchOutbound(stub, audit, undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.resolved.confirmationDepth).toBe(4_730_696 - 4_730_586 + 1);
    expect(audit.length).toBe(3);
  });
});

describe('resolveCardanoTx — the integrity binding', () => {
  it('discards a response whose body hashes to a different transaction id', async () => {
    const { txCbor } = buildBoundTx();
    const wrongHash = 'f'.repeat(64);
    const stub = mkStubFetch([
      (u) =>
        u.endsWith('/tx_cbor')
          ? jsonResponse([{ tx_hash: wrongHash, cbor: bytesToHex(txCbor) }])
          : undefined,
      (u) =>
        u.endsWith('/tx_info')
          ? jsonResponse([{ num_confirmations: 42, tx_timestamp: 1, absolute_slot: 1 }])
          : undefined,
    ]);
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash: wrongHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe('TX_INTEGRITY_MISMATCH');
  });

  it('a later provider surviving the binding rescues the resolution', async () => {
    const { txCbor, txHash } = buildBoundTx();
    // Provider A serves well-formed transaction bytes whose body hashes to a
    // DIFFERENT transaction id (binding fails); provider B serves the real
    // bytes.
    const otherTx = buildOtherBoundTx().txCbor;
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios-A') && url.endsWith('/tx_cbor')) {
        return jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(otherTx) }]);
      }
      if (url.includes('koios-B') && url.endsWith('/tx_cbor')) {
        return jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(txCbor) }]);
      }
      if (url.endsWith('/tx_info')) {
        return jsonResponse([{ num_confirmations: 9, tx_timestamp: 1, absolute_slot: 1 }]);
      }
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: ['https://koios-A.example/api/v1', 'https://koios-B.example/api/v1'],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.resolved.providerUrl).toBe('https://koios-B.example/api/v1');
  });
});

describe('resolveCardanoTx — terminal negatives and precedence', () => {
  it('every provider unreachable → PROVIDER_UNAVAILABLE', async () => {
    const stub = mkStubFetch([(u) => (u.endsWith('/tx_cbor') ? emptyResponse(503) : undefined)]);
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash: '0'.repeat(64),
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe('PROVIDER_UNAVAILABLE');
  });

  it('a definitive empty answer with no other provider → TX_NOT_FOUND', async () => {
    const stub = mkStubFetch([(u) => (u.endsWith('/tx_cbor') ? jsonResponse([]) : undefined)]);
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash: '0'.repeat(64),
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe('TX_NOT_FOUND');
  });

  it("a single provider's negative is not authoritative: the remaining chain is consulted", async () => {
    const { txCbor, txHash } = buildBoundTx();
    let blockfrostHits = 0;
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios') && url.endsWith('/tx_cbor')) return jsonResponse([]);
      if (url.includes('blockfrost')) {
        blockfrostHits++;
        if (url.endsWith('/cbor')) return jsonResponse({ cbor: bytesToHex(txCbor) });
        if (/\/txs\/[0-9a-f]+$/.test(url)) {
          return jsonResponse({ block_time: 100, slot: 200, block_height: 1000 });
        }
        if (url.endsWith('/blocks/latest')) return jsonResponse({ height: 1010 });
      }
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      blockfrostProjectId: 'mainnet01abc',
      fetchFn: wrapped,
    });
    expect(blockfrostHits).toBeGreaterThan(0);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.resolved.provider).toBe('blockfrost');
    // Depth is counted in BLOCKS (tip height − tx height + 1), never in
    // slots: the active-slot coefficient would inflate a slot count ~20×.
    expect(r.resolved.confirmationDepth).toBe(11);
    expect(r.resolved.blockTime).toBe(100);
    expect(r.resolved.blockSlot).toBe(200);
  });

  it('an active integrity mismatch outranks a definitive negative', async () => {
    const { txHash } = buildBoundTx();
    const otherTx = buildOtherBoundTx().txCbor;
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios-A') && url.endsWith('/tx_cbor')) {
        return jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(otherTx) }]);
      }
      if (url.includes('koios-B') && url.endsWith('/tx_cbor')) return jsonResponse([]);
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: ['https://koios-A.example/api/v1', 'https://koios-B.example/api/v1'],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe('TX_INTEGRITY_MISMATCH');
  });

  it('Blockfrost 404 with Koios unreachable → TX_NOT_FOUND', async () => {
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios')) return emptyResponse(503);
      if (url.endsWith('/cbor')) return emptyResponse(404);
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash: '0'.repeat(64),
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      blockfrostProjectId: 'mainnet01abc',
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe('TX_NOT_FOUND');
  });

  it('a tip-block transaction has depth exactly 1 (Blockfrost heights equal)', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios')) return emptyResponse(503);
      if (url.endsWith('/cbor')) return jsonResponse({ cbor: bytesToHex(txCbor) });
      if (/\/txs\/[0-9a-f]+$/.test(url)) {
        return jsonResponse({ block_time: 1747061000, slot: 187706895, block_height: 9832220 });
      }
      if (url.endsWith('/blocks/latest')) return jsonResponse({ height: 9832220 });
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      blockfrostProjectId: 'mainnet01abc',
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.resolved.confirmationDepth).toBe(1);
  });
});

describe('resolveCardanoTx — internally inconsistent provider snapshots', () => {
  // Routes for a Koios provider that serves the bound bytes and a
  // heights-based depth (no num_confirmations): tip height per provider URL.
  function koiosHeightRoutes(
    txHash: string,
    txCbor: Uint8Array,
    blockHeight: number,
    tipHeight: number,
  ): Route[] {
    return [
      (u) =>
        u.endsWith('/tx_cbor')
          ? jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(txCbor) }])
          : undefined,
      (u) =>
        u.endsWith('/tx_info')
          ? jsonResponse([
              { tx_hash: txHash, block_height: blockHeight, tx_timestamp: 1, absolute_slot: 1 },
            ])
          : undefined,
      (u) => (u.endsWith('/tip') ? jsonResponse([{ block_height: tipHeight }]) : undefined),
    ];
  }

  it('a Koios tip below the including block discards the provider — depth is never fabricated', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const wrapped = wrapFetchOutbound(
      mkStubFetch(koiosHeightRoutes(txHash, txCbor, 100, 99)),
      [],
      undefined,
    );
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    // With no further provider the run ends in the network-class end state,
    // carrying the inconsistency as that provider's failure evidence.
    expect(r.code).toBe('PROVIDER_UNAVAILABLE');
    expect(r.message).toContain('inconsistent provider snapshot');
  });

  it('the boundary holds: tip equal to the including block resolves with depth exactly 1', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const wrapped = wrapFetchOutbound(
      mkStubFetch(koiosHeightRoutes(txHash, txCbor, 100, 100)),
      [],
      undefined,
    );
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.resolved.confirmationDepth).toBe(1);
  });

  it('an inconsistent provider falls through to the next provider in the chain', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const stub: FetchOutbound = async (url) => {
      if (url.endsWith('/tx_cbor')) {
        return jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(txCbor) }]);
      }
      if (url.endsWith('/tx_info')) {
        return jsonResponse([
          { tx_hash: txHash, block_height: 100, tx_timestamp: 1, absolute_slot: 1 },
        ]);
      }
      if (url.endsWith('/tip')) {
        return jsonResponse([{ block_height: url.includes('koios-A') ? 99 : 105 }]);
      }
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: ['https://koios-A.example/api/v1', 'https://koios-B.example/api/v1'],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.resolved.providerUrl).toBe('https://koios-B.example/api/v1');
    expect(r.resolved.confirmationDepth).toBe(6);
  });

  it('a Blockfrost tip below the including block discards the provider', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios')) return emptyResponse(503);
      if (url.endsWith('/cbor')) return jsonResponse({ cbor: bytesToHex(txCbor) });
      if (/\/txs\/[0-9a-f]+$/.test(url)) {
        return jsonResponse({ block_time: 100, slot: 200, block_height: 100 });
      }
      if (url.endsWith('/blocks/latest')) return jsonResponse({ height: 99 });
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      blockfrostProjectId: 'mainnet01abc',
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe('PROVIDER_UNAVAILABLE');
    expect(r.message).toContain('inconsistent provider snapshot');
  });

  it('a served num_confirmations of 0 for an on-chain transaction is the same inconsistency', async () => {
    const { txCbor, txHash } = buildBoundTx();
    const stub = mkStubFetch([
      (u) =>
        u.endsWith('/tx_cbor')
          ? jsonResponse([{ tx_hash: txHash, cbor: bytesToHex(txCbor) }])
          : undefined,
      (u) =>
        u.endsWith('/tx_info')
          ? jsonResponse([{ num_confirmations: 0, tx_timestamp: 1, absolute_slot: 1 }])
          : undefined,
    ]);
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const r = await resolveCardanoTx({
      txHash,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      fetchFn: wrapped,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe('PROVIDER_UNAVAILABLE');
    expect(r.message).toContain('inconsistent provider snapshot');
  });
});
