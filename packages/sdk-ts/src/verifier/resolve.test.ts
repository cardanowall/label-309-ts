import { describe, expect, it } from 'vitest';

import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type CanonicalCborValue,
} from '@cardanowall/crypto-core/cbor';

import { wrapFetchOutbound } from './fetch';
import {
  extractLabel309Metadata,
  KOIOS_MAINNET_URL,
  NotALabel309RecordError,
  resolveCardanoTx,
} from './resolve';
import type {
  FetchOutbound,
  FetchOutboundOptions,
  FetchOutboundResult,
  HttpCallRecord,
  VerifyTxInput,
} from './types';

const TX_HASH = '0'.repeat(64);

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(value: unknown, status = 200): FetchOutboundResult {
  return {
    status,
    bytes: new TextEncoder().encode(JSON.stringify(value)),
    durationMs: 1,
  };
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
  it('returns ResolvedTx with parsed fields', async () => {
    const cborHex = '8404';
    const stub = mkStubFetch([
      (u) =>
        u.endsWith('/tx_cbor') ? jsonResponse([{ tx_hash: TX_HASH, cbor: cborHex }]) : undefined,
      (u) =>
        u.endsWith('/tx_info')
          ? jsonResponse([{ num_confirmations: 42, tx_timestamp: 1700000000, absolute_slot: 99 }])
          : undefined,
    ]);
    const audit: HttpCallRecord[] = [];
    const wrapped = wrapFetchOutbound(stub, audit, undefined);
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
    };
    const r = await resolveCardanoTx({ input, fetchFn: wrapped });
    expect(r.provider).toBe('koios');
    expect(r.numConfirmations).toBe(42);
    expect(r.blockTime).toBe(1700000000);
    expect(r.blockSlot).toBe(99);
    expect(bytesToHex(r.txCbor)).toBe(cborHex);
    expect(audit.length).toBe(2);
  });

  // Regression — Koios v1 `/tx_info` dropped `num_confirmations` and now
  // returns only `block_height`. Verified live 2026-05-20: response keys
  // do not include num_confirmations on api.koios.rest or preprod.koios.rest.
  // SDK falls back to `/tip` + `block_height` arithmetic.
  it('computes confirmations from /tip when tx_info omits num_confirmations (Koios v1)', async () => {
    const cborHex = '8404';
    const stub = mkStubFetch([
      (u) =>
        u.endsWith('/tx_cbor') ? jsonResponse([{ tx_hash: TX_HASH, cbor: cborHex }]) : undefined,
      (u) =>
        u.endsWith('/tx_info')
          ? jsonResponse([
              {
                tx_hash: TX_HASH,
                // no num_confirmations
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
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
    };
    const r = await resolveCardanoTx({ input, fetchFn: wrapped });
    expect(r.numConfirmations).toBe(4_730_696 - 4_730_586 + 1);
    expect(audit.length).toBe(3);
  });
});

describe('resolveCardanoTx — Koios error paths', () => {
  it('throws on tx_cbor 503', async () => {
    const stub = mkStubFetch([(u) => (u.endsWith('/tx_cbor') ? emptyResponse(503) : undefined)]);
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
    };
    await expect(resolveCardanoTx({ input, fetchFn: wrapped })).rejects.toThrow(
      /all_providers_failed/,
    );
  });

  it('throws NotALabel309RecordError on empty array (and re-throws across gateway chain)', async () => {
    const stub = mkStubFetch([(u) => (u.endsWith('/tx_cbor') ? jsonResponse([]) : undefined)]);
    const wrapped = wrapFetchOutbound(stub, [], undefined);
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: ['https://koios-A.example/api/v1', 'https://koios-B.example/api/v1'],
      blockfrostProjectId: 'mainnet01abc',
    };
    await expect(resolveCardanoTx({ input, fetchFn: wrapped })).rejects.toBeInstanceOf(
      NotALabel309RecordError,
    );
  });
});

describe('resolveCardanoTx — multi-gateway fallback', () => {
  it('Koios A 503 → Koios B 200 succeeds; both audit rows recorded', async () => {
    const cborHex = '8404';
    const audit: HttpCallRecord[] = [];
    let txCborHits = 0;
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios-A')) return emptyResponse(503);
      if (url.endsWith('/tx_cbor')) {
        txCborHits++;
        return jsonResponse([{ tx_hash: TX_HASH, cbor: cborHex }]);
      }
      if (url.endsWith('/tx_info')) {
        return jsonResponse([{ num_confirmations: 17, tx_timestamp: 1, absolute_slot: 1 }]);
      }
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, audit, undefined);
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: ['https://koios-A.example/api/v1', 'https://koios-B.example/api/v1'],
    };
    const r = await resolveCardanoTx({ input, fetchFn: wrapped });
    expect(r.provider).toBe('koios');
    expect(r.providerUrl).toBe('https://koios-B.example/api/v1');
    expect(txCborHits).toBe(1);
    expect(audit.some((a) => a.url.includes('koios-A') && a.status === 503)).toBe(true);
    expect(audit.some((a) => a.url.includes('koios-B') && a.status === 200)).toBe(true);
  });

  it('all Koios fail → Blockfrost fallback succeeds', async () => {
    const audit: HttpCallRecord[] = [];
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios')) return emptyResponse(503);
      if (url.endsWith('/cbor')) return jsonResponse({ cbor: '8404' });
      if (/\/txs\/[0-9a-f]+$/.test(url))
        return jsonResponse({ block_time: 100, slot: 200, block_height: 1000 });
      if (url.endsWith('/blocks/latest')) return jsonResponse({ slot: 250, height: 1010 });
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, audit, undefined);
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: ['https://koios-A.example/api/v1'],
      blockfrostProjectId: 'mainnet01abc',
    };
    const r = await resolveCardanoTx({ input, fetchFn: wrapped });
    expect(r.provider).toBe('blockfrost');
    // Confirmations must be derived from block_height (one block per ~20 s on
    // Cardano because f=0.05), NOT slot. tipHeight - txHeight + 1 = 11.
    expect(r.numConfirmations).toBe(11);
    expect(r.blockTime).toBe(100);
    expect(r.blockSlot).toBe(200);
    expect(audit.length).toBe(4); // koios fail + 3 blockfrost calls
  });

  it('Blockfrost path computes confirmations from block_height (NOT slot)', async () => {
    // Regression: pre-fix `numConfirmations = tipSlot - txSlot` inflated by ~20x
    // because Cardano's active-slot coefficient f=0.05 means ~1 block per 20 slots.
    // Correct formula matches the worker's BlockfrostGateway.getTxConfirmations:
    // `tipHeight - txBlockHeight + 1` (mirrors Blockfrost OpenAPI line 9170
    // `block_height` + /blocks/latest line 7099 `height`).
    const audit: HttpCallRecord[] = [];
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios')) return emptyResponse(503);
      if (url.endsWith('/cbor')) return jsonResponse({ cbor: '8404' });
      if (/\/txs\/[0-9a-f]+$/.test(url))
        // 1-block-old tx: tipHeight 9832220, txHeight 9832220 → 1 confirmation.
        return jsonResponse({ block_time: 1747061000, slot: 187706895, block_height: 9832220 });
      if (url.endsWith('/blocks/latest')) return jsonResponse({ slot: 187706900, height: 9832220 });
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, audit, undefined);
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: ['https://koios-A.example/api/v1'],
      blockfrostProjectId: 'mainnet01abc',
    };
    const r = await resolveCardanoTx({ input, fetchFn: wrapped });
    expect(r.numConfirmations).toBe(1);
  });

  it('definitive Koios empty → does NOT try Blockfrost', async () => {
    const audit: HttpCallRecord[] = [];
    let blockfrostCalls = 0;
    const stub: FetchOutbound = async (url) => {
      if (url.includes('koios') && url.endsWith('/tx_cbor')) return jsonResponse([]);
      if (url.includes('blockfrost')) {
        blockfrostCalls++;
        return jsonResponse({ cbor: '8404' });
      }
      return emptyResponse(500);
    };
    const wrapped = wrapFetchOutbound(stub, audit, undefined);
    const input: VerifyTxInput = {
      txHash: TX_HASH,
      cardanoGatewayChain: [KOIOS_MAINNET_URL],
      blockfrostProjectId: 'mainnet01abc',
    };
    await expect(resolveCardanoTx({ input, fetchFn: wrapped })).rejects.toBeInstanceOf(
      NotALabel309RecordError,
    );
    expect(blockfrostCalls).toBe(0);
  });
});

describe('extractLabel309Metadata', () => {
  it('happy path round-trips through decodeCanonicalCbor', () => {
    const recordValue: CanonicalCborValue = {
      t: 'poe',
      v: 1,
    };
    const auxMap = new Map<number, Map<number, CanonicalCborValue>>();
    const metadataMap = new Map<number, CanonicalCborValue>();
    metadataMap.set(309, recordValue);
    auxMap.set(0, metadataMap);
    const txCbor = encodeCanonicalCbor([
      new Map<string, string>([['x', 'body']]),
      new Map<string, string>([['x', 'witness_set']]),
      true,
      auxMap as unknown as CanonicalCborValue,
    ] as readonly CanonicalCborValue[]);
    const extracted = extractLabel309Metadata(txCbor);
    expect(extracted).not.toBeNull();
    const decoded = decodeCanonicalCbor(extracted!);
    expect(decoded).toEqual(recordValue);
  });

  it('returns null when no auxiliary data', () => {
    const txCbor = encodeCanonicalCbor([
      new Map<string, string>([['x', 'body']]),
      new Map<string, string>([['x', 'witness_set']]),
      true,
      null,
    ] as readonly CanonicalCborValue[]);
    expect(extractLabel309Metadata(txCbor)).toBeNull();
  });

  it('returns null when label 309 not present', () => {
    const auxMap = new Map<number, Map<number, CanonicalCborValue>>();
    const metadataMap = new Map<number, CanonicalCborValue>();
    metadataMap.set(674, 'other-label');
    auxMap.set(0, metadataMap);
    const txCbor = encodeCanonicalCbor([
      new Map<string, string>([['x', 'body']]),
      new Map<string, string>([['x', 'witness_set']]),
      true,
      auxMap as unknown as CanonicalCborValue,
    ] as readonly CanonicalCborValue[]);
    expect(extractLabel309Metadata(txCbor)).toBeNull();
  });

  it('throws when tx is not a 4+-element array', () => {
    const bad = encodeCanonicalCbor([1, 2] as readonly CanonicalCborValue[]);
    expect(() => extractLabel309Metadata(bad)).toThrow();
  });
});
