// Stubbed FetchOutbound that replays captured gateway responses.
// Routes URL → captured-response from the corpus record. Throws on miss so the
// test fails with an informative diagnostic.
//
// Two confirmation paths are supported:
//   * Koios   — `/tx_cbor` + `/tx_info` (block_height) + `/tip` (block_height).
//   * Blockfrost — `/txs/{hash}/cbor` + `/txs/{hash}` + `/blocks/latest`.
// The verifier derives confirmations as `max(0, tipHeight - txHeight + 1)`
// (blocks + 1) on both paths.

import type {
  FetchOutbound,
  FetchOutboundOptions,
  FetchOutboundResult,
} from '@cardanowall/sdk-ts/fetch';

import type { MainnetCorpusRecord } from './_corpus-schema';

function jsonResponse(value: unknown): FetchOutboundResult {
  return { status: 200, bytes: new TextEncoder().encode(JSON.stringify(value)), durationMs: 1 };
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesResponse(bytes: Uint8Array): FetchOutboundResult {
  return { status: 200, bytes, durationMs: 1 };
}

export function stubFetchFromCorpusRecord(record: MainnetCorpusRecord): FetchOutbound {
  const captures = record.captured_gateway_responses;
  const arweave = captures.arweave_envelope_responses ?? {};

  return async (url: string, _opts: FetchOutboundOptions): Promise<FetchOutboundResult> => {
    // Koios confirmation path.
    if (url.endsWith('/tx_cbor')) {
      return jsonResponse(captures.koios_tx_cbor);
    }
    if (url.endsWith('/tx_info')) {
      return jsonResponse(captures.koios_tx_info);
    }
    if (url.endsWith('/tip')) {
      return jsonResponse(captures.koios_tip);
    }
    // Blockfrost confirmation path.
    if (url.endsWith('/blocks/latest')) {
      return jsonResponse(captures.blockfrost_blocks_latest);
    }
    if (url.endsWith('/cbor') && url.includes('/txs/')) {
      return jsonResponse(captures.blockfrost_tx_cbor);
    }
    if (url.includes('/txs/')) {
      return jsonResponse(captures.blockfrost_tx);
    }
    // Sealed-item ciphertext (Arweave).
    for (const [arTxId, hex] of Object.entries(arweave)) {
      if (url === `https://arweave.net/${arTxId}`) {
        return bytesResponse(hexToBytes(hex));
      }
    }
    throw new Error(`stubFetch: no captured response for ${_opts.method} ${url}`);
  };
}
