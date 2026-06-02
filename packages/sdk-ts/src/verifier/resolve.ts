// Cardano gateway resolver — Koios first, then Blockfrost fallback if a
// project ID is supplied. Returns the RAW on-chain transaction CBOR (NOT
// the gateway's lossy JSON metadata projection — the verifier needs the
// producer's original bytes to detect non-canonical encodings).

import { sliceLabel309Value } from './cbor-walker';
import type { FetchOutbound, VerifyTxInput } from './types';

export interface ResolvedTx {
  readonly txCbor: Uint8Array;
  readonly numConfirmations: number;
  readonly blockTime: number;
  readonly blockSlot: number;
  readonly provider: 'koios' | 'blockfrost';
  readonly providerUrl: string;
}

export const KOIOS_MAINNET_URL = 'https://api.koios.rest/api/v1';
export const BLOCKFROST_MAINNET_HOST = 'https://cardano-mainnet.blockfrost.io/api/v0';

// Distinct error class so the verifier can short-circuit the gateway-fallback
// loop on a definitive "this tx is not on chain / has no PoE metadata"
// response: a definitive negative from one gateway is authoritative, so there
// is no point rotating to the next gateway.
export class NotACip309RecordError extends Error {
  readonly code = 'METADATA_NOT_FOUND' as const;
  constructor(message: string) {
    super(message);
    this.name = 'NotACip309RecordError';
  }
}

export async function resolveCardanoTx(args: {
  readonly input: VerifyTxInput;
  readonly fetchFn: FetchOutbound;
}): Promise<ResolvedTx> {
  const { input, fetchFn } = args;
  const koiosChain = input.cardanoGatewayChain ?? [KOIOS_MAINNET_URL];

  let lastErr: unknown;
  for (const koiosUrl of koiosChain) {
    try {
      return await resolveViaKoios(input.txHash, koiosUrl, fetchFn);
    } catch (e) {
      if (e instanceof NotACip309RecordError) throw e;
      lastErr = e;
    }
  }

  if (input.blockfrostProjectId !== undefined) {
    try {
      return await resolveViaBlockfrost(input.txHash, input.blockfrostProjectId, fetchFn);
    } catch (e) {
      if (e instanceof NotACip309RecordError) throw e;
      lastErr = e;
    }
  }

  throw new Error(`all_providers_failed: ${(lastErr as Error | undefined)?.message ?? 'unknown'}`);
}

async function resolveViaKoios(
  txHash: string,
  koiosUrl: string,
  fetchFn: FetchOutbound,
): Promise<ResolvedTx> {
  const cborRes = await fetchFn(`${koiosUrl}/tx_cbor`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ _tx_hashes: [txHash] }),
    purpose: 'cardano',
  });
  if (cborRes.status !== 200) {
    throw new Error(`koios_tx_cbor_${cborRes.status}`);
  }
  const cborJson = parseJson(cborRes.bytes);
  if (!Array.isArray(cborJson) || cborJson.length === 0) {
    throw new NotACip309RecordError('koios returned empty array for tx_cbor; tx may not exist');
  }
  const cborEntry = cborJson[0] as { tx_hash?: unknown; cbor?: unknown };
  if (typeof cborEntry.cbor !== 'string') {
    throw new Error('koios_tx_cbor_missing_cbor_field');
  }
  if (
    typeof cborEntry.tx_hash === 'string' &&
    cborEntry.tx_hash.toLowerCase() !== txHash.toLowerCase()
  ) {
    throw new Error(`koios_tx_cbor_hash_mismatch: requested ${txHash} got ${cborEntry.tx_hash}`);
  }
  const txCbor = hexToBytes(cborEntry.cbor);

  const infoRes = await fetchFn(`${koiosUrl}/tx_info`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ _tx_hashes: [txHash] }),
    purpose: 'cardano',
  });
  if (infoRes.status !== 200) {
    throw new Error(`koios_tx_info_${infoRes.status}`);
  }
  const infoJson = parseJson(infoRes.bytes);
  if (!Array.isArray(infoJson) || infoJson.length === 0) {
    throw new NotACip309RecordError('koios returned empty array for tx_info');
  }
  const infoEntry = infoJson[0] as {
    tx_hash?: unknown;
    num_confirmations?: unknown;
    block_height?: unknown;
    tx_timestamp?: unknown;
    absolute_slot?: unknown;
  };
  if (
    typeof infoEntry.tx_hash === 'string' &&
    infoEntry.tx_hash.toLowerCase() !== txHash.toLowerCase()
  ) {
    throw new Error(`koios_tx_info_hash_mismatch: requested ${txHash} got ${infoEntry.tx_hash}`);
  }

  // Koios v1 `/tx_info` no longer returns `num_confirmations` — only
  // `block_height` (verified live against `preprod.koios.rest/api/v1/tx_info`
  // and `api.koios.rest/api/v1/tx_info` on 2026-05-20: response keys do not
  // include num_confirmations). Compute manually as `tip - txBlockHeight + 1`,
  // mirroring the Blockfrost path. Fall back to a deprecated direct read of
  // `num_confirmations` for forward-compat against older Koios deployments.
  let numConfirmations: number;
  if (typeof infoEntry.num_confirmations === 'number') {
    numConfirmations = requireNonNegativeInt(infoEntry.num_confirmations, 'num_confirmations');
  } else {
    const txBlockHeight = requireNonNegativeInt(infoEntry.block_height, 'block_height');
    const tipRes = await fetchFn(`${koiosUrl}/tip`, {
      method: 'GET',
      headers: { accept: 'application/json' },
      purpose: 'cardano',
    });
    if (tipRes.status !== 200) {
      throw new Error(`koios_tip_${tipRes.status}`);
    }
    const tipJson = parseJson(tipRes.bytes);
    if (!Array.isArray(tipJson) || tipJson.length === 0) {
      throw new Error('koios_tip_empty');
    }
    const tipEntry = tipJson[0] as { block_height?: unknown };
    const tipHeight = requireNonNegativeInt(tipEntry.block_height, 'tip.block_height');
    numConfirmations = Math.max(0, tipHeight - txBlockHeight + 1);
  }

  return {
    txCbor,
    numConfirmations,
    blockTime: requireNonNegativeInt(infoEntry.tx_timestamp, 'tx_timestamp'),
    blockSlot: requireNonNegativeInt(infoEntry.absolute_slot, 'absolute_slot'),
    provider: 'koios',
    providerUrl: koiosUrl,
  };
}

async function resolveViaBlockfrost(
  txHash: string,
  projectId: string,
  fetchFn: FetchOutbound,
): Promise<ResolvedTx> {
  const base = BLOCKFROST_MAINNET_HOST;
  const headers = { project_id: projectId, accept: 'application/json' };

  const cborRes = await fetchFn(`${base}/txs/${txHash}/cbor`, {
    method: 'GET',
    headers,
    purpose: 'cardano',
  });
  if (cborRes.status !== 200) {
    throw new Error(`blockfrost_tx_cbor_${cborRes.status}`);
  }
  const cborJson = parseJson(cborRes.bytes) as { cbor?: unknown };
  if (typeof cborJson.cbor !== 'string') {
    throw new Error('blockfrost_tx_cbor_missing_cbor_field');
  }
  const txCbor = hexToBytes(cborJson.cbor);

  const txRes = await fetchFn(`${base}/txs/${txHash}`, {
    method: 'GET',
    headers,
    purpose: 'cardano',
  });
  if (txRes.status !== 200) {
    throw new Error(`blockfrost_tx_${txRes.status}`);
  }
  const txJson = parseJson(txRes.bytes) as {
    block_time?: unknown;
    slot?: unknown;
    block_height?: unknown;
  };
  const blockTime = requireNonNegativeInt(txJson.block_time, 'block_time');
  const txSlot = requireNonNegativeInt(txJson.slot, 'slot');
  // Confirmations are counted in BLOCKS, not slots. Cardano's active-slot
  // coefficient f=0.05 means only ~1 slot in 20 produces a block, so a
  // slot-difference count would inflate confirmations by ~20×. Blockfrost
  // returns `block_height` on `tx_content` and `height` on `/blocks/latest` —
  // both are the block-number field — so confirmations are
  // `tipHeight - blockHeight + 1`.
  const txBlockHeight = requireNonNegativeInt(txJson.block_height, 'block_height');

  const tipRes = await fetchFn(`${base}/blocks/latest`, {
    method: 'GET',
    headers,
    purpose: 'cardano',
  });
  if (tipRes.status !== 200) {
    throw new Error(`blockfrost_blocks_latest_${tipRes.status}`);
  }
  const tipJson = parseJson(tipRes.bytes) as { slot?: unknown; height?: unknown };
  const tipHeight = requireNonNegativeInt(tipJson.height, 'tip_height');
  const numConfirmations = Math.max(0, tipHeight - txBlockHeight + 1);

  return {
    txCbor,
    numConfirmations,
    blockTime,
    blockSlot: txSlot,
    provider: 'blockfrost',
    providerUrl: base,
  };
}

// Byte-faithful label-309 extraction (delegates to the position-aware
// `cbor-walker`, which never decode-then-re-encodes).
export function extractLabel309Metadata(txCbor: Uint8Array): Uint8Array | null {
  return sliceLabel309Value(txCbor);
}

function parseJson(bytes: Uint8Array): unknown {
  return JSON.parse(new TextDecoder().decode(bytes));
}

function requireNonNegativeInt(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new Error(`gateway_field_invalid: ${field} (got ${typeof value}=${String(value)})`);
  }
  return value;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`hex string has odd length (${clean.length})`);
  }
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('hex string contains non-hex characters');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
