// Cardano transaction resolution — an ordered explorer chain (Koios-compatible
// endpoints, then a Blockfrost fallback when a project ID is supplied), with
// the transaction-reference integrity binding applied to every response
// BEFORE anything is read out of it.
//
// The verifier fetches the RAW on-chain transaction CBOR, never an explorer's
// metadata-JSON projection: the projection is lossy (map-key ordering,
// definite-vs-indefinite lengths, bytes-vs-text discrimination), so a
// verifier that re-encoded from it could not reproduce the byte-exact signing
// input.
//
// Resolution distinguishes three terminal negatives, in evidence order:
//
//   * TX_INTEGRITY_MISMATCH — at least one provider actively served bytes
//     that fail the blake2b-256 binding to the requested reference and no
//     provider's response survived it. Provider-attributable; verdict
//     `unverifiable` (no record bytes were ever obtained).
//   * TX_NOT_FOUND — at least one provider answered definitively that it
//     knows no such transaction, and none had it. A single provider's
//     negative is not chain-authoritative, so every remaining provider is
//     consulted first. Network class; verdict `unverifiable`.
//   * PROVIDER_UNAVAILABLE — every provider was unreachable or returned no
//     usable response. Network class; verdict `unverifiable`.
//
// Chain facts (tip height, block height, block time, block slot) are
// explorer-asserted; the binding cannot establish them. Confirmation depth is
// counted in blocks: depth = tip − block + 1, so a transaction in the tip
// block has depth exactly 1.

import { isDenyHostError } from '../fetch/fetch-outbound';
import { sliceTxComponents, type TxComponents } from './cbor-walker';
import { bindTransactionBytes } from './tx-binding';
import type { FetchOutbound } from './types';

export const KOIOS_MAINNET_URL = 'https://api.koios.rest/api/v1';
export const BLOCKFROST_MAINNET_HOST = 'https://cardano-mainnet.blockfrost.io/api/v0';

export interface ResolvedTx {
  readonly txCbor: Uint8Array;
  readonly components: TxComponents;
  readonly confirmationDepth: number;
  readonly blockTime: number; // POSIX seconds UTC
  readonly blockSlot: number;
  readonly provider: 'koios' | 'blockfrost';
  readonly providerUrl: string;
}

export type ResolveFailureCode = 'TX_NOT_FOUND' | 'PROVIDER_UNAVAILABLE' | 'TX_INTEGRITY_MISMATCH';

export type ResolveOutcome =
  | { readonly ok: true; readonly resolved: ResolvedTx }
  | { readonly ok: false; readonly code: ResolveFailureCode; readonly message: string };

type ProviderAttempt =
  | { readonly kind: 'served'; readonly resolved: ResolvedTx }
  | { readonly kind: 'not_found'; readonly detail: string }
  | { readonly kind: 'integrity_mismatch'; readonly detail: string }
  | { readonly kind: 'unusable'; readonly detail: string };

export async function resolveCardanoTx(args: {
  readonly txHash: string;
  readonly cardanoGatewayChain?: ReadonlyArray<string> | undefined;
  readonly blockfrostProjectId?: string | undefined;
  readonly fetchFn: FetchOutbound;
}): Promise<ResolveOutcome> {
  const koiosChain = args.cardanoGatewayChain ?? [KOIOS_MAINNET_URL];

  let sawNotFound: string | null = null;
  let sawIntegrityMismatch: string | null = null;
  let lastUnusable: string | null = null;

  const record = (attempt: ProviderAttempt): ResolvedTx | null => {
    switch (attempt.kind) {
      case 'served':
        return attempt.resolved;
      case 'not_found':
        sawNotFound = attempt.detail;
        return null;
      case 'integrity_mismatch':
        sawIntegrityMismatch = attempt.detail;
        return null;
      case 'unusable':
        lastUnusable = attempt.detail;
        return null;
    }
  };

  for (const koiosUrl of koiosChain) {
    const resolved = record(await resolveViaKoios(args.txHash, koiosUrl, args.fetchFn));
    if (resolved !== null) return { ok: true, resolved };
  }
  if (args.blockfrostProjectId !== undefined) {
    const resolved = record(
      await resolveViaBlockfrost(args.txHash, args.blockfrostProjectId, args.fetchFn),
    );
    if (resolved !== null) return { ok: true, resolved };
  }

  // Evidence precedence: a provider that actively served wrong bytes is the
  // strongest signal, then a definitive negative answer, then plain
  // unreachability.
  if (sawIntegrityMismatch !== null) {
    return {
      ok: false,
      code: 'TX_INTEGRITY_MISMATCH',
      message: `no provider response survived the transaction-reference binding: ${sawIntegrityMismatch as string}`,
    };
  }
  if (sawNotFound !== null) {
    return {
      ok: false,
      code: 'TX_NOT_FOUND',
      message: `no consulted provider knows transaction ${args.txHash}: ${sawNotFound as string}`,
    };
  }
  return {
    ok: false,
    code: 'PROVIDER_UNAVAILABLE',
    message: lastUnusable ?? 'no provider configured',
  };
}

// Bind a fetched transaction's bytes to the requested reference. Runs the
// moment the bytes arrive — BEFORE any further chain-fact call against the
// same provider, so a provider serving wrong bytes is identified without
// spending more calls on it.
type BoundTx =
  | { readonly kind: 'bound'; readonly components: TxComponents }
  | { readonly kind: 'integrity_mismatch'; readonly detail: string }
  | { readonly kind: 'unusable'; readonly detail: string };

function bindFetchedTx(args: {
  readonly txHash: string;
  readonly txCbor: Uint8Array;
  readonly providerUrl: string;
}): BoundTx {
  let components: TxComponents;
  try {
    components = sliceTxComponents(args.txCbor);
  } catch (e) {
    return {
      kind: 'unusable',
      detail: `${args.providerUrl}: response is not parseable transaction CBOR (${e instanceof Error ? e.message : String(e)})`,
    };
  }
  const binding = bindTransactionBytes({
    requestedTxHashHex: args.txHash,
    txBody: components.txBody,
    auxiliaryData: components.auxiliaryData,
  });
  if (!binding.ok) {
    return {
      kind: 'integrity_mismatch',
      detail: `${args.providerUrl}: ${binding.message}`,
    };
  }
  return { kind: 'bound', components };
}

async function resolveViaKoios(
  txHash: string,
  koiosUrl: string,
  fetchFn: FetchOutbound,
): Promise<ProviderAttempt> {
  try {
    const cborRes = await fetchFn(`${koiosUrl}/tx_cbor`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ _tx_hashes: [txHash] }),
      purpose: 'cardano',
    });
    if (cborRes.status !== 200) {
      return { kind: 'unusable', detail: `${koiosUrl}: tx_cbor returned HTTP ${cborRes.status}` };
    }
    const cborJson = parseJson(cborRes.bytes);
    if (!Array.isArray(cborJson)) {
      return { kind: 'unusable', detail: `${koiosUrl}: tx_cbor returned a non-array body` };
    }
    if (cborJson.length === 0) {
      // An empty result set is Koios's definitive "I know no such tx".
      return { kind: 'not_found', detail: `${koiosUrl} returned an empty tx_cbor result set` };
    }
    const cborEntry = cborJson[0] as { cbor?: unknown };
    if (typeof cborEntry.cbor !== 'string') {
      return { kind: 'unusable', detail: `${koiosUrl}: tx_cbor entry carries no cbor field` };
    }
    const txCbor = hexToBytes(cborEntry.cbor);
    const bound = bindFetchedTx({ txHash, txCbor, providerUrl: koiosUrl });
    if (bound.kind !== 'bound') return bound;

    const infoRes = await fetchFn(`${koiosUrl}/tx_info`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ _tx_hashes: [txHash] }),
      purpose: 'cardano',
    });
    if (infoRes.status !== 200) {
      return { kind: 'unusable', detail: `${koiosUrl}: tx_info returned HTTP ${infoRes.status}` };
    }
    const infoJson = parseJson(infoRes.bytes);
    if (!Array.isArray(infoJson) || infoJson.length === 0) {
      return { kind: 'unusable', detail: `${koiosUrl}: tx_info returned no entry` };
    }
    const infoEntry = infoJson[0] as {
      num_confirmations?: unknown;
      block_height?: unknown;
      tx_timestamp?: unknown;
      absolute_slot?: unknown;
    };

    // Koios v1 `/tx_info` carries `block_height` but (on current deployments)
    // no `num_confirmations`; depth is computed as tip − block + 1, with a
    // direct read kept for older deployments that still serve the field.
    let confirmationDepth: number;
    if (typeof infoEntry.num_confirmations === 'number') {
      confirmationDepth = requireNonNegativeInt(infoEntry.num_confirmations, 'num_confirmations');
      // A served count of 0 for a transaction the provider itself reports as
      // on-chain is the same self-contradiction as a lagging tip (see
      // depthFromHeights): the snapshot is unusable.
      if (confirmationDepth < 1) {
        throw new Error(
          'inconsistent provider snapshot: num_confirmations is 0 for an on-chain transaction',
        );
      }
    } else {
      const txBlockHeight = requireNonNegativeInt(infoEntry.block_height, 'block_height');
      const tipRes = await fetchFn(`${koiosUrl}/tip`, {
        method: 'GET',
        headers: { accept: 'application/json' },
        purpose: 'cardano',
      });
      if (tipRes.status !== 200) {
        return { kind: 'unusable', detail: `${koiosUrl}: tip returned HTTP ${tipRes.status}` };
      }
      const tipJson = parseJson(tipRes.bytes);
      if (!Array.isArray(tipJson) || tipJson.length === 0) {
        return { kind: 'unusable', detail: `${koiosUrl}: tip returned no entry` };
      }
      const tipEntry = tipJson[0] as { block_height?: unknown };
      const tipHeight = requireNonNegativeInt(tipEntry.block_height, 'tip.block_height');
      confirmationDepth = depthFromHeights(tipHeight, txBlockHeight);
    }

    return {
      kind: 'served',
      resolved: {
        txCbor,
        components: bound.components,
        confirmationDepth,
        blockTime: requireNonNegativeInt(infoEntry.tx_timestamp, 'tx_timestamp'),
        blockSlot: requireNonNegativeInt(infoEntry.absolute_slot, 'absolute_slot'),
        provider: 'koios',
        providerUrl: koiosUrl,
      },
    };
  } catch (e) {
    // A denyHosts hit is a run-level service-independence violation, not a
    // provider-availability outcome; the pipeline reports it as such.
    if (isDenyHostError(e)) throw e;
    return {
      kind: 'unusable',
      detail: `${koiosUrl}: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

async function resolveViaBlockfrost(
  txHash: string,
  projectId: string,
  fetchFn: FetchOutbound,
): Promise<ProviderAttempt> {
  const base = BLOCKFROST_MAINNET_HOST;
  const headers = { project_id: projectId, accept: 'application/json' };
  try {
    const cborRes = await fetchFn(`${base}/txs/${txHash}/cbor`, {
      method: 'GET',
      headers,
      purpose: 'cardano',
    });
    if (cborRes.status === 404) {
      return { kind: 'not_found', detail: `${base} returned 404 for the transaction` };
    }
    if (cborRes.status !== 200) {
      return { kind: 'unusable', detail: `${base}: tx cbor returned HTTP ${cborRes.status}` };
    }
    const cborJson = parseJson(cborRes.bytes) as { cbor?: unknown };
    if (typeof cborJson.cbor !== 'string') {
      return { kind: 'unusable', detail: `${base}: tx cbor response carries no cbor field` };
    }
    const txCbor = hexToBytes(cborJson.cbor);
    const bound = bindFetchedTx({ txHash, txCbor, providerUrl: base });
    if (bound.kind !== 'bound') return bound;

    const txRes = await fetchFn(`${base}/txs/${txHash}`, {
      method: 'GET',
      headers,
      purpose: 'cardano',
    });
    if (txRes.status !== 200) {
      return { kind: 'unusable', detail: `${base}: tx info returned HTTP ${txRes.status}` };
    }
    const txJson = parseJson(txRes.bytes) as {
      block_time?: unknown;
      slot?: unknown;
      block_height?: unknown;
    };
    const blockTime = requireNonNegativeInt(txJson.block_time, 'block_time');
    const blockSlot = requireNonNegativeInt(txJson.slot, 'slot');
    // Confirmations are counted in BLOCKS, not slots: Cardano's active-slot
    // coefficient f=0.05 means only ~1 slot in 20 produces a block, so a
    // slot-difference count would inflate depth by ~20×.
    const txBlockHeight = requireNonNegativeInt(txJson.block_height, 'block_height');

    const tipRes = await fetchFn(`${base}/blocks/latest`, {
      method: 'GET',
      headers,
      purpose: 'cardano',
    });
    if (tipRes.status !== 200) {
      return { kind: 'unusable', detail: `${base}: blocks/latest returned HTTP ${tipRes.status}` };
    }
    const tipJson = parseJson(tipRes.bytes) as { height?: unknown };
    const tipHeight = requireNonNegativeInt(tipJson.height, 'tip_height');

    return {
      kind: 'served',
      resolved: {
        txCbor,
        components: bound.components,
        confirmationDepth: depthFromHeights(tipHeight, txBlockHeight),
        blockTime,
        blockSlot,
        provider: 'blockfrost',
        providerUrl: base,
      },
    };
  } catch (e) {
    if (isDenyHostError(e)) throw e;
    return { kind: 'unusable', detail: `${base}: ${e instanceof Error ? e.message : String(e)}` };
  }
}

// depth = tip − block + 1; a transaction in the tip block has depth exactly 1.
// A provider whose tip height is below the height of the block it itself
// reports for the transaction contradicts its own snapshot. An internally
// inconsistent snapshot proves only that the provider's view is unusable, so
// the provider is discarded through the per-provider failure path (the throw
// lands in the surrounding catch) and contributes no chain facts — a depth is
// never fabricated by flooring.
function depthFromHeights(tipHeight: number, blockHeight: number): number {
  const depth = tipHeight - blockHeight + 1;
  if (depth < 1) {
    throw new Error(
      `inconsistent provider snapshot: tip height ${tipHeight} is below the transaction's block height ${blockHeight}`,
    );
  }
  return depth;
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
