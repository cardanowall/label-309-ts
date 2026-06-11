// Cardano conformance replay: the transaction-reference integrity binding and
// the confirmation-depth definition, driven by the shared conformance
// fixtures. The binding vectors carry synthetic minimal transaction bodies;
// the pinned facts are the blake2b-256 inputs/outputs and the disposition.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { blake2b256 } from '@cardanowall/crypto-core/hash';
import {
  encodePoeRecord,
  PoeRecordSchema,
  reassembleLabel309Value,
} from '@cardanowall/poe-standard';
import { describe, expect, it } from 'vitest';

import { unwrapAuxiliaryData } from './cbor-walker';
import { bindTransactionBytes } from './tx-binding';
import { verifyResolved } from './verify';

const here = path.dirname(fileURLToPath(import.meta.url));
const cardanoDir = path.resolve(here, '../../tests/fixtures/cardano');

function loadFixture<T>(filename: string): T {
  return JSON.parse(fs.readFileSync(path.join(cardanoDir, filename), 'utf8')) as T;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// tx-binding.json
// ---------------------------------------------------------------------------

interface TxBindingCorpus {
  vectors: Array<{
    name: string;
    requested_tx_hash_hex: string;
    transaction_body_cbor_hex: string;
    auxiliary_data_cbor_hex: string;
    expected: {
      ok: boolean;
      computed_tx_hash_hex?: string;
      computed_auxiliary_data_hash_hex?: string;
      record_body_hex?: string;
      error_code?: string;
    };
  }>;
}

describe('transaction-reference integrity binding — conformance vectors', () => {
  const corpus = loadFixture<TxBindingCorpus>('tx-binding.json');
  for (const v of corpus.vectors) {
    it(v.name, () => {
      const txBody = hexToBytes(v.transaction_body_cbor_hex);
      const auxiliaryData = hexToBytes(v.auxiliary_data_cbor_hex);
      const binding = bindTransactionBytes({
        requestedTxHashHex: v.requested_tx_hash_hex,
        txBody,
        auxiliaryData,
      });

      if (v.expected.error_code === 'TX_INTEGRITY_MISMATCH') {
        expect(binding.ok).toBe(false);
        return;
      }

      // Either the positive vector or the bound-tx-without-label-309 case:
      // both bindings hold.
      expect(binding.ok).toBe(true);
      if (v.expected.computed_tx_hash_hex !== undefined) {
        expect(bytesToHex(blake2b256(txBody))).toBe(v.expected.computed_tx_hash_hex);
      }
      if (v.expected.computed_auxiliary_data_hash_hex !== undefined) {
        expect(bytesToHex(blake2b256(auxiliaryData))).toBe(
          v.expected.computed_auxiliary_data_hash_hex,
        );
      }

      const unwrapped = unwrapAuxiliaryData(auxiliaryData);
      if (v.expected.error_code === 'METADATA_NOT_FOUND') {
        expect(unwrapped.label309).toBeNull();
        return;
      }
      expect(unwrapped.label309).not.toBeNull();
      const reassembled = reassembleLabel309Value(unwrapped.label309!);
      expect(reassembled.ok).toBe(true);
      if (!reassembled.ok) return;
      expect(bytesToHex(reassembled.body)).toBe(v.expected.record_body_hex);
    });
  }
});

// ---------------------------------------------------------------------------
// confirmation-depth.json
// ---------------------------------------------------------------------------

interface ConfirmationDepthCorpus {
  vectors: Array<{
    name: string;
    tip_height: number;
    block_height: number;
    threshold: number;
    expected_depth: number;
    expected: { status: 'pending' | 'confirmed'; code?: string };
  }>;
}

describe('confirmation depth — conformance vectors', () => {
  const corpus = loadFixture<ConfirmationDepthCorpus>('confirmation-depth.json');
  const record = PoeRecordSchema.parse({
    v: 1,
    items: [{ hashes: { 'sha2-256': new Uint8Array(32).fill(7) } }],
  });
  const recordBody = encodePoeRecord(record);

  for (const v of corpus.vectors) {
    it(v.name, async () => {
      // depth = tip − block + 1; a transaction in the tip block has depth 1.
      const depth = v.tip_height - v.block_height + 1;
      expect(depth).toBe(v.expected_depth);

      // Replay the threshold comparison through the real pipeline.
      const report = await verifyResolved({
        txHash: '0'.repeat(64),
        metadataCbor: recordBody,
        confirmationDepth: depth,
        blockTime: 1700000000,
        confirmationDepthThreshold: v.threshold,
        fetchContent: false,
      });
      if (v.expected.status === 'pending') {
        expect(report.verdict).toBe('pending');
        expect(report.exitCode).toBe(3);
        expect(report.issues.some((i) => i.code === (v.expected.code ?? ''))).toBe(true);
      } else {
        expect(report.verdict).toBe('valid');
        expect(report.issues.some((i) => i.code === 'INSUFFICIENT_CONFIRMATIONS')).toBe(false);
      }
    });
  }
});
