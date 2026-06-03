// Cross-implementation corpus parity test.
//
// Replays a fixed corpus of PoE records through the standalone verifier and
// asserts that each emitted VerifyReport reproduces its recorded golden under
// `tests/fixtures/verify-reports/` byte-for-byte. The corpus is synthetic,
// byte-deterministic, and shared verbatim across the TypeScript, Python, and
// Rust SDKs; replaying the SAME goldens in every implementation is what proves
// the three verifiers stay in exact agreement.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { verifyReportToDict, verifyTx } from '@cardanowall/sdk-ts/verifier';

import {
  MainnetCorpusSchema,
  type MainnetCorpusRecord,
} from '../nxdomain-namespace/_corpus-schema.js';
import { stubFetchFromCorpusRecord } from '../nxdomain-namespace/_stub-fetch.js';

const CORPUS_PATH =
  process.env['CARDANOWALL_NXDOMAIN_CORPUS_PATH'] ??
  fileURLToPath(new URL('../fixtures/mainnet-corpus.json', import.meta.url));
const FIXTURES_DIR = fileURLToPath(new URL('../fixtures/verify-reports/', import.meta.url));

const corpus = MainnetCorpusSchema.parse(JSON.parse(readFileSync(CORPUS_PATH, 'utf8')));

const CONFORMANCE_DENY = ['cardanowall.com', '*.cardanowall.com', 'localhost', '127.0.0.1'];

function sortedKeys(_key: string, value: unknown): unknown {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
    );
  }
  return value;
}

function canonicalJson(d: Record<string, unknown>): string {
  return JSON.stringify(d, sortedKeys, 2) + '\n';
}

function isCardanoWallHost(url: string): boolean {
  const h = new URL(url).hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  return h === 'cardanowall.com' || h.endsWith('.cardanowall.com');
}

// Replay the verifier against one corpus record exactly as the golden writer
// does: route Blockfrost-provider records through the Blockfrost resolver and
// plumb any recipient secret keys into `decryption`.
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function verifyCorpusRecord(
  record: MainnetCorpusRecord,
): Promise<Awaited<ReturnType<typeof verifyTx>>> {
  const useBlockfrost = record.provider === 'blockfrost';
  const decryption = (record.recipient_secret_keys ?? []).map((r) => ({
    itemIndex: r.item_index,
    recipientSecretKey: hexToBytes(r.secret_key),
  }));
  return verifyTx({
    txHash: record.tx_hash,
    cardanoGatewayChain: useBlockfrost ? [] : ['https://api.koios.rest/api/v1'],
    ...(useBlockfrost ? { blockfrostProjectId: 'corpus' } : {}),
    ...(decryption.length > 0 ? { decryption } : {}),
    denyHosts: CONFORMANCE_DENY,
    fetchOutbound: stubFetchFromCorpusRecord(record),
  });
}

// The corpus is synthetic and deterministic; real mainnet captures will
// replace it once production publishes records in this shape.
describe('verify-mainnet-corpus integration', () => {
  it('corpus has at least 100 records', () => {
    expect(corpus.records.length).toBeGreaterThanOrEqual(100);
  });

  // Sanity: the realistic surfaces (signed, sealed, tx-level description) MUST
  // be present in the corpus, otherwise the cross-impl parity goldens would
  // never exercise the renamed report fields.
  it('corpus exercises the realistic report surfaces', () => {
    const fixtures = corpus.records.map((r) =>
      JSON.parse(readFileSync(`${FIXTURES_DIR}${r.tx_hash}.json`, 'utf8')),
    );
    expect(fixtures.some((f) => Array.isArray(f.record_signatures))).toBe(true);
    expect(fixtures.some((f) => Array.isArray(f.item_decryptions))).toBe(true);
    expect(fixtures.some((f) => Array.isArray(f.tx_witnesses) && f.tx_witnesses.length > 0)).toBe(
      true,
    );
    expect(fixtures.some((f) => f.tx_summary?.fee_lovelace !== undefined)).toBe(true);
    expect(fixtures.every((f) => Array.isArray(f.metadata_labels))).toBe(true);
  });

  describe.each(corpus.records.map((r) => [r.tx_hash, r] as const))(
    'record %s',
    (txHash: string, record: MainnetCorpusRecord) => {
      it('VerifyReport matches expected fixture byte-for-byte', async () => {
        const result = await verifyCorpusRecord(record);
        const actual = canonicalJson(verifyReportToDict(result));
        const expected = readFileSync(`${FIXTURES_DIR}${txHash}.json`, 'utf8');
        expect(actual).toBe(expected);
        expect(result.verdict).toBe(record.expected_verdict);
        expect(result.http_calls.every((c) => !isCardanoWallHost(c.url))).toBe(true);
      });
    },
  );
});
