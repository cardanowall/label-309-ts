// Layer 1 + Layer 2 NXDOMAIN proof against the synthetic mainnet corpus.
//
// Layer 1 (always on): the verifier resolves every corpus record to its
// expected verdict whether the conformance deny-list is active OR bypassed,
// and never issues an outbound call to an operator.example host (the
// service-independence claim — the verifier needs only public gateways).
// Layer 2 (opt-in via CARDANOWALL_NXDOMAIN_LAYER2): a direct fetch to
// operator.example fails DNS, proving the deny-list is the only thing standing
// between the verifier and the operator's own infrastructure.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { defaultFetchOutbound } from '@cardanowall/sdk-ts/fetch';
import { verifyTx } from '@cardanowall/sdk-ts/verifier';

import { MainnetCorpusSchema, type MainnetCorpusRecord } from './_corpus-schema.js';
import { stubFetchFromCorpusRecord } from './_stub-fetch.js';

const CORPUS_PATH =
  process.env['CARDANOWALL_NXDOMAIN_CORPUS_PATH'] ??
  fileURLToPath(new URL('../fixtures/mainnet-corpus.json', import.meta.url));
const corpus = MainnetCorpusSchema.parse(JSON.parse(readFileSync(CORPUS_PATH, 'utf8')));

const CONFORMANCE_DENY = ['operator.example', '*.operator.example', 'localhost', '127.0.0.1'];

function isDeniedOperatorHost(url: string): boolean {
  const h = new URL(url).hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  return h === 'operator.example' || h.endsWith('.operator.example');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Resolve one corpus record under a chosen deny-list, mirroring the golden
// writer's gateway routing (Blockfrost provider + recipient decryption keys).
async function verifyCorpusRecord(
  record: MainnetCorpusRecord,
  denyHosts: ReadonlyArray<string>,
): Promise<Awaited<ReturnType<typeof verifyTx>>> {
  const useBlockfrost = record.provider === 'blockfrost';
  // The keyring is global to the run; per-item pairing is the verifier's job.
  const decryption = (record.recipient_secret_keys ?? []).map((r) => ({
    recipientSecretKey: hexToBytes(r.secret_key),
  }));
  return verifyTx({
    txHash: record.tx_hash,
    cardanoGatewayChain: useBlockfrost ? [] : ['https://api.koios.rest/api/v1'],
    // Pin the Arweave chain to the single gateway the corpus stub serves, so
    // resolution stays decoupled from the default gateway ROTATION (asserted
    // independently by the ARWEAVE_GATEWAY_DEFAULTS unit test) and the audit
    // trail is deterministic across SDK twins.
    arweaveGatewayChain: ['https://arweave.net'],
    ...(useBlockfrost ? { blockfrostProjectId: 'corpus' } : {}),
    ...(decryption.length > 0 ? { decryption } : {}),
    denyHosts,
    fetchOutbound: stubFetchFromCorpusRecord(record),
  });
}

// The corpus is a synthetic, byte-deterministic set of PoE records shared
// across the SDK implementations.
describe.each(corpus.records.map((r) => [r.tx_hash, r] as const))(
  'mainnet corpus — record %s',
  (_txHash: string, record: MainnetCorpusRecord) => {
    it('verifies with conformance denyHosts (Layer 1 active)', async () => {
      const result = await verifyCorpusRecord(record, CONFORMANCE_DENY);
      expect(result.verdict).toBe(record.expected_verdict);
      expect(result.auditTrail.every((c) => !isDeniedOperatorHost(c.url))).toBe(true);
    });

    it('verifies with denyHosts: [] (Layer 1 bypassed)', async () => {
      const result = await verifyCorpusRecord(record, []);
      expect(result.verdict).toBe(record.expected_verdict);
      expect(result.auditTrail.every((c) => !isDeniedOperatorHost(c.url))).toBe(true);
    });

    it.skipIf(!process.env['CARDANOWALL_NXDOMAIN_LAYER2'])(
      'rejects direct fetch to operator.example via DNS NXDOMAIN (Layer 2)',
      async () => {
        await expect(
          defaultFetchOutbound('https://operator.example/probe', {
            method: 'GET',
            purpose: 'https',
          }),
        ).rejects.toThrow(/ENOTFOUND|getaddrinfo|nodename|fetch failed/i);
      },
    );
  },
);
