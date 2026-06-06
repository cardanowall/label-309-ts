// Layer 1 + Layer 2 NXDOMAIN proof against the synthetic mainnet corpus.
//
// Layer 1 (always on): the verifier resolves every corpus record to its
// expected verdict whether the conformance deny-list is active OR bypassed,
// and never issues an outbound call to a cardanowall.com host (the
// service-independence claim — the verifier needs only public gateways).
// Layer 2 (opt-in via CARDANOWALL_NXDOMAIN_LAYER2): a direct fetch to
// cardanowall.com fails DNS, proving the deny-list is the only thing standing
// between the verifier and the vendor's own infra.

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

const CONFORMANCE_DENY = ['cardanowall.com', '*.cardanowall.com', 'localhost', '127.0.0.1'];

function isCardanoWallHost(url: string): boolean {
  const h = new URL(url).hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  return h === 'cardanowall.com' || h.endsWith('.cardanowall.com');
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
  const decryption = (record.recipient_secret_keys ?? []).map((r) => ({
    itemIndex: r.item_index,
    recipientSecretKey: hexToBytes(r.secret_key),
  }));
  return verifyTx({
    txHash: record.tx_hash,
    cardanoGatewayChain: useBlockfrost ? [] : ['https://api.koios.rest/api/v1'],
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
      expect(result.http_calls.every((c) => !isCardanoWallHost(c.url))).toBe(true);
    });

    it('verifies with denyHosts: [] (Layer 1 bypassed)', async () => {
      const result = await verifyCorpusRecord(record, []);
      expect(result.verdict).toBe(record.expected_verdict);
      expect(result.http_calls.every((c) => !isCardanoWallHost(c.url))).toBe(true);
    });

    it.skipIf(!process.env['CARDANOWALL_NXDOMAIN_LAYER2'])(
      'rejects direct fetch to cardanowall.com via DNS NXDOMAIN (Layer 2)',
      async () => {
        await expect(
          defaultFetchOutbound('https://cardanowall.com/probe', {
            method: 'GET',
            purpose: 'https',
          }),
        ).rejects.toThrow(/ENOTFOUND|getaddrinfo|nodename|fetch failed/i);
      },
    );
  },
);
