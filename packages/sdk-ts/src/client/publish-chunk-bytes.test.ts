// Behaviour test for the `chunkBytes` option on the sealed/merkle publish
// helpers: a blob above the single-shot threshold must route through the
// resumable session flow with the caller's requested chunk size in the
// session-create body (the server's echo stays authoritative; a dedup 200 on
// create keeps the test short).

import { describe, expect, it, vi } from 'vitest';

import { x25519PublicKey } from '@cardanowall/crypto-core/kem';

import { Label309Client } from './label-309-client';
import { DEFAULT_RESUMABLE_THRESHOLD_BYTES } from './resumable-upload';

const QUOTE_ID = '01956b41-7c00-7000-8000-000000000001';
const REQUESTED_CHUNK_BYTES = 5_242_880; // 5 MiB, well under the server cap

const PUBLISH_BODY = {
  id: 'poe_06bqrjg0csvqfanaqexvqexvqc',
  tx_hash: null,
  status: 'submitting' as const,
  items_count: 1,
  signed: false,
  sealed: true,
  items: [],
  conformance_profile: 'sealed' as const,
  balance_after_usd_micros: '4500000',
};

function jsonResponse(body: unknown, status = 202): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('publishSealed — chunkBytes plumbs into the resumable session create', () => {
  it(
    'sends the requested chunk_bytes when the ciphertext exceeds the threshold',
    { timeout: 60_000 },
    async () => {
      let sessionCreateBody: { chunk_bytes: number; total_bytes: number } | undefined;
      const arUri = `ar://${'C'.repeat(43)}`;

      const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
        const path = new URL(typeof url === 'string' ? url : url.toString()).pathname;
        if (path.endsWith('/poe/uploads/sessions')) {
          sessionCreateBody = JSON.parse(init!.body as string) as {
            chunk_bytes: number;
            total_bytes: number;
          };
          // Create-time dedup short-circuit: the URI resolves with no chunk
          // PUTs, so the test exercises only the create negotiation.
          return jsonResponse(
            {
              deduplicated: true,
              uri: arUri,
              sha256: '00'.repeat(32),
              bytes: sessionCreateBody.total_bytes,
              charged_usd_micros: 0,
            },
            200,
          );
        }
        if (path.endsWith('/poe/publish')) {
          return jsonResponse(PUBLISH_BODY);
        }
        throw new Error(`unexpected request: ${path}`);
      });

      const client = new Label309Client({
        baseUrl: 'https://cardanowall.com/api/v1',
        apiKey: 'opaque-bearer-token',
        fetch: fetchMock as unknown as typeof globalThis.fetch,
      });

      // One byte over the threshold guarantees the ciphertext (which only
      // grows under the sealed framing) takes the session path.
      const content = new Uint8Array(DEFAULT_RESUMABLE_THRESHOLD_BYTES + 1);
      const recipientPub = x25519PublicKey({ secretKey: new Uint8Array(32).fill(0x22) });

      const response = await client.poe.publishSealed({
        content,
        recipients: [recipientPub],
        quoteId: QUOTE_ID,
        kem: 'x25519',
        chunkBytes: REQUESTED_CHUNK_BYTES,
      });

      expect(response.id).toBe(PUBLISH_BODY.id);
      expect(sessionCreateBody).toBeDefined();
      expect(sessionCreateBody!.chunk_bytes).toBe(REQUESTED_CHUNK_BYTES);
      expect(sessionCreateBody!.total_bytes).toBeGreaterThan(DEFAULT_RESUMABLE_THRESHOLD_BYTES);
    },
  );
});
