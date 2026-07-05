// Unit tests for the high-level publishContent() / publishPrehashed() /
// publishMerkle() helpers — assert canonical record shape, signer
// integration, Merkle root binding, the merkle flow's internal quote /
// price cap / deterministic upload key, partial-upload handling, and
// input-validation boundaries. The sealed flow is covered in sealed.test.ts.

import { describe, expect, it, vi } from 'vitest';

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { merkleSha2256Root } from '@cardanowall/crypto-core';
import { decodeLeavesList } from '@cardanowall/crypto-core/merkle';
import { getPublicKeyEd25519, signEd25519 } from '@cardanowall/crypto-core/sig';
import { validatePoeRecord } from '@cardanowall/poe-standard';

import { Label309Client } from './label-309-client';
import { MaxUsdExceededError } from './max-usd-exceeded-error';
import { PartialUploadError } from './partial-upload-error';
import { PublishError } from './publish';
import type { Signer } from './types';

function jsonResponse(body: unknown, status = 202): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function makeClient(fetchMock: ReturnType<typeof vi.fn>): Label309Client {
  return new Label309Client({
    baseUrl: 'https://cardanowall.com/api/v1',
    apiKey: 'opaque-bearer-token',
    fetch: fetchMock as unknown as typeof globalThis.fetch,
  });
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Build a deterministic in-memory Ed25519 signer.
function makeInMemorySigner(): Signer {
  const seed = new Uint8Array(32).fill(0x42);
  const signerPubkey = getPublicKeyEd25519({ seed });
  return {
    signerPubkey,
    async sign(sigStructureBytes: Uint8Array): Promise<Uint8Array> {
      return signEd25519({ seed, message: sigStructureBytes });
    },
  };
}

const QUOTE_ID = '01956b41-7c00-7000-8000-000000000001';

const PUBLISH_BODY = {
  id: 'poe_06bqrjg0csvqfanaqexvqexvqc',
  tx_hash: null,
  status: 'submitting' as const,
  items_count: 1,
  signed: true,
  sealed: false,
  items: [],
  conformance_profile: 'signed' as const,
  balance_after_usd_micros: '4500000',
};

function makeUploadsResponse(uri: string) {
  return {
    uploads: [{ idx: 0, ok: true, uri, sha256: '00'.repeat(32), bytes: 42 }],
  };
}

describe('PoeNamespace.publishContent — hash-only happy path', () => {
  it('hashes content (sha2-256 default), submits a signed single-item record', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_BODY));
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();

    const out = await client.poe.publishContent({
      content: 'hello world',
      quoteId: QUOTE_ID,
      signer,
    });

    expect(out.id).toBe(PUBLISH_BODY.id);
    expect(out.status).toBe('submitting');
    expect(out.dedup_hit).toBe(false);

    // One fetch — direct /publish, no /uploads round-trip for hash-only.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://cardanowall.com/api/v1/poe/publish');
    expect((init as { method: string }).method).toBe('POST');

    // Decode the submitted record bytes; assert the shape (and the quote id).
    const body = JSON.parse((init as { body: string }).body) as {
      record: string;
      quote_id: string;
    };
    expect(body.quote_id).toBe(QUOTE_ID);
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    const record = validated.record;
    expect(record.v).toBe(1);
    expect(record.items).toHaveLength(1);
    expect(record.sigs).toHaveLength(1);

    // The submitted item carries sha2-256(content).
    const expectedDigest = bytesToHex(nobleSha256(new TextEncoder().encode('hello world')));
    const actualDigest = bytesToHex(record.items![0]!.hashes['sha2-256']!);
    expect(actualDigest).toBe(expectedDigest);
  });

  it('publishes an UNSIGNED record when no signer is supplied', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_BODY));
    const client = makeClient(fetchMock);
    await client.poe.publishContent({ content: 'hello', quoteId: QUOTE_ID });
    const body = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body) as {
      record: string;
    };
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    expect(validated.record.sigs).toBeUndefined();
  });

  it('supports blake2b-256 hashAlg', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_BODY));
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();

    await client.poe.publishContent({
      content: new Uint8Array([0xaa, 0xbb, 0xcc]),
      quoteId: QUOTE_ID,
      hashAlg: 'blake2b-256',
      signer,
    });

    const body = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body) as {
      record: string;
    };
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    expect(validated.record.items![0]!.hashes).toHaveProperty('blake2b-256');
    expect(validated.record.items![0]!.hashes).not.toHaveProperty('sha2-256');
  });

  it('threads idempotencyKey into the Idempotency-Key header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_BODY));
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    await client.poe.publishContent({
      content: 'x',
      quoteId: QUOTE_ID,
      signer,
      idempotencyKey: 'idem-7',
    });
    const headers = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Headers;
    expect(headers.get('idempotency-key')).toBe('idem-7');
  });

  it('reports dedup_hit=true when the server returns 200', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_BODY, 200));
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    const out = await client.poe.publishContent({ content: 'x', quoteId: QUOTE_ID, signer });
    expect(out.dedup_hit).toBe(true);
  });
});

describe('PoeNamespace.publishMerkle — internal quote + uploads + publish', () => {
  const QUOTE_BODY = {
    quote_id: QUOTE_ID,
    amount: '42',
    currency: 'USD',
    expires_at: '2100-01-01T00:00:00Z',
  };

  async function uploadedLeavesList(fetchMock: ReturnType<typeof vi.fn>): Promise<Uint8Array> {
    const form = (fetchMock.mock.calls[1]![1] as { body: FormData }).body;
    return new Uint8Array(await (form.get('file_0') as Blob).arrayBuffer());
  }

  it('binds merkleSha2256Root(leaves) + leaves.length into merkle[0] and archives the record bytes', async () => {
    const leaves = [
      nobleSha256(new Uint8Array([0])),
      nobleSha256(new Uint8Array([1])),
      nobleSha256(new Uint8Array([2])),
      nobleSha256(new Uint8Array([3])),
    ];
    const expectedRoot = merkleSha2256Root(leaves);
    const arUri = `ar://${'X'.repeat(43)}`;

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(QUOTE_BODY, 200))
      .mockResolvedValueOnce(jsonResponse(makeUploadsResponse(arUri), 200))
      .mockResolvedValueOnce(jsonResponse(PUBLISH_BODY, 202));

    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    const out = await client.poe.publishMerkle({ leaves, signer });

    expect(out.leaf_count).toBe(4);
    expect(out.root).toBe(bytesToHex(expectedRoot));
    expect(out.ar_uri).toBe(arUri);
    expect(out.balance_after_usd_micros).toBe('4500000');

    // The helper quotes internally: quote → uploads → publish.
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://cardanowall.com/api/v1/poe/quote');
    expect(fetchMock.mock.calls[1]![0]).toBe('https://cardanowall.com/api/v1/poe/uploads');
    expect(fetchMock.mock.calls[2]![0]).toBe('https://cardanowall.com/api/v1/poe/publish');

    // The quote priced the exact leaves-list byte count and an upper bound
    // of the record size.
    const leavesListBytes = await uploadedLeavesList(fetchMock);
    const quoteBody = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body) as {
      record_bytes: number;
      recipient_count: number;
      file_bytes_total: number;
    };
    expect(quoteBody.recipient_count).toBe(0);
    expect(quoteBody.file_bytes_total).toBe(leavesListBytes.length);

    // The upload rode the deterministic content-derived idempotency key.
    const uploadHeaders = (fetchMock.mock.calls[1]![1] as { headers: Headers }).headers;
    expect(uploadHeaders.get('idempotency-key')).toBe(
      `merkle1-${bytesToHex(nobleSha256(leavesListBytes)).slice(0, 32)}`,
    );

    // Submitted record must validate, carry merkle[0] with the right root,
    // consume the internal quote, and be archived verbatim in the response.
    const body = JSON.parse((fetchMock.mock.calls[2]![1] as { body: string }).body) as {
      record: string;
      quote_id: string;
    };
    expect(body.quote_id).toBe(QUOTE_ID);
    expect(body.record).toBe(bytesToHex(out.recordBytes));
    expect(quoteBody.record_bytes).toBeGreaterThanOrEqual(out.recordBytes.length);
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    expect(validated.record.merkle).toHaveLength(1);
    expect(validated.record.merkle![0]!.leaf_count).toBe(4);
    expect(bytesToHex(validated.record.merkle![0]!.root)).toBe(bytesToHex(expectedRoot));
    expect(validated.record.sigs).toHaveLength(1);
  });

  it('threads leafAlg into the uploaded leaves-list and omits it otherwise', async () => {
    const leaves = [nobleSha256(new Uint8Array([0])), nobleSha256(new Uint8Array([1]))];
    const arUri = `ar://${'Y'.repeat(43)}`;

    const run = async (leafAlg: string | undefined): Promise<Uint8Array> => {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(jsonResponse(QUOTE_BODY, 200))
        .mockResolvedValueOnce(jsonResponse(makeUploadsResponse(arUri), 200))
        .mockResolvedValueOnce(jsonResponse(PUBLISH_BODY, 202));
      const client = makeClient(fetchMock);
      await client.poe.publishMerkle({
        leaves,
        ...(leafAlg !== undefined ? { leafAlg } : {}),
      });
      return uploadedLeavesList(fetchMock);
    };

    // With leafAlg: the uploaded leaves-list carries the advisory claim.
    const withAlg = decodeLeavesList(await run('sha2-256'));
    expect(withAlg.leafAlg).toBe('sha2-256');
    // Without: the field is absent, exactly as before the rework.
    const withoutAlg = decodeLeavesList(await run(undefined));
    expect(withoutAlg.leafAlg).toBeUndefined();
  });

  it('enforces maxUsdMicros against the internal quote before any upload', async () => {
    const leaves = [nobleSha256(new Uint8Array([0]))];
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ ...QUOTE_BODY, amount: '1500000' }, 200));
    const client = makeClient(fetchMock);
    const err = await client.poe
      .publishMerkle({ leaves, maxUsdMicros: 1_000_000n })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MaxUsdExceededError);
    expect((err as MaxUsdExceededError).quotedUsdMicros).toBe('1500000');
    // Only the quote was requested; nothing was uploaded or published.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('refreshes an expired price lock after the upload and publishes against the new one', async () => {
    const leaves = [nobleSha256(new Uint8Array([0]))];
    const arUri = `ar://${'Z'.repeat(43)}`;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          { quote_id: 'lock-1', amount: '42', currency: 'USD', expires_at: '2000-01-01T00:00:00Z' },
          200,
        ),
      )
      .mockResolvedValueOnce(jsonResponse(makeUploadsResponse(arUri), 200))
      .mockResolvedValueOnce(
        jsonResponse(
          { quote_id: 'lock-2', amount: '42', currency: 'USD', expires_at: '2100-01-01T00:00:00Z' },
          200,
        ),
      )
      .mockResolvedValueOnce(jsonResponse(PUBLISH_BODY, 202));
    const client = makeClient(fetchMock);
    await client.poe.publishMerkle({ leaves });
    expect(fetchMock).toHaveBeenCalledTimes(4);
    const body = JSON.parse((fetchMock.mock.calls[3]![1] as { body: string }).body) as {
      quote_id: string;
    };
    expect(body.quote_id).toBe('lock-2');
  });

  it('re-caps against the refreshed price after a stale-quote refresh, refusing the publish', async () => {
    const leaves = [nobleSha256(new Uint8Array([0]))];
    const arUri = `ar://${'W'.repeat(43)}`;
    // The first lock is stale, so the leaves-list still uploads; the post-upload
    // requote comes back above the cap and the publish is refused. The cap test
    // above only exercises the pre-upload internal-quote cap.
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          { quote_id: 'lock-1', amount: '42', currency: 'USD', expires_at: '2000-01-01T00:00:00Z' },
          200,
        ),
      )
      .mockResolvedValueOnce(jsonResponse(makeUploadsResponse(arUri), 200))
      .mockResolvedValueOnce(
        jsonResponse(
          {
            quote_id: 'lock-2',
            amount: '1500000',
            currency: 'USD',
            expires_at: '2100-01-01T00:00:00Z',
          },
          200,
        ),
      );
    const client = makeClient(fetchMock);
    const err = await client.poe
      .publishMerkle({ leaves, maxUsdMicros: 1_000_000n })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MaxUsdExceededError);
    expect((err as MaxUsdExceededError).quotedUsdMicros).toBe('1500000');
    // quote → upload → requote, but NO publish.
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rejects an empty leaves array with PublishError(INVALID_LEAVES)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    await expect(client.poe.publishMerkle({ leaves: [], signer })).rejects.toThrow(PublishError);
    await expect(client.poe.publishMerkle({ leaves: [], signer })).rejects.toMatchObject({
      code: 'INVALID_LEAVES',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('throws PartialUploadError when /uploads partially fails (publish never runs)', async () => {
    const leaves = [nobleSha256(new Uint8Array([0]))];
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(QUOTE_BODY, 200))
      .mockResolvedValueOnce(
        jsonResponse(
          {
            uploads: [
              {
                idx: 0,
                ok: false,
                error: { code: 'upload-failed', detail: 'arweave timeout' },
              },
            ],
          },
          200,
        ),
      );
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    await expect(client.poe.publishMerkle({ leaves, signer })).rejects.toBeInstanceOf(
      PartialUploadError,
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe('PoeNamespace.publishContent — malformed signer rejections', () => {
  it('rejects a 31-byte signerPubkey with PublishError(INVALID_SIGNER_PUBKEY)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    const badSigner: Signer = {
      signerPubkey: new Uint8Array(31),
      async sign() {
        return new Uint8Array(64);
      },
    };
    await expect(
      client.poe.publishContent({ content: 'x', quoteId: QUOTE_ID, signer: badSigner }),
    ).rejects.toMatchObject({
      code: 'INVALID_SIGNER_PUBKEY',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a signer that returns a wrong-length signature with PublishError(INVALID_SIGNER_SIGNATURE)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    const realPubkey = getPublicKeyEd25519({ seed: new Uint8Array(32).fill(0x11) });
    const shortSig: Signer = {
      signerPubkey: realPubkey,
      async sign() {
        return new Uint8Array(63);
      },
    };
    await expect(
      client.poe.publishContent({ content: 'x', quoteId: QUOTE_ID, signer: shortSig }),
    ).rejects.toMatchObject({
      code: 'INVALID_SIGNER_SIGNATURE',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('PoeNamespace.publishPrehashed — caller-supplied digest', () => {
  it('passes the supplied sha2-256 digest through unchanged (no re-hashing)', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_BODY));
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    const digestHex = bytesToHex(nobleSha256(new TextEncoder().encode('hello world')));

    const out = await client.poe.publishPrehashed({
      hashes: { 'sha2-256': digestHex },
      quoteId: QUOTE_ID,
      signer,
    });
    expect(out.id).toBe(PUBLISH_BODY.id);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const body = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body) as {
      record: string;
      quote_id: string;
    };
    expect(body.quote_id).toBe(QUOTE_ID);
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    expect(bytesToHex(validated.record.items![0]!.hashes['sha2-256']!)).toBe(digestHex);
  });

  it('rejects an empty `hashes` map with PublishError(INVALID_DIGEST)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    await expect(
      client.poe.publishPrehashed({ hashes: {}, quoteId: QUOTE_ID, signer }),
    ).rejects.toMatchObject({
      code: 'INVALID_DIGEST',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a wrong-length digest with PublishError(INVALID_DIGEST)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    await expect(
      client.poe.publishPrehashed({
        hashes: { 'sha2-256': '00'.repeat(31) }, // 31 bytes, not 32
        quoteId: QUOTE_ID,
        signer,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_DIGEST' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('strict hex decoding — digest (publishPrehashed) / leaf (publishMerkle)', () => {
  // Each pair is a full-width (32-byte) hex string whose final byte is
  // malformed. `parseInt` silently mis-decoded every one of these
  // (`parseInt('4z',16)===4`, `parseInt('+5',16)===5`, `parseInt('-1',16)===-1`
  // wrapping to 255, `parseInt(' 4',16)===4`) and yielded a wrong-but-32-byte
  // digest that then got hashed, paid for on upload, and anchored on-chain.
  // Strict decode — the same accept/reject set as the Rust SDK's `hex::decode`
  // — refuses them before any network call, and each publish path raises the
  // error code its field maps to.
  const MISDECODE_TAILS = ['4z', '+5', '-1', ' 4'] as const;
  const PREFIX_31_BYTES = '00'.repeat(31); // 62 hex chars; one byte-pair short of 32

  for (const tail of MISDECODE_TAILS) {
    const digest = `${PREFIX_31_BYTES}${tail}`;

    it(`publishPrehashed refuses a digest ending in ${JSON.stringify(tail)} as INVALID_DIGEST (no network)`, async () => {
      const fetchMock = vi.fn();
      const client = makeClient(fetchMock);
      await expect(
        client.poe.publishPrehashed({ hashes: { 'sha2-256': digest }, quoteId: QUOTE_ID }),
      ).rejects.toMatchObject({ code: 'INVALID_DIGEST' });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it(`publishMerkle refuses a leaf ending in ${JSON.stringify(tail)} as INVALID_LEAVES (no network)`, async () => {
      const fetchMock = vi.fn();
      const client = makeClient(fetchMock);
      await expect(client.poe.publishMerkle({ leaves: [digest] })).rejects.toMatchObject({
        code: 'INVALID_LEAVES',
      });
      expect(fetchMock).not.toHaveBeenCalled();
    });
  }

  it('publishPrehashed accepts a mixed-case digest and decodes it to the same bytes as its lowercase twin', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PUBLISH_BODY));
    const client = makeClient(fetchMock);
    const lower = bytesToHex(nobleSha256(new TextEncoder().encode('mixed case digest')));

    const out = await client.poe.publishPrehashed({
      hashes: { 'sha2-256': lower.toUpperCase() },
      quoteId: QUOTE_ID,
    });
    expect(out.id).toBe(PUBLISH_BODY.id);

    const body = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body) as {
      record: string;
    };
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    // The uppercase input anchored the identical digest bytes.
    expect(bytesToHex(validated.record.items![0]!.hashes['sha2-256']!)).toBe(lower);
  });

  it('publishPrehashed rejects an odd-length digest as INVALID_DIGEST (no network)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    await expect(
      client.poe.publishPrehashed({ hashes: { 'sha2-256': '0'.repeat(63) }, quoteId: QUOTE_ID }),
    ).rejects.toMatchObject({ code: 'INVALID_DIGEST' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
