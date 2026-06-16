// Unit tests for the high-level publishContent() / publishPrehashed() /
// publishSealed() / publishMerkle() helpers — assert canonical record shape,
// signer integration, sealed-envelope construction, Merkle root binding,
// partial-upload handling, and input-validation boundaries.

import { describe, expect, it, vi } from 'vitest';

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { eciesSealedPoeUnwrap, merkleSha2256Root } from '@cardanowall/crypto-core';
import { getPublicKeyEd25519, signEd25519 } from '@cardanowall/crypto-core/sig';
import { mlkem768x25519Keygen, x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { validatePoeRecord } from '@cardanowall/poe-standard';

import { Label309Client } from './label-309-client';
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

describe('PoeNamespace.publishSealed — encrypt + uploads + publish', () => {
  it('encrypts to x25519 recipients, uploads ciphertext to arweave, posts record with ar:// URI', async () => {
    const recipientSecret = new Uint8Array(32).fill(0x11);
    const recipientPub = x25519PublicKey({ secretKey: recipientSecret });
    const arUri = `ar://${'C'.repeat(43)}`;

    let capturedCiphertext: Uint8Array | undefined;
    const fetchMock = vi
      .fn()
      // First call: /uploads (multipart)
      .mockImplementationOnce(async (_url: string, init: RequestInit) => {
        const form = (init as { body: FormData }).body;
        expect(form.get('target')).toBe('arweave');
        const blob = form.get('file_0') as Blob;
        capturedCiphertext = new Uint8Array(await blob.arrayBuffer());
        return jsonResponse(makeUploadsResponse(arUri), 200);
      })
      // Second call: /publish (JSON)
      .mockResolvedValueOnce(jsonResponse(PUBLISH_BODY, 202));

    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    const out = await client.poe.publishSealed({
      content: 'top-secret',
      quoteId: QUOTE_ID,
      recipients: [recipientPub],
      // Explicit classical opt-out (default is now the hybrid KEM).
      kem: 'x25519',
      signer,
    });

    expect(out.id).toBe(PUBLISH_BODY.id);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://cardanowall.com/api/v1/poe/uploads');
    expect(fetchMock.mock.calls[1]![0]).toBe('https://cardanowall.com/api/v1/poe/publish');

    // The recipient can decrypt the ciphertext we uploaded.
    expect(capturedCiphertext).toBeInstanceOf(Uint8Array);

    // Submitted record must validate + reference the real ar:// URI.
    const body = JSON.parse((fetchMock.mock.calls[1]![1] as { body: string }).body) as {
      record: string;
    };
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    const item = validated.record.items![0]!;
    expect(item.enc).toBeDefined();
    expect(item.uris).toBeDefined();
    expect(item.uris![0]!).toBe(arUri);
    expect(validated.record.sigs).toHaveLength(1);

    // End-to-end: decrypt the ciphertext we captured with the recipient secret.
    const envelope = item.enc! as unknown as Record<string, unknown>;
    const unwrapped = eciesSealedPoeUnwrap({
      envelope: {
        scheme: envelope['scheme'] as 1,
        aead: envelope['aead'] as 'chacha20-poly1305-stream64k',
        kem: envelope['kem'] as 'x25519',
        nonce: envelope['nonce'] as Uint8Array,
        slots: envelope['slots'] as ReadonlyArray<{ epk: Uint8Array; wrap: Uint8Array }>,
        slots_mac: envelope['slots_mac'] as Uint8Array,
      },
      ciphertext: capturedCiphertext!,
      hashes: item.hashes,
      recipientSecretKey: recipientSecret,
    });
    expect(unwrapped.matched).toBe(true);
    if (!unwrapped.matched) throw new Error('unreachable');
    expect(new TextDecoder().decode(unwrapped.plaintext)).toBe('top-secret');
  });

  it('defaults to the hybrid (mlkem768x25519) KEM: 1216-byte recipient, hybrid envelope round-trips', async () => {
    const seed = new Uint8Array(32).fill(0x33);
    const { secretSeed, publicKey } = mlkem768x25519Keygen(seed);
    const arUri = `ar://${'D'.repeat(43)}`;

    let capturedCiphertext: Uint8Array | undefined;
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(async (_url: string, init: RequestInit) => {
        const form = (init as { body: FormData }).body;
        const blob = form.get('file_0') as Blob;
        capturedCiphertext = new Uint8Array(await blob.arrayBuffer());
        return jsonResponse(makeUploadsResponse(arUri), 200);
      })
      .mockResolvedValueOnce(jsonResponse(PUBLISH_BODY, 202));

    const client = makeClient(fetchMock);
    // No `kem` passed → hybrid by default.
    const out = await client.poe.publishSealed({
      content: 'pq-secret',
      quoteId: QUOTE_ID,
      recipients: [publicKey],
    });
    expect(out.id).toBe(PUBLISH_BODY.id);

    const body = JSON.parse((fetchMock.mock.calls[1]![1] as { body: string }).body) as {
      record: string;
    };
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    const item = validated.record.items![0]!;
    const envelope = item.enc! as unknown as Record<string, unknown>;
    expect(envelope['kem']).toBe('mlkem768x25519');
    // Hybrid slots carry the single 1120-byte kem_ct, never a per-slot epk.
    const slots = envelope['slots'] as ReadonlyArray<{ kem_ct?: unknown; epk?: unknown }>;
    expect(slots[0]!.kem_ct).toBeInstanceOf(Uint8Array);
    expect((slots[0]!.kem_ct as Uint8Array).length).toBe(1120);
    expect(slots[0]!.epk).toBeUndefined();

    const unwrapped = eciesSealedPoeUnwrap({
      envelope: {
        scheme: envelope['scheme'] as 1,
        aead: envelope['aead'] as 'chacha20-poly1305-stream64k',
        kem: 'mlkem768x25519',
        nonce: envelope['nonce'] as Uint8Array,
        slots: envelope['slots'] as ReadonlyArray<{ kem_ct: Uint8Array; wrap: Uint8Array }>,
        slots_mac: envelope['slots_mac'] as Uint8Array,
      },
      ciphertext: capturedCiphertext!,
      hashes: item.hashes,
      recipientSecretKey: secretSeed,
    });
    expect(unwrapped.matched).toBe(true);
    if (!unwrapped.matched) throw new Error('unreachable');
    expect(new TextDecoder().decode(unwrapped.plaintext)).toBe('pq-secret');
  });

  it('rejects an empty recipients array with PublishError(INVALID_RECIPIENT)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    await expect(
      client.poe.publishSealed({ content: 'x', quoteId: QUOTE_ID, recipients: [] }),
    ).rejects.toMatchObject({ code: 'INVALID_RECIPIENT' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a wrong-length recipient pubkey for the chosen KEM (32 B under hybrid default)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    // A 32-byte X25519 key under the hybrid default (expects 1216 B) is rejected.
    await expect(
      client.poe.publishSealed({
        content: 'x',
        quoteId: QUOTE_ID,
        recipients: [new Uint8Array(32)],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RECIPIENT' });
    // And a 31-byte key under explicit x25519 (expects 32 B) is rejected.
    await expect(
      client.poe.publishSealed({
        content: 'x',
        quoteId: QUOTE_ID,
        recipients: [new Uint8Array(31)],
        kem: 'x25519',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RECIPIENT' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('throws PartialUploadError when /uploads returns any failed entry', async () => {
    const recipientPub = x25519PublicKey({ secretKey: new Uint8Array(32).fill(0x22) });
    const fetchMock = vi.fn().mockResolvedValueOnce(
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
    const err = await client.poe
      .publishSealed({ content: 'x', quoteId: QUOTE_ID, recipients: [recipientPub], kem: 'x25519' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PartialUploadError);
    const typed = err as PartialUploadError;
    expect(typed.failedIndices).toEqual([0]);
    // Only the uploads call was made; /publish never followed.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('PoeNamespace.publishMerkle — Merkle batch via uploads + publish', () => {
  it('binds merkleSha2256Root(leaves) + leaves.length into merkle[0] of the on-chain record', async () => {
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
      .mockResolvedValueOnce(jsonResponse(makeUploadsResponse(arUri), 200))
      .mockResolvedValueOnce(jsonResponse(PUBLISH_BODY, 202));

    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    const out = await client.poe.publishMerkle({ leaves, quoteId: QUOTE_ID, signer });

    expect(out.leaf_count).toBe(4);
    expect(out.root).toBe(bytesToHex(expectedRoot));
    expect(out.ar_uri).toBe(arUri);
    expect(out.balance_after_usd_micros).toBe('4500000');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://cardanowall.com/api/v1/poe/uploads');
    expect(fetchMock.mock.calls[1]![0]).toBe('https://cardanowall.com/api/v1/poe/publish');

    // Submitted record must validate + carry merkle[0] with the right root.
    const body = JSON.parse((fetchMock.mock.calls[1]![1] as { body: string }).body) as {
      record: string;
    };
    const validated = validatePoeRecord(hexToBytes(body.record));
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    expect(validated.record.merkle).toHaveLength(1);
    expect(validated.record.merkle![0]!.leaf_count).toBe(4);
    expect(bytesToHex(validated.record.merkle![0]!.root)).toBe(bytesToHex(expectedRoot));
    expect(validated.record.sigs).toHaveLength(1);
  });

  it('rejects an empty leaves array with PublishError(INVALID_LEAVES)', async () => {
    const fetchMock = vi.fn();
    const client = makeClient(fetchMock);
    const signer = makeInMemorySigner();
    await expect(
      client.poe.publishMerkle({ leaves: [], quoteId: QUOTE_ID, signer }),
    ).rejects.toThrow(PublishError);
    await expect(
      client.poe.publishMerkle({ leaves: [], quoteId: QUOTE_ID, signer }),
    ).rejects.toMatchObject({
      code: 'INVALID_LEAVES',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('throws PartialUploadError when /uploads partially fails (publish never runs)', async () => {
    const leaves = [nobleSha256(new Uint8Array([0]))];
    const fetchMock = vi.fn().mockResolvedValueOnce(
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
    await expect(
      client.poe.publishMerkle({ leaves, quoteId: QUOTE_ID, signer }),
    ).rejects.toBeInstanceOf(PartialUploadError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
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
