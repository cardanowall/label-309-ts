// Two-phase sealed publishing behaviour: prepare determinism, the portable
// prepared_seal_json_v1 artifact, receipt-validated resume, quote
// consumption/refresh, the price cap, and the one-shot wrapper. Assertions
// target request sequences, request bodies, receipts, and record bytes —
// never log strings.

import { describe, expect, it, vi } from 'vitest';

import { sha256 } from '@cardanowall/crypto-core/hash';
import { mlkem768x25519Keygen, x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { eciesSealedPoeUnwrap } from '@cardanowall/crypto-core/sealed-poe';
import { deriveX25519KeypairFromSeed } from '@cardanowall/crypto-core/seed-derive';
import { encodePoeRecord, validatePoeRecord, type PoeRecord } from '@cardanowall/poe-standard';

import { bytesToHex } from '../hex';
import { InsufficientFundsError } from './insufficient-funds-error';
import { InvalidUploadReceiptError } from './invalid-upload-receipt-error';
import { Label309Client } from './label-309-client';
import { MaxUsdExceededError } from './max-usd-exceeded-error';
import { PartialUploadError } from './partial-upload-error';
import { PublishError } from './publish';
import {
  PREPARED_SEAL_JSON_VERSION,
  PreparedSeal,
  PreparedSealJsonError,
  SealPrepareError,
  SubmitSealedError,
  encodeSealedRecord,
  preparedSealFromJson,
  preparedSealToJson,
  publishSealed,
  sealPrepare,
  sealPrepareWithRng,
  sealedRecord,
  type DeterministicRng,
  type UploadReceipt,
} from './sealed';

const QUOTE_ID = '01956b41-7c00-7000-8000-000000000001';
const FRESH_EXPIRY = '2100-01-01T00:00:00Z';
const STALE_EXPIRY = '2000-01-01T00:00:00Z';

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

function problemResponse(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/problem+json' },
  });
}

function quoteBody(id: string, amount: string, expiresAt: string) {
  return { quote_id: id, amount, currency: 'USD', expires_at: expiresAt };
}

function freshQuoteBody(amount: string) {
  return quoteBody(QUOTE_ID, amount, FRESH_EXPIRY);
}

function uploadSuccessBody(uri: string) {
  return { uploads: [{ idx: 0, ok: true, uri, sha256: '00'.repeat(32), bytes: 1 }] };
}

function makeClient(fetchMock: ReturnType<typeof vi.fn>): Label309Client {
  return new Label309Client({
    baseUrl: 'https://cardanowall.com/api/v1',
    apiKey: 'opaque-bearer-token',
    fetch: fetchMock as unknown as typeof globalThis.fetch,
  });
}

function queuedFetch(responses: Response[]): ReturnType<typeof vi.fn> {
  return vi.fn(async (): Promise<Response> => {
    const next = responses.shift();
    if (next === undefined) throw new Error('unexpected extra request');
    return next;
  });
}

function requestUrl(fetchMock: ReturnType<typeof vi.fn>, index: number): string {
  return String(fetchMock.mock.calls[index]![0]);
}

function requestHeader(
  fetchMock: ReturnType<typeof vi.fn>,
  index: number,
  name: string,
): string | null {
  return (fetchMock.mock.calls[index]![1] as { headers: Headers }).headers.get(name);
}

function requestJson(fetchMock: ReturnType<typeof vi.fn>, index: number): Record<string, unknown> {
  return JSON.parse((fetchMock.mock.calls[index]![1] as { body: string }).body) as Record<
    string,
    unknown
  >;
}

async function uploadedFileBytes(
  fetchMock: ReturnType<typeof vi.fn>,
  index: number,
): Promise<Uint8Array> {
  const form = (fetchMock.mock.calls[index]![1] as { body: FormData }).body;
  const blob = form.get('file_0') as Blob;
  return new Uint8Array(await blob.arrayBuffer());
}

/**
 * A deterministic byte source for reproducible prepares: byte `n` of the
 * stream is `(start + n) mod 256` — the counter stream the cross-SDK
 * fixtures declare.
 */
function counterRng(start: number): DeterministicRng {
  let state = start;
  return (out: Uint8Array) => {
    for (let i = 0; i < out.length; i++) {
      out[i] = state & 0xff;
      state = (state + 1) % 256;
    }
  };
}

/** Derive `count` classical recipient public keys from fixed seeds. */
function x25519Recipients(count: number): Uint8Array[] {
  return Array.from(
    { length: count },
    (_, i) => deriveX25519KeypairFromSeed(new Uint8Array(32).fill(i + 1)).publicKey,
  );
}

/** A reproducible classical prepared seal over the given plaintexts. */
function deterministicPrepared(plaintexts: string[], recipientCount: number): PreparedSeal {
  return sealPrepareWithRng(
    {
      items: plaintexts.map((content) => ({ content })),
      recipients: x25519Recipients(recipientCount),
      kem: 'x25519',
    },
    counterRng(0),
  );
}

/** A receipt matching the prepared item at `index` with the given uri. */
function receiptFor(prepared: PreparedSeal, index: number, uri: string): UploadReceipt {
  const item = prepared.items[index]!;
  return {
    itemId: item.itemId,
    uri,
    ciphertextSha256: sha256(item.ciphertext()),
    bytes: item.ciphertext().length,
  };
}

/**
 * The canonical form of the fixture-side tamper tests: compact JSON, keys
 * sorted at every nesting level, the fingerprint member removed. Recomputing
 * it here (independently of the module under test) doubles as a check of
 * the canonical-form definition itself.
 */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
}

function recomputedFingerprint(document: Record<string, unknown>): string {
  const copy: Record<string, unknown> = { ...document };
  delete copy['prepared_sha256'];
  return bytesToHex(sha256(new TextEncoder().encode(canonicalize(copy))));
}

const arUri = (fill: string): string => `ar://${fill.repeat(43)}`;

// =============================================================================
// Phase 1: determinism, derivations, and the portable artifact
// =============================================================================

describe('sealPrepare / sealPrepareWithRng', () => {
  it('is deterministic under a fixed rng and pins the per-item derivations', () => {
    const a = deterministicPrepared(['item zero', 'item one'], 2);
    const b = deterministicPrepared(['item zero', 'item one'], 2);
    // The same rng stream reproduces the artifact byte-for-byte.
    expect(preparedSealToJson(a)).toBe(preparedSealToJson(b));
    expect(a.preparedSha256).toBe(b.preparedSha256);

    // item_id is the lowercase-hex SHA-256 of the item's ciphertext.
    for (const item of a.items) {
      expect(item.itemId).toBe(bytesToHex(sha256(item.ciphertext())));
    }
    // The per-item upload idempotency key is derived from the fingerprint.
    for (let index = 0; index < a.items.length; index++) {
      expect(a.uploadIdempotencyKey(index)).toBe(`seal1-${a.preparedSha256.slice(0, 32)}-${index}`);
    }
    expect(() => a.uploadIdempotencyKey(2)).toThrow(RangeError);
  });

  it('the secure entry point draws fresh randomness on every call', () => {
    const input = { items: [{ content: 'item zero' }], recipients: x25519Recipients(1) } as const;
    const a = sealPrepare({ ...input, kem: 'x25519' });
    const b = sealPrepare({ ...input, kem: 'x25519' });
    // A repeat would mean a repeated content key.
    expect(a.preparedSha256).not.toBe(b.preparedSha256);
  });

  it('rejects empty items, empty recipients, and KEM-mismatched key lengths', () => {
    const recipients = x25519Recipients(1);
    expect(() => sealPrepare({ items: [], recipients })).toThrow(SealPrepareError);
    expect(() => sealPrepare({ items: [], recipients })).toThrow(
      expect.objectContaining({ code: 'NO_ITEMS' }) as Error,
    );
    expect(() => sealPrepare({ items: [{ content: 'x' }], recipients: [] })).toThrow(
      expect.objectContaining({ code: 'INVALID_RECIPIENT' }) as Error,
    );
    // A 32-byte classical key under the hybrid default (expects 1216 B).
    expect(() => sealPrepare({ items: [{ content: 'x' }], recipients })).toThrow(
      expect.objectContaining({ code: 'INVALID_RECIPIENT' }) as Error,
    );
    // A 31-byte key under explicit x25519 (expects 32 B).
    expect(() =>
      sealPrepare({ items: [{ content: 'x' }], recipients: [new Uint8Array(31)], kem: 'x25519' }),
    ).toThrow(expect.objectContaining({ code: 'INVALID_RECIPIENT' }) as Error);
  });

  it('PreparedSeal cannot be constructed outside the module', () => {
    // The artifact's fields are private so an in-memory instance can never
    // drift from its fingerprint; the only doors are sealPrepare and the
    // verified JSON parser.
    expect(() => new PreparedSeal(Symbol('forged'))).toThrow(TypeError);
  });
});

describe('prepared_seal_json_v1', () => {
  it('round-trips and rejects corruption, unknown members, and foreign versions', () => {
    const prepared = deterministicPrepared(['round trip'], 2);
    const json = preparedSealToJson(prepared);

    // Round trip: parse → identical artifact → identical canonical JSON.
    const parsed = preparedSealFromJson(json);
    expect(preparedSealToJson(parsed)).toBe(json);
    expect(parsed.preparedSha256).toBe(prepared.preparedSha256);

    const document = JSON.parse(json) as Record<string, unknown>;

    // A flipped fingerprint is rejected as corruption.
    const fp = document['prepared_sha256'] as string;
    const flipped = fp.startsWith('0') ? `1${fp.slice(1)}` : `0${fp.slice(1)}`;
    const tampered = { ...document, prepared_sha256: flipped };
    expect(() => preparedSealFromJson(JSON.stringify(tampered))).toThrow(
      expect.objectContaining({ code: 'FINGERPRINT_MISMATCH' }) as Error,
    );

    // Unknown members are rejected: the strict schema is what makes the
    // fingerprint meaningful (an ignored field would be unauthenticated).
    const extra = { ...document, surprise: true };
    expect(() => preparedSealFromJson(JSON.stringify(extra))).toThrow(
      expect.objectContaining({ code: 'PARSE' }) as Error,
    );

    // A foreign version string is refused before any structural work.
    const wrongVersion = { ...document, version: 'prepared_seal_json_v2' };
    expect(() => preparedSealFromJson(JSON.stringify(wrongVersion))).toThrow(
      expect.objectContaining({ code: 'UNSUPPORTED_VERSION' }) as Error,
    );

    // Not JSON at all.
    expect(() => preparedSealFromJson('{nope')).toThrow(PreparedSealJsonError);
  });

  it('rejects a ciphertext swap even with a recomputed fingerprint', () => {
    const prepared = deterministicPrepared(['tamper me'], 1);
    const document = JSON.parse(preparedSealToJson(prepared)) as Record<string, unknown>;

    // Sanity: the test-side canonicalization reproduces the SDK's own
    // fingerprint, independently pinning the canonical-form definition.
    expect(recomputedFingerprint(document)).toBe(prepared.preparedSha256);

    // Swap the ciphertext and recompute the fingerprint like an attacker
    // fixing up the checksum would: the item_id ↔ ciphertext invariant still
    // rejects the document.
    const items = document['items'] as Array<Record<string, unknown>>;
    items[0]!['ciphertext'] = 'AAAA';
    document['prepared_sha256'] = recomputedFingerprint(document);
    expect(() => preparedSealFromJson(JSON.stringify(document))).toThrow(
      expect.objectContaining({ code: 'INVALID' }) as Error,
    );
  });
});

describe('prepared_seal_json_v1 — canonical-form backstop', () => {
  // Each variant below is a raw-text mutation of one canonical artifact that
  // parses back to the same value — so the structural walk and the fingerprint
  // check pass — yet is not the byte-exact canonical serialization. The parser
  // must refuse them all, giving the TS/PY/RS SDKs an identical accept/reject
  // verdict for a single shared prepared_seal_json_v1 document.
  const canonical = (): string => preparedSealToJson(deterministicPrepared(['backstop me'], 2));

  it('accepts the canonical form but rejects a reformatted (pretty-printed) copy', () => {
    const json = canonical();
    // Canonical in → identical artifact out.
    expect(preparedSealToJson(preparedSealFromJson(json))).toBe(json);

    // Same values and same key order, but insignificant whitespace reintroduced.
    const pretty = JSON.stringify(JSON.parse(json), null, 2);
    expect(pretty).not.toBe(json);
    expect(() => preparedSealFromJson(pretty)).toThrow(
      expect.objectContaining({ code: 'INVALID' }) as Error,
    );
  });

  it('rejects a float-typed scheme (1.0) that JSON.parse collapses to the integer 1', () => {
    const json = canonical().replaceAll('"scheme":1', '"scheme":1.0');
    expect(json).toContain('"scheme":1.0');
    expect(() => preparedSealFromJson(json)).toThrow(
      expect.objectContaining({ code: 'INVALID' }) as Error,
    );
  });

  it('rejects an exponent-typed scheme (1e0)', () => {
    const json = canonical().replaceAll('"scheme":1', '"scheme":1e0');
    expect(() => preparedSealFromJson(json)).toThrow(
      expect.objectContaining({ code: 'INVALID' }) as Error,
    );
  });

  it('rejects a duplicate top-level member (JSON.parse keeps the last occurrence)', () => {
    const duplicate = `{${JSON.stringify('version')}:${JSON.stringify(PREPARED_SEAL_JSON_VERSION)},`;
    const json = canonical().replace('{', duplicate);
    // The duplicate parses away (last wins), so the walk and fingerprint pass;
    // only the byte-equality gate observes the extra member.
    expect(() => preparedSealFromJson(json)).toThrow(
      expect.objectContaining({ code: 'INVALID' }) as Error,
    );
  });

  it('rejects an explicit null for an absent optional slot member (kem_ct on an x25519 slot)', () => {
    const json = canonical().replace(',"wrap":', ',"kem_ct":null,"wrap":');
    expect(() => preparedSealFromJson(json)).toThrow(PreparedSealJsonError);
  });
});

// =============================================================================
// Pure assembly seams
// =============================================================================

describe('sealedRecord / encodeSealedRecord', () => {
  it('produces byte-identical records to a direct construction over the same material', async () => {
    const prepared = deterministicPrepared(['byte identity'], 2);
    const uri = arUri('B');
    const viaPrepared = await encodeSealedRecord(prepared, [uri]);

    // The direct construction: the same hashes, envelope, and URI lowered to
    // a record by hand and fed to the canonical encoder.
    const item = prepared.items[0]!;
    const record = {
      v: 1,
      items: [{ hashes: item.hashes(), uris: [uri], enc: item.envelope() }],
    } as unknown as PoeRecord;
    const direct = encodePoeRecord(record);
    expect(bytesToHex(viaPrepared)).toBe(bytesToHex(direct));
  });

  it('supports multi-item records and validates uri count and supersedes', async () => {
    const prepared = deterministicPrepared(['one', 'two', 'three'], 2);
    const uris = [arUri('0'), arUri('1'), arUri('2')];
    const supersedes = 'ab'.repeat(32);

    const recordBytes = await encodeSealedRecord(prepared, uris, supersedes);
    const validated = validatePoeRecord(recordBytes);
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    const items = validated.record.items!;
    expect(items).toHaveLength(3);
    for (let index = 0; index < items.length; index++) {
      expect(items[index]!.uris).toEqual([uris[index]!]);
      expect(items[index]!.enc).toBeDefined();
    }
    expect(bytesToHex(validated.record.supersedes! as Uint8Array)).toBe(supersedes);

    // One URI per item is a hard contract.
    expect(() => sealedRecord(prepared, uris.slice(0, 2))).toThrow(
      expect.objectContaining({ code: 'URI_COUNT_MISMATCH' }) as Error,
    );
    // Supersedes must be a 64-hex transaction hash.
    expect(() => sealedRecord(prepared, uris, 'not-hex')).toThrow(
      expect.objectContaining({ code: 'INVALID_SUPERSEDES' }) as Error,
    );
  });
});

// =============================================================================
// Quoting
// =============================================================================

describe('PoeNamespace.quotePreparedSeal', () => {
  it('prices the exact prepared shape without uploading anything', async () => {
    const prepared = deterministicPrepared(['priced one', 'priced two'], 2);
    const fetchMock = queuedFetch([jsonResponse(freshQuoteBody('123'), 200)]);
    const client = makeClient(fetchMock);

    const quote = await client.poe.quotePreparedSeal({ prepared });
    expect(quote.amount).toBe('123');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(requestUrl(fetchMock, 0)).toBe('https://cardanowall.com/api/v1/poe/quote');

    const sent = requestJson(fetchMock, 0);
    // Storage side: the exact ciphertext total. Recipient side: one slot per
    // recipient per item.
    let ciphertextTotal = 0;
    for (const item of prepared.items) ciphertextTotal += item.ciphertext().length;
    expect(sent['file_bytes_total']).toBe(ciphertextTotal);
    expect(sent['recipient_count']).toBe(4);
    // Record side: an upper bound of the real encoded record with real URIs.
    const actual = (await encodeSealedRecord(prepared, [arUri('0'), arUri('1')])).length;
    expect(sent['record_bytes'] as number).toBeGreaterThanOrEqual(actual);
  });
});

// =============================================================================
// Phase 2: submitSealed
// =============================================================================

describe('PoeNamespace.submitSealed', () => {
  it('uploads each item under its deterministic key and publishes the archived bytes', async () => {
    const prepared = deterministicPrepared(['first plaintext', 'second plaintext'], 1);
    const uriA = arUri('D');
    const uriB = arUri('E');
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uriA), 200),
      jsonResponse(uploadSuccessBody(uriB), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    const client = makeClient(fetchMock);

    const submission = await client.poe.submitSealed({ prepared });

    expect(fetchMock).toHaveBeenCalledTimes(4);
    // Each upload carries its item's ciphertext under its deterministic key.
    for (let index = 0; index < 2; index++) {
      expect(requestUrl(fetchMock, 1 + index)).toBe('https://cardanowall.com/api/v1/poe/uploads');
      expect(requestHeader(fetchMock, 1 + index, 'idempotency-key')).toBe(
        prepared.uploadIdempotencyKey(index),
      );
      expect(await uploadedFileBytes(fetchMock, 1 + index)).toEqual(
        prepared.items[index]!.ciphertext(),
      );
    }
    // The publish consumed the internal quote and posted the archived bytes.
    const sent = requestJson(fetchMock, 3);
    expect(sent['quote_id']).toBe(QUOTE_ID);
    expect(sent['record']).toBe(bytesToHex(submission.recordBytes));
    expect(submission.uris).toEqual([uriA, uriB]);
    expect(submission.response.id).toBe(PUBLISH_BODY.id);
    expect(submission.quote.quote_id).toBe(QUOTE_ID);
    // Receipts mirror the uploads, in item order.
    expect(submission.uploads).toHaveLength(2);
    for (let index = 0; index < 2; index++) {
      const receipt = submission.uploads[index]!;
      const item = prepared.items[index]!;
      expect(receipt.itemId).toBe(item.itemId);
      expect(receipt.bytes).toBe(item.ciphertext().length);
      expect(bytesToHex(receipt.ciphertextSha256)).toBe(bytesToHex(sha256(item.ciphertext())));
    }
    expect(submission.uploads[0]!.uri).toBe(uriA);
    expect(submission.uploads[1]!.uri).toBe(uriB);
  });

  it('rides the caller idempotency key on the publish only, never on an upload', async () => {
    const prepared = deterministicPrepared(['first plaintext', 'second plaintext'], 1);
    const uriA = arUri('D');
    const uriB = arUri('E');
    const callerKey = 'caller-supplied-key-abc123';
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uriA), 200),
      jsonResponse(uploadSuccessBody(uriB), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    const client = makeClient(fetchMock);
    await client.poe.submitSealed({ prepared, idempotencyKey: callerKey });

    // Each upload rides its deterministic seal1- key, never the caller's; a
    // crash-retry dedups on content, not on the caller's publish token.
    for (let index = 0; index < 2; index++) {
      const key = requestHeader(fetchMock, 1 + index, 'idempotency-key');
      expect(key).toBe(prepared.uploadIdempotencyKey(index));
      expect(key).not.toBe(callerKey);
    }
    // The publish carries exactly the caller's key.
    expect(requestHeader(fetchMock, 3, 'idempotency-key')).toBe(callerKey);
  });

  it('skips items covered by validated receipts', async () => {
    const prepared = deterministicPrepared(['first plaintext', 'second plaintext'], 1);
    const uriA = arUri('D');
    const uriB = arUri('E');
    const receipt = receiptFor(prepared, 0, uriA);
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uriB), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    const client = makeClient(fetchMock);

    const submission = await client.poe.submitSealed({ prepared, uploaded: [receipt] });

    // Only the uncovered item was uploaded — and it is the SECOND item.
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(await uploadedFileBytes(fetchMock, 1)).toEqual(prepared.items[1]!.ciphertext());
    // The resumed receipt keeps its slot in item order.
    expect(submission.uris).toEqual([uriA, uriB]);
    expect(submission.uploads[0]!.itemId).toBe(receipt.itemId);
    expect(submission.uploads[0]!.uri).toBe(uriA);
  });

  it('places a resumed non-zero-index receipt in its own record slot', async () => {
    const prepared = deterministicPrepared(['item zero', 'item one', 'item two'], 1);
    const uriZero = arUri('0');
    const uriOne = arUri('1');
    const uriTwo = arUri('2');
    // The receipt covers the MIDDLE item (index 1) — resuming only item 0
    // cannot tell correct placement apart from a receipts-first ordering.
    const receipt = receiptFor(prepared, 1, uriOne);
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uriZero), 200),
      jsonResponse(uploadSuccessBody(uriTwo), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    const client = makeClient(fetchMock);
    const submission = await client.poe.submitSealed({ prepared, uploaded: [receipt] });

    // Only items 0 and 2 upload, each under its own deterministic key.
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(await uploadedFileBytes(fetchMock, 1)).toEqual(prepared.items[0]!.ciphertext());
    expect(requestHeader(fetchMock, 1, 'idempotency-key')).toBe(prepared.uploadIdempotencyKey(0));
    expect(await uploadedFileBytes(fetchMock, 2)).toEqual(prepared.items[2]!.ciphertext());
    expect(requestHeader(fetchMock, 2, 'idempotency-key')).toBe(prepared.uploadIdempotencyKey(2));
    // The resumed receipt occupies the MIDDLE slot of the URI + receipt lists.
    expect(submission.uris).toEqual([uriZero, uriOne, uriTwo]);
    expect(submission.uploads[1]!.itemId).toBe(receipt.itemId);
    expect(submission.uploads[1]!.uri).toBe(uriOne);
  });

  it('rejects invalid receipts before any network call', async () => {
    const prepared = deterministicPrepared(['first plaintext'], 1);
    const goodDigest = sha256(prepared.items[0]!.ciphertext());
    const goodBytes = prepared.items[0]!.ciphertext().length;
    const cases: UploadReceipt[] = [
      // Unknown item id.
      { itemId: '00'.repeat(32), uri: 'ar://x', ciphertextSha256: goodDigest, bytes: goodBytes },
      // Digest mismatch.
      {
        itemId: prepared.items[0]!.itemId,
        uri: 'ar://x',
        ciphertextSha256: new Uint8Array(32),
        bytes: goodBytes,
      },
      // Byte-count mismatch.
      { itemId: prepared.items[0]!.itemId, uri: 'ar://x', ciphertextSha256: goodDigest, bytes: 1 },
      // Empty uri.
      {
        itemId: prepared.items[0]!.itemId,
        uri: '',
        ciphertextSha256: goodDigest,
        bytes: goodBytes,
      },
    ];
    for (const receipt of cases) {
      const fetchMock = queuedFetch([jsonResponse(freshQuoteBody('42'), 200)]);
      const client = makeClient(fetchMock);
      const err = await client.poe
        .submitSealed({ prepared, uploaded: [receipt] })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SubmitSealedError);
      expect((err as SubmitSealedError).uploads).toHaveLength(0);
      expect((err as SubmitSealedError).cause).toBeInstanceOf(InvalidUploadReceiptError);
      // The rejection is pre-network: no quote was spent.
      expect(fetchMock).not.toHaveBeenCalled();
    }
    // A duplicate receipt for the same item is rejected too.
    const fetchMock = queuedFetch([]);
    const client = makeClient(fetchMock);
    const duplicate = receiptFor(prepared, 0, 'ar://x');
    const err = await client.poe
      .submitSealed({ prepared, uploaded: [duplicate, duplicate] })
      .catch((e: unknown) => e);
    expect((err as SubmitSealedError).cause).toBeInstanceOf(InvalidUploadReceiptError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('enforces the price cap before uploading — bigint and decimal-string forms', async () => {
    const prepared = deterministicPrepared(['capped'], 1);
    for (const cap of [1_000_000n, '1000000'] as const) {
      const fetchMock = queuedFetch([jsonResponse(freshQuoteBody('1500000'), 200)]);
      const client = makeClient(fetchMock);
      const err = await client.poe
        .submitSealed({ prepared, maxUsdMicros: cap })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SubmitSealedError);
      const cause = (err as SubmitSealedError).cause;
      expect(cause).toBeInstanceOf(MaxUsdExceededError);
      expect((cause as MaxUsdExceededError).quotedUsdMicros).toBe('1500000');
      expect((cause as MaxUsdExceededError).maxUsdMicros).toBe(1_000_000n);
      expect((err as SubmitSealedError).uploads).toHaveLength(0);
      // Only the quote was requested; nothing was uploaded or published.
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
    // A non-integer cap string is a caller bug, rejected before any network.
    const fetchMock = queuedFetch([]);
    const client = makeClient(fetchMock);
    const err = await client.poe
      .submitSealed({ prepared, maxUsdMicros: '1.5' })
      .catch((e: unknown) => e);
    expect((err as SubmitSealedError).cause).toBeInstanceOf(PublishError);
    expect(((err as SubmitSealedError).cause as PublishError).code).toBe('INVALID_MAX_USD');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('caps against a fresh caller preview quote with no network traffic', async () => {
    const prepared = deterministicPrepared(['capped preview'], 1);
    // A fresh preview is consumed as the price lock without a quote request, so
    // the cap breach must be caught before anything is uploaded or published.
    // The internal-quote cap test above cannot exercise this consumption path.
    const pricey = quoteBody('preview-pricey', '1500000', FRESH_EXPIRY);
    const fetchMock = queuedFetch([]);
    const client = makeClient(fetchMock);
    const err = await client.poe
      .submitSealed({ prepared, quote: pricey, maxUsdMicros: 1_000_000n })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SubmitSealedError);
    const cause = (err as SubmitSealedError).cause;
    expect(cause).toBeInstanceOf(MaxUsdExceededError);
    expect((cause as MaxUsdExceededError).quotedUsdMicros).toBe('1500000');
    expect((cause as MaxUsdExceededError).maxUsdMicros).toBe(1_000_000n);
    expect((err as SubmitSealedError).uploads).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('consumes a fresh caller quote and silently replaces a stale one', async () => {
    const prepared = deterministicPrepared(['quoted'], 1);
    const uri = arUri('F');

    // A fresh preview is consumed as the price lock: no quote request goes
    // out, and the publish carries the preview's id.
    const fresh = quoteBody('preview-fresh', '42', FRESH_EXPIRY);
    let fetchMock = queuedFetch([
      jsonResponse(uploadSuccessBody(uri), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    let client = makeClient(fetchMock);
    const submission = await client.poe.submitSealed({ prepared, quote: fresh });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(requestJson(fetchMock, 1)['quote_id']).toBe('preview-fresh');
    expect(submission.quote.quote_id).toBe('preview-fresh');

    // A stale preview is silently replaced by a fresh internal quote.
    const stale = quoteBody('preview-stale', '42', STALE_EXPIRY);
    fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uri), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    client = makeClient(fetchMock);
    await client.poe.submitSealed({ prepared, quote: stale });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(requestJson(fetchMock, 2)['quote_id']).toBe(QUOTE_ID);
  });

  it('re-quotes after the uploads when the price lock expired, re-enforcing the cap', async () => {
    const prepared = deterministicPrepared(['slow upload'], 1);
    const uri = arUri('G');
    // The internal quote arrives already expired, so after the upload the
    // helper re-quotes and publishes against the SECOND lock.
    let fetchMock = queuedFetch([
      jsonResponse(quoteBody('lock-1', '42', STALE_EXPIRY), 200),
      jsonResponse(uploadSuccessBody(uri), 200),
      jsonResponse(quoteBody('lock-2', '42', FRESH_EXPIRY), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    let client = makeClient(fetchMock);
    const submission = await client.poe.submitSealed({ prepared });
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(requestJson(fetchMock, 3)['quote_id']).toBe('lock-2');
    expect(submission.quote.quote_id).toBe('lock-2');

    // The refreshed price is re-checked against the cap; a breach carries the
    // completed receipts so the paid upload is not lost.
    fetchMock = queuedFetch([
      jsonResponse(quoteBody('lock-1', '42', STALE_EXPIRY), 200),
      jsonResponse(uploadSuccessBody(uri), 200),
      jsonResponse(quoteBody('lock-2', '9000000', FRESH_EXPIRY), 200),
    ]);
    client = makeClient(fetchMock);
    const err = await client.poe
      .submitSealed({ prepared, maxUsdMicros: 1_000_000n })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SubmitSealedError);
    expect((err as SubmitSealedError).cause).toBeInstanceOf(MaxUsdExceededError);
    expect((err as SubmitSealedError).uploads).toHaveLength(1);
    expect((err as SubmitSealedError).uploads[0]!.uri).toBe(uri);
  });

  it('carries completed receipts through an upload failure, and the resume completes', async () => {
    const prepared = deterministicPrepared(['first plaintext', 'second plaintext'], 1);
    const uriA = arUri('D');

    // The first attempt uploads item 0, then fails on item 1's upload: the
    // error must hand back item 0's receipt.
    const failedUpload = {
      uploads: [
        {
          idx: 0,
          ok: false,
          error: { code: 'storage-provider-rejected', detail: 'arweave timeout' },
        },
      ],
    };
    let fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uriA), 200),
      jsonResponse(failedUpload, 200),
    ]);
    let client = makeClient(fetchMock);
    const err = await client.poe.submitSealed({ prepared }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SubmitSealedError);
    expect((err as SubmitSealedError).cause).toBeInstanceOf(PartialUploadError);
    const receipts = (err as SubmitSealedError).uploads;
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!.itemId).toBe(prepared.items[0]!.itemId);
    expect(receipts[0]!.uri).toBe(uriA);

    // The retry resumes from the carried receipts: item 0 is never
    // re-uploaded, only item 1 flows, and the publish completes.
    const uriB = arUri('E');
    fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uriB), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    client = makeClient(fetchMock);
    const submission = await client.poe.submitSealed({ prepared, uploaded: receipts });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(await uploadedFileBytes(fetchMock, 1)).toEqual(prepared.items[1]!.ciphertext());
    expect(submission.uris).toEqual([uriA, uriB]);
  });

  it('a publish failure also carries every receipt', async () => {
    const prepared = deterministicPrepared(['published'], 1);
    const uri = arUri('H');
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uri), 200),
      problemResponse(
        {
          code: 'insufficient-funds',
          status: 402,
          title: 'Payment Required',
          balance_usd_micros: '0',
          required_usd_micros: '180000',
        },
        402,
      ),
    ]);
    const client = makeClient(fetchMock);
    const err = await client.poe.submitSealed({ prepared }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SubmitSealedError);
    expect((err as SubmitSealedError).cause).toBeInstanceOf(InsufficientFundsError);
    expect((err as SubmitSealedError).uploads).toHaveLength(1);
    expect((err as SubmitSealedError).uploads[0]!.uri).toBe(uri);
  });
});

// =============================================================================
// One-shot wrapper
// =============================================================================

describe('publishSealed — one-shot wrapper', () => {
  it('encrypts to x25519 recipients, publishes, and the recipient can decrypt', async () => {
    const recipientSecret = new Uint8Array(32).fill(0x11);
    const pub = x25519PublicKey({ secretKey: recipientSecret });
    const uri = arUri('C');
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uri), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    const client = makeClient(fetchMock);

    const submission = await client.poe.publishSealed({
      items: [{ content: 'top-secret' }],
      recipients: [pub],
      // Explicit classical opt-out (the default is the hybrid KEM).
      kem: 'x25519',
    });

    expect(submission.response.id).toBe(PUBLISH_BODY.id);
    expect(submission.uris).toEqual([uri]);
    const capturedCiphertext = await uploadedFileBytes(fetchMock, 1);

    // The submitted record validates, references the real ar:// URI, and its
    // envelope decrypts back to the plaintext with the recipient secret.
    const validated = validatePoeRecord(submission.recordBytes);
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    const item = validated.record.items![0]!;
    expect(item.uris).toEqual([uri]);
    const envelope = item.enc as unknown as Record<string, unknown>;
    const unwrapped = eciesSealedPoeUnwrap({
      envelope: {
        scheme: envelope['scheme'] as 1,
        aead: envelope['aead'] as 'chacha20-poly1305-stream64k',
        kem: envelope['kem'] as 'x25519',
        nonce: envelope['nonce'] as Uint8Array,
        slots: envelope['slots'] as ReadonlyArray<{ epk: Uint8Array; wrap: Uint8Array }>,
        slots_mac: envelope['slots_mac'] as Uint8Array,
      },
      ciphertext: capturedCiphertext,
      hashes: item.hashes,
      recipientSecretKey: recipientSecret,
    });
    expect(unwrapped.matched).toBe(true);
    if (!unwrapped.matched) throw new Error('unreachable');
    expect(new TextDecoder().decode(unwrapped.plaintext)).toBe('top-secret');
  });

  it('defaults to the hybrid (mlkem768x25519) KEM and round-trips', async () => {
    const seed = new Uint8Array(32).fill(0x33);
    const { secretSeed, publicKey } = mlkem768x25519Keygen(seed);
    const uri = arUri('D');
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uri), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    const client = makeClient(fetchMock);

    // No `kem` passed → hybrid by default.
    const submission = await client.poe.publishSealed({
      items: [{ content: 'pq-secret' }],
      recipients: [publicKey],
    });

    const validated = validatePoeRecord(submission.recordBytes);
    expect(validated.valid).toBe(true);
    if (!validated.valid) throw new Error('unreachable');
    const item = validated.record.items![0]!;
    const envelope = item.enc as unknown as Record<string, unknown>;
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
      ciphertext: await uploadedFileBytes(fetchMock, 1),
      hashes: item.hashes,
      recipientSecretKey: secretSeed,
    });
    expect(unwrapped.matched).toBe(true);
    if (!unwrapped.matched) throw new Error('unreachable');
    expect(new TextDecoder().decode(unwrapped.plaintext)).toBe('pq-secret');
  });

  it('wraps a prepare rejection in SubmitSealedError with no network traffic', async () => {
    const fetchMock = queuedFetch([]);
    const client = makeClient(fetchMock);
    const err = await client.poe
      .publishSealed({ items: [{ content: 'x' }], recipients: [] })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SubmitSealedError);
    expect((err as SubmitSealedError).uploads).toHaveLength(0);
    expect((err as SubmitSealedError).cause).toBeInstanceOf(SealPrepareError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('free-function form works without the client wrapper', async () => {
    // The namespace method is sugar; the free function is the parity surface.
    const uri = arUri('E');
    const fetchMock = queuedFetch([
      jsonResponse(freshQuoteBody('42'), 200),
      jsonResponse(uploadSuccessBody(uri), 200),
      jsonResponse(PUBLISH_BODY, 202),
    ]);
    const submission = await publishSealed(
      {
        apiKey: 'opaque-bearer-token',
        baseUrl: 'https://cardanowall.com/api/v1',
        fetch: fetchMock as unknown as typeof globalThis.fetch,
      },
      { items: [{ content: 'free' }], recipients: x25519Recipients(1), kem: 'x25519' },
    );
    expect(submission.uris).toEqual([uri]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
