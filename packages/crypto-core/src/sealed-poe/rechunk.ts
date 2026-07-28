// Async re-chunking onto the fixed 64 KiB STREAM grid, shared by the streaming
// sealed-PoE pairs (the KEM-slots pair in `stream-seal.ts` and the passphrase
// pair in `passphrase.ts`). A source `AsyncIterable` may hand over bytes in any
// sizes — its read boundaries are NOT the STREAM chunk boundaries — so both
// directions re-chunk with a one-block EOF lookahead: a full-size block is kept
// PENDING and only marked `final` once the next read proves end-of-input,
// because the STREAM final flag lives in the nonce and a final chunk may itself
// be full size. An exact multiple of the chunk size has NO trailing empty
// chunk; only a truly empty input is the single empty-final case.
//
// This module is internal to the sealed-poe package (not re-exported from its
// index): it exists so the two streaming pairs drive the exact same chunk
// machine rather than each carrying a copy of the lookahead logic.

import { CHUNK_SIZE, SEALED_CHUNK_SIZE, StreamTamperedError, TAG_SIZE } from './stream';

// Re-chunk an arbitrary-sized async byte stream into exactly-CHUNK_SIZE plaintext
// blocks with one-block EOF lookahead, yielding `final: true` only on the true
// last block. An exact multiple of CHUNK_SIZE ends on a full final block (no
// trailing empty chunk); a truly empty input yields one empty final block.
export async function* rechunkPlaintext(
  source: AsyncIterable<Uint8Array>,
  signal: AbortSignal | undefined,
): AsyncGenerator<{ chunk: Uint8Array; final: boolean }> {
  const acc = new Uint8Array(CHUNK_SIZE);
  let accLen = 0;
  // A completed full block awaiting its final/non-final verdict: it is non-final
  // iff any further block follows.
  let pending: Uint8Array | null = null;
  let emittedAny = false;

  for await (const raw of source) {
    signal?.throwIfAborted();
    let offset = 0;
    while (offset < raw.length) {
      const take = Math.min(CHUNK_SIZE - accLen, raw.length - offset);
      acc.set(raw.subarray(offset, offset + take), accLen);
      accLen += take;
      offset += take;
      if (accLen === CHUNK_SIZE) {
        if (pending !== null) {
          yield { chunk: pending, final: false };
          emittedAny = true;
        }
        pending = acc.slice(0, CHUNK_SIZE);
        accLen = 0;
      }
    }
  }
  signal?.throwIfAborted();

  if (accLen > 0) {
    // A short trailing block. Any pending full block precedes it, so it is
    // non-final; the short block is the final one.
    if (pending !== null) {
      yield { chunk: pending, final: false };
    }
    yield { chunk: acc.slice(0, accLen), final: true };
    emittedAny = true;
  } else if (pending !== null) {
    // Input was an exact multiple of CHUNK_SIZE: the last full block is final.
    yield { chunk: pending, final: true };
    emittedAny = true;
  }
  if (!emittedAny) {
    // Empty input → exactly one empty final chunk (a lone tag).
    yield { chunk: new Uint8Array(0), final: true };
  }
}

// Re-chunk an arbitrary-sized async ciphertext stream into SEALED_CHUNK_SIZE
// sealed blocks with one-block EOF lookahead. The final block is opened with
// `final: true` even when it is exactly SEALED_CHUNK_SIZE; a trailing sealed
// length of 1..15 (below the tag floor) or a totally empty stream is rejected
// here, before any tag is checked, mirroring the buffered `streamOpen` layout
// math.
export async function* rechunkSealed(
  source: AsyncIterable<Uint8Array>,
  signal: AbortSignal | undefined,
): AsyncGenerator<{ chunk: Uint8Array; final: boolean }> {
  const acc = new Uint8Array(SEALED_CHUNK_SIZE);
  let accLen = 0;
  let pending: Uint8Array | null = null;
  let sawAny = false;

  for await (const raw of source) {
    signal?.throwIfAborted();
    let offset = 0;
    while (offset < raw.length) {
      sawAny = true;
      const take = Math.min(SEALED_CHUNK_SIZE - accLen, raw.length - offset);
      acc.set(raw.subarray(offset, offset + take), accLen);
      accLen += take;
      offset += take;
      if (accLen === SEALED_CHUNK_SIZE) {
        if (pending !== null) {
          yield { chunk: pending, final: false };
        }
        pending = acc.slice(0, SEALED_CHUNK_SIZE);
        accLen = 0;
      }
    }
  }
  signal?.throwIfAborted();

  if (accLen > 0) {
    // A trailing partial sealed block. A full SEALED_CHUNK_SIZE block would have
    // moved to `pending`, so this is 1..SEALED_CHUNK_SIZE-1 bytes; anything below
    // the TAG_SIZE tag floor cannot form a well-formed final chunk.
    if (accLen < TAG_SIZE) {
      throw new StreamTamperedError('STREAM: trailing bytes cannot form a well-formed final chunk');
    }
    if (pending !== null) {
      yield { chunk: pending, final: false };
    }
    yield { chunk: acc.slice(0, accLen), final: true };
  } else if (pending !== null) {
    // Exact multiple of SEALED_CHUNK_SIZE: the last full sealed block is final.
    yield { chunk: pending, final: true };
  } else if (!sawAny) {
    // No bytes at all — below the single-tag floor.
    throw new StreamTamperedError('STREAM: ciphertext shorter than the single-tag floor');
  }
}
