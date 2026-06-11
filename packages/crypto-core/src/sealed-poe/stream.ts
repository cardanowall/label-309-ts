// chacha20-poly1305-stream64k: the segmented STREAM content format for sealed
// PoE (the age v1 STREAM layout).
//
//   cipher          : ChaCha20-Poly1305 (RFC 8439; 12-byte nonce, 16-byte tag)
//   chunk size      : 65536 plaintext bytes per non-final chunk
//   chunk nonce     : uint88_be(counter) || final_flag — counter starts at 0,
//                     +1 per chunk; final_flag is 0x01 on the final chunk,
//                     0x00 otherwise
//   per-chunk AAD   : empty (all context binds transitively through the
//                     payload_key, whose CEK is committed by slots_mac or the
//                     passphrase commitment header)
//   final chunk     : 0..65536 plaintext bytes; zero-length only when the whole
//                     plaintext is empty (an empty plaintext is exactly one
//                     zero-length final chunk — a lone 16-byte tag)
//
// The counter nonces are safe because the payload_key is single-use (a fresh
// CEK salted by the envelope-unique enc.nonce), so no two streams ever share a
// (key, nonce) pair. The final flag domain-separates the last chunk, which is
// what makes truncation detectable.
//
// Layout violations — a tag failure, a truncated stream, data after the final
// chunk, a non-final chunk shorter than CHUNK_SIZE, a zero-length final chunk
// on a non-empty stream — all surface as StreamTamperedError; the caller maps
// it to the single generic decryption failure. Each chunk's tag is verified
// before that chunk's plaintext is released, but the whole-plaintext hash
// recheck is post-hoc: incremental consumers MUST treat released bytes as
// tentative until it passes.

import { chacha20Poly1305Decrypt, chacha20Poly1305Encrypt } from '../aead/chacha20-poly1305';
import { AeadVerificationError } from '../aead/errors';

// Pinned format constants. The 88-bit counter admits at most 2^88 chunks, far
// above any realisable payload, so the format imposes no cryptographic payload
// ceiling — the practical maximum is a deployment denial-of-service policy, not
// a wire constant.
export const CHUNK_SIZE = 65536;
export const TAG_SIZE = 16;

const NONCE_LENGTH = 12;
const COUNTER_LENGTH = 11;
const SEALED_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE;
const PAYLOAD_KEY_LENGTH = 32;
const EMPTY_AAD: Uint8Array = new Uint8Array(0);

// Authenticated-decryption failure of the stream: a chunk tag did not verify or
// the chunk layout violates the format rules. Callers surface it as the single
// generic decryption failure (the TAMPERED_CIPHERTEXT outcome).
export class StreamTamperedError extends Error {
  readonly code = 'TAMPERED_CIPHERTEXT' as const;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'StreamTamperedError';
  }
}

// Shared chunk-nonce state machine: an 11-byte big-endian counter followed by
// the final-flag byte. The counter increments once per chunk; using a chunk
// machine after its final chunk is a caller error, never silently accepted.
class ChunkNonce {
  private readonly nonce = new Uint8Array(NONCE_LENGTH);
  private finished = false;

  next(final: boolean): Uint8Array {
    if (this.finished) {
      throw new Error('STREAM: no chunks may follow the final chunk');
    }
    if (final) {
      this.finished = true;
      this.nonce[COUNTER_LENGTH] = 0x01;
    }
    const out = this.nonce.slice();
    this.increment();
    return out;
  }

  get done(): boolean {
    return this.finished;
  }

  private increment(): void {
    for (let i = COUNTER_LENGTH - 1; i >= 0; i--) {
      const v = ((this.nonce[i] as number) + 1) & 0xff;
      this.nonce[i] = v;
      if (v !== 0) return;
    }
    // 2^88 chunks exhausted — unreachable for any realisable payload.
    throw new Error('STREAM: chunk counter overflow');
  }
}

function assertPayloadKey(payloadKey: Uint8Array): void {
  if (payloadKey.length !== PAYLOAD_KEY_LENGTH) {
    throw new Error(
      `STREAM: payloadKey MUST be exactly ${PAYLOAD_KEY_LENGTH} bytes, got ${payloadKey.length}`,
    );
  }
}

// Incremental sealer. Feed plaintext chunk by chunk: every non-final chunk MUST
// be exactly CHUNK_SIZE bytes; the final chunk carries 0..CHUNK_SIZE bytes, and
// a zero-length final chunk is admissible only as the sole chunk of an empty
// plaintext.
export class StreamSealer {
  private readonly payloadKey: Uint8Array;
  private readonly nonce = new ChunkNonce();
  private chunkIndex = 0;

  constructor(payloadKey: Uint8Array) {
    assertPayloadKey(payloadKey);
    this.payloadKey = payloadKey;
  }

  sealChunk(plaintext: Uint8Array, final: boolean): Uint8Array {
    if (!final && plaintext.length !== CHUNK_SIZE) {
      throw new Error(
        `STREAM: non-final chunk MUST carry exactly ${CHUNK_SIZE} plaintext bytes, got ${plaintext.length}`,
      );
    }
    if (final && plaintext.length > CHUNK_SIZE) {
      throw new Error(
        `STREAM: final chunk MUST carry at most ${CHUNK_SIZE} plaintext bytes, got ${plaintext.length}`,
      );
    }
    if (final && plaintext.length === 0 && this.chunkIndex > 0) {
      throw new Error(
        'STREAM: a zero-length final chunk is admissible only for an empty plaintext',
      );
    }
    const sealed = chacha20Poly1305Encrypt({
      key: this.payloadKey,
      nonce: this.nonce.next(final),
      aad: EMPTY_AAD,
      plaintext,
    });
    this.chunkIndex += 1;
    return sealed;
  }
}

// Incremental opener. Feed sealed chunks in order with the expected final flag;
// each chunk's plaintext is released only after its tag verifies (and is still
// tentative until the caller's whole-plaintext hash recheck passes). Chunk
// boundaries are the caller's responsibility in incremental use; `streamOpen`
// derives them from the blob length.
export class StreamOpener {
  private readonly payloadKey: Uint8Array;
  private readonly nonce = new ChunkNonce();
  private chunkIndex = 0;

  constructor(payloadKey: Uint8Array) {
    assertPayloadKey(payloadKey);
    this.payloadKey = payloadKey;
  }

  openChunk(sealedChunk: Uint8Array, final: boolean): Uint8Array {
    if (sealedChunk.length < TAG_SIZE) {
      throw new StreamTamperedError(
        `STREAM: sealed chunk shorter than the ${TAG_SIZE}-byte tag floor`,
      );
    }
    if (!final && sealedChunk.length !== SEALED_CHUNK_SIZE) {
      throw new StreamTamperedError(
        `STREAM: non-final sealed chunk MUST be exactly ${SEALED_CHUNK_SIZE} bytes, got ${sealedChunk.length}`,
      );
    }
    if (final && sealedChunk.length > SEALED_CHUNK_SIZE) {
      throw new StreamTamperedError(
        `STREAM: final sealed chunk MUST be at most ${SEALED_CHUNK_SIZE} bytes, got ${sealedChunk.length}`,
      );
    }
    if (final && sealedChunk.length === TAG_SIZE && this.chunkIndex > 0) {
      throw new StreamTamperedError('STREAM: zero-length final chunk on a non-empty stream');
    }
    let plaintext: Uint8Array;
    try {
      plaintext = chacha20Poly1305Decrypt({
        key: this.payloadKey,
        nonce: this.nonce.next(final),
        aad: EMPTY_AAD,
        ciphertext: sealedChunk,
      });
    } catch (e) {
      if (!(e instanceof AeadVerificationError)) throw e;
      throw new StreamTamperedError(`STREAM: chunk ${this.chunkIndex} tag verification failed`, {
        cause: e,
      });
    }
    this.chunkIndex += 1;
    return plaintext;
  }
}

// Whole-buffer seal: split the plaintext into CHUNK_SIZE chunks (an empty
// plaintext is exactly one zero-length final chunk) and concatenate the sealed
// chunks.
export function streamSeal(args: { payloadKey: Uint8Array; plaintext: Uint8Array }): Uint8Array {
  const { plaintext } = args;
  const sealer = new StreamSealer(args.payloadKey);
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  const out = new Uint8Array(plaintext.length + chunkCount * TAG_SIZE);
  let offset = 0;
  for (let i = 0; i < chunkCount; i++) {
    const final = i === chunkCount - 1;
    const chunk = plaintext.subarray(
      i * CHUNK_SIZE,
      Math.min((i + 1) * CHUNK_SIZE, plaintext.length),
    );
    const sealed = sealer.sealChunk(chunk, final);
    out.set(sealed, offset);
    offset += sealed.length;
  }
  return out;
}

// Whole-buffer open. The chunk boundaries are fully determined by the blob
// length: every non-final sealed chunk is exactly SEALED_CHUNK_SIZE bytes and
// the final sealed chunk is whatever remains (TAG_SIZE..SEALED_CHUNK_SIZE). A
// blob below the 16-byte floor, a tail that cannot form a well-formed final
// chunk, or a zero-length final chunk on a non-empty stream is malformed before
// any tag is checked. Truncation that removes the final chunk leaves a stream
// whose last chunk was sealed with the 0x00 flag but is opened with the 0x01
// flag nonce, so its tag fails — the final-flag byte is the truncation
// detector.
export function streamOpen(args: { payloadKey: Uint8Array; ciphertext: Uint8Array }): Uint8Array {
  const { ciphertext } = args;
  const total = ciphertext.length;
  if (total < TAG_SIZE) {
    throw new StreamTamperedError(
      `STREAM: ciphertext shorter than the ${TAG_SIZE}-byte single-tag floor`,
    );
  }
  const rem = total % SEALED_CHUNK_SIZE;
  let nonFinalCount: number;
  let finalSealedLength: number;
  if (rem === 0) {
    nonFinalCount = total / SEALED_CHUNK_SIZE - 1;
    finalSealedLength = SEALED_CHUNK_SIZE;
  } else if (rem >= TAG_SIZE) {
    nonFinalCount = (total - rem) / SEALED_CHUNK_SIZE;
    finalSealedLength = rem;
  } else {
    throw new StreamTamperedError('STREAM: trailing bytes cannot form a well-formed final chunk');
  }
  if (nonFinalCount > 0 && finalSealedLength === TAG_SIZE) {
    throw new StreamTamperedError('STREAM: zero-length final chunk on a non-empty stream');
  }

  const opener = new StreamOpener(args.payloadKey);
  const out = new Uint8Array(nonFinalCount * CHUNK_SIZE + finalSealedLength - TAG_SIZE);
  let readOffset = 0;
  let writeOffset = 0;
  for (let i = 0; i < nonFinalCount; i++) {
    const plaintext = opener.openChunk(
      ciphertext.subarray(readOffset, readOffset + SEALED_CHUNK_SIZE),
      false,
    );
    out.set(plaintext, writeOffset);
    readOffset += SEALED_CHUNK_SIZE;
    writeOffset += CHUNK_SIZE;
  }
  const finalPlaintext = opener.openChunk(ciphertext.subarray(readOffset), true);
  out.set(finalPlaintext, writeOffset);
  return out;
}
