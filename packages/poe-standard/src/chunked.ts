// Label 309 v1 chunked-bytes and chunked-text helpers.
//
// The Cardano ledger CDDL constrains every `transaction_metadatum` byte string
// (`bstr`) and text string (`tstr`) to ≤ 64 bytes. Label 309 therefore carries
// any logical value larger than 64 bytes as an ARRAY of ≤ 64-byte chunks. Two
// chunked shapes exist:
//
//   * `bytes-chunk-array` — `[ 1* bstr .size (1..64) ]` — used for chunked
//     `COSE_Sign1` bytes (`sigs[i].cose_sign1`) and the chunked
//     `cbor<COSE_Key>` blob (`sigs[i].cose_key`).
//   * `uri-chunk-array` — `[ 1* tstr .size (1..64) ]` — used as the inner
//     element of `items[i].uris` and `merkle[i].uris`.
//
// Two reconstruction invariants are normative:
//
//   1. **Per-chunk size.** `[1, 64]` bytes (zero-length chunks rejected
//      identically to oversized chunks). The validator's schema layer enforces
//      this; the helpers here assume the schema gate has fired.
//   2. **UTF-8 codepoint integrity (text only).** The reconstructed
//      concatenation MUST be valid UTF-8. The canonical-CBOR decoder already
//      rejects any `tstr` that is not valid UTF-8 (→ `MALFORMED_CBOR`) before
//      these helpers run, so each chunk arrives as a well-formed string; the
//      `TextDecoder({ fatal: true })` pass below is the residual structural
//      guard.

const CHUNK_MAX_BYTES = 64;

const UTF8_ENCODER = new TextEncoder();

/**
 * Split a logical byte string into ≤ 64-byte CBOR-bytes chunks
 * (`bytes-chunk-array`). Always returns a non-empty array.
 *
 * For empty inputs, returns `[<empty>]` so the caller's schema gate fails
 * later via `CHUNK_TOO_LARGE` (zero-length chunks are rejected). Real callers
 * feed COSE_Sign1 / cbor<COSE_Key> byte strings, which are never empty.
 */
export function chunkBytes(value: Uint8Array): Uint8Array[] {
  if (value.length === 0) return [new Uint8Array(0)];
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < value.length; i += CHUNK_MAX_BYTES) {
    chunks.push(value.subarray(i, Math.min(i + CHUNK_MAX_BYTES, value.length)));
  }
  return chunks;
}

/**
 * Reverse of {@link chunkBytes}: concatenate chunked bytes (`sigs[i].cose_sign1`,
 * `sigs[i].cose_key`) into a single buffer for downstream CBOR/COSE decode.
 * The validator-layer schema enforces the per-chunk size + non-empty-array
 * invariants before this helper runs, so it makes no length checks.
 */
export function bytesChunkArrayConcat(chunks: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export type ReconstructUriResult =
  | { ok: true; uri: string }
  | { ok: false; code: 'INVALID_URI'; reason: string };

/**
 * Reconstruct a chunked URI (`uri-chunk-array`) into its logical string.
 *
 * The chunks arrive as JS strings produced by the canonical-CBOR decoder,
 * which already rejects any non-UTF-8 `tstr` (surfacing it upstream as
 * `MALFORMED_CBOR`) — so by the time this helper runs the only structural
 * task left is to byte-concatenate and decode. We re-encode each chunk to its
 * UTF-8 bytes, concatenate, and decode the whole with `{ fatal: true }`. A
 * conformant producer never splits a multi-byte codepoint across chunks (the
 * Cardano 64-byte cap is applied on codepoint boundaries), so this decode
 * succeeds for every well-formed record; the `INVALID_URI` branch is the
 * residual guard for a byte sequence that does not reconstruct to valid UTF-8.
 *
 * Per-scheme shape validation (the IPFS CID profile) and absolute-URI /
 * fragment-identifier / scheme-set checks fire in `validator.ts`, NOT here —
 * this helper is structural-only.
 */
export function reconstructChunkedUri(chunks: ReadonlyArray<string>): ReconstructUriResult {
  const merged = bytesChunkArrayConcat(chunks.map((c) => UTF8_ENCODER.encode(c)));
  try {
    const uri = new TextDecoder('utf-8', { fatal: true }).decode(merged);
    return { ok: true, uri };
  } catch (cause) {
    return {
      ok: false,
      code: 'INVALID_URI',
      reason: cause instanceof Error ? cause.message : String(cause),
    };
  }
}

/**
 * Chunk a URI string into `[ tstr .size (1..64) ]`, splitting on UTF-8 byte
 * boundaries so no multi-byte codepoint straddles a chunk.
 *
 * For pure-ASCII URIs (the common `ar://`, `ipfs://` cases) this collapses
 * to plain 64-byte byte-slice chunks. For URIs with non-ASCII path components
 * (rare but possible — RFC 3986 §2.5 IRIs / percent-encoded UTF-8) the
 * algorithm rewinds to the nearest codepoint boundary at each chunk break.
 */
export function chunkUri(uri: string): string[] {
  const bytes = UTF8_ENCODER.encode(uri);
  if (bytes.length === 0) return [''];
  if (bytes.length <= CHUNK_MAX_BYTES) return [uri];
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const chunks: string[] = [];
  let cursor = 0;
  while (cursor < bytes.length) {
    let end = Math.min(cursor + CHUNK_MAX_BYTES, bytes.length);
    // Rewind to the start of the previous UTF-8 codepoint if we landed in
    // the middle of a multibyte sequence. UTF-8 continuation bytes match
    // 0b10xx_xxxx; rewind while the byte at `end` is a continuation.
    while (end < bytes.length && (bytes[end]! & 0xc0) === 0x80) end--;
    chunks.push(decoder.decode(bytes.subarray(cursor, end)));
    cursor = end;
  }
  return chunks;
}
