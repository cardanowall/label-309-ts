// Label 309 metadata-label-309 carriage: the whole-body chunk-array transport.
//
// The Cardano ledger caps every metadata byte string and text string at 64
// bytes, so a serialised record body crosses the ledger as an opaque
// whole-body chunk array: a definite-length CBOR array of definite-length
// byte strings of at most 64 bytes each, whose in-order concatenation is the
// canonical record-body bytes. This transport split is the ONLY chunking the
// format performs — fields inside the reassembled body are ordinary CBOR
// values with no per-field chunk wrappers and no 64-byte cap of their own.
//
// This module owns both directions of that transport:
//
//   - `chunkRecordBody`        — producer: canonical body bytes → the chunk
//                                array stored as the label-309 value.
//   - `reassembleLabel309Value`— consumer: raw label-309 value bytes → the
//                                record body, enforcing the carriage-error
//                                taxonomy (`MALFORMED_CBOR` for every
//                                non-chunk-array shape, `CHUNK_TOO_LARGE` for
//                                an oversized element, zero-length elements
//                                tolerated).
//
// Reassembly happens BEFORE structural validation: `validatePoeRecord`
// receives the concatenated body and never sees the transport wrapper.

import { decodeCanonicalCbor, encodeCanonicalCbor } from '@cardanowall/crypto-core/cbor';

import { SEVERITY, type ErrorCode } from './error-codes';
import type { ValidationIssue } from './validator';

/** The ledger's per-metadatum string cap: the maximum transport chunk size. */
export const TRANSPORT_CHUNK_MAX_BYTES = 64;

/**
 * Split a serialised record body into the whole-body transport chunk array —
 * the value a producer stores under metadata label 309.
 *
 * Uses the minimal split: every chunk except the last is exactly 64 bytes.
 * The chunk-array form is required regardless of body length, so a body of
 * 64 bytes or fewer still yields a one-element array. Chunks are copies — a
 * caller mutating the input body afterwards cannot corrupt them.
 *
 * A canonical CBOR record body is never empty, so zero-length input is a
 * caller bug and throws `RangeError` (the `1* bstr` transport grammar cannot
 * represent an empty body).
 */
export function chunkRecordBody(body: Uint8Array): Uint8Array[] {
  if (body.length === 0) {
    throw new RangeError('record body must be non-empty; a CBOR value is at least one byte');
  }
  const chunks: Uint8Array[] = [];
  for (let offset = 0; offset < body.length; offset += TRANSPORT_CHUNK_MAX_BYTES) {
    chunks.push(body.slice(offset, Math.min(offset + TRANSPORT_CHUNK_MAX_BYTES, body.length)));
  }
  return chunks;
}

/**
 * Serialise the transport chunk array to the CBOR bytes of the label-309
 * value (the byte form of `chunkRecordBody`'s output). Convenience for
 * producers and test harnesses that embed the value at the byte level.
 */
export function encodeLabel309Value(body: Uint8Array): Uint8Array {
  return encodeCanonicalCbor(chunkRecordBody(body));
}

export type Label309ReassemblyResult =
  | { readonly ok: true; readonly body: Uint8Array }
  | { readonly ok: false; readonly issue: ValidationIssue };

/**
 * Reassemble a label-309 value into the record body, enforcing the
 * carriage-error taxonomy:
 *
 *   - a definite-length array of definite-length byte strings each ≤ 64
 *     bytes is accepted; the body is the in-order concatenation;
 *   - zero-length elements are tolerated (chunk boundaries are
 *     semantics-free, including degenerate ones) — an array whose
 *     concatenation is empty reassembles to zero bytes, and the failure then
 *     surfaces from the canonical decode of the empty body, not from this
 *     layer;
 *   - an element longer than 64 bytes is `CHUNK_TOO_LARGE`;
 *   - every other shape — a non-array value, a non-byte-string element, an
 *     indefinite-length array or element — is `MALFORMED_CBOR`.
 *
 * The input is the raw CBOR bytes of the label-309 value exactly as carried
 * in the transaction's auxiliary data.
 */
export function reassembleLabel309Value(valueBytes: Uint8Array): Label309ReassemblyResult {
  let decoded: unknown;
  try {
    decoded = decodeCanonicalCbor(valueBytes);
  } catch (cause) {
    return failure(
      'MALFORMED_CBOR',
      `label-309 value failed to decode: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  if (!Array.isArray(decoded)) {
    return failure(
      'MALFORMED_CBOR',
      'label-309 value must be the whole-body chunk array (a CBOR array of byte strings), regardless of body length',
    );
  }
  let total = 0;
  for (let i = 0; i < decoded.length; i++) {
    const element: unknown = decoded[i];
    if (!(element instanceof Uint8Array)) {
      return failure('MALFORMED_CBOR', `chunk array element ${i} is not a byte string`);
    }
    if (element.length > TRANSPORT_CHUNK_MAX_BYTES) {
      return failure(
        'CHUNK_TOO_LARGE',
        `chunk array element ${i} is ${element.length} bytes; the ledger caps metadata byte strings at ${TRANSPORT_CHUNK_MAX_BYTES}`,
      );
    }
    total += element.length;
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const element of decoded as ReadonlyArray<Uint8Array>) {
    body.set(element, offset);
    offset += element.length;
  }
  return { ok: true, body };
}

function failure(code: ErrorCode, message: string): Label309ReassemblyResult {
  return { ok: false, issue: { code, path: [], message, severity: SEVERITY[code] } };
}
