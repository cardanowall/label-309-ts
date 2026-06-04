import { cdeDecodeOptions, decode, encode } from 'cbor2';
import { sortCoreDeterministic } from 'cbor2/sorts';

import { CanonicalCborError } from './errors';

export type CanonicalCborValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | readonly CanonicalCborValue[]
  | { readonly [key: string]: CanonicalCborValue }
  | ReadonlyMap<string | number, CanonicalCborValue>;

export function encodeCanonicalCbor(value: CanonicalCborValue): Uint8Array {
  return encode(value, {
    cde: true,
    collapseBigInts: true,
    rejectDuplicateKeys: true,
    sortKeys: sortCoreDeterministic,
  });
}

export function decodeCanonicalCbor(bytes: Uint8Array): unknown {
  try {
    return decode(bytes, {
      ...cdeDecodeOptions,
      rejectStreaming: true,
      rejectDuplicateKeys: true,
      // A Label 309 record carries integers, byte/text strings, arrays, maps and
      // `null` — and nothing else. Without these rejections the major-type-7
      // surface leaks into the decoder: a float16/32/64 that happens to hold an
      // integral value (e.g. 1.0) silently decodes to the integer 1 and passes
      // a `z.literal(1)` / Number.isInteger schema check, so two byte strings
      // that are NOT byte-identical canonicalise to the same record. That
      // breaks the cross-implementation parity invariant (the Python twin
      // already rejects non-integer `v` / `enc.scheme` outright). Reject the
      // whole non-record surface — floats, negative zero, undefined, and
      // non-{true,false,null} simple values — so any such input surfaces as
      // MALFORMED_CBOR via mapDecodeError rather than decoding to a look-alike.
      rejectFloats: true,
      rejectNegativeZero: true,
      rejectUndefined: true,
      rejectSimple: true,
    });
  } catch (cause) {
    throw mapDecodeError(cause);
  }
}

function mapDecodeError(cause: unknown): CanonicalCborError {
  const message = cause instanceof Error ? cause.message : String(cause);
  const lower = message.toLowerCase();
  // Every canonical-decode violation collapses to the single public taxonomy
  // code MALFORMED_CBOR: indefinite-length (streaming) items, duplicate keys,
  // non-canonical (unsorted) key ordering, non-minimal integer encodings, and
  // invalid UTF-8 in text strings. cbor2 raises the SAME "Duplicate or out of
  // order key" message for both true duplicates AND distinct-but-unsorted keys,
  // so the two are indistinguishable by message — and per the Label 309 taxonomy
  // both belong under MALFORMED_CBOR anyway. The specific cause survives in the
  // human-readable message below; for indefinite-length we state it explicitly
  // so the diagnostic is not lost when the code is collapsed.
  const isIndefinite = lower.includes('streaming') || lower.includes('indefinite');
  const detail = isIndefinite
    ? `indefinite-length items are not permitted in canonical CBOR: ${message}`
    : message;
  return new CanonicalCborError('MALFORMED_CBOR', `cbor decode failed: ${detail}`, { cause });
}
