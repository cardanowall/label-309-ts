// Permissive (non-canonical) CBOR decoder for outer wire decode (e.g. Cardano tx CBOR),
// where the input is not constrained to be canonical RFC 8949 §4.2.1 form.
//
// CIP-309 records themselves MUST be canonical and MUST go through
// `decodeCanonicalCbor`. This decoder
// exists to peel the outer Cardano tx structure ([body, witness_set, is_valid,
// auxiliary_data]) so the label-309 byte string can be re-encoded canonically
// for validator + signature verification.

import { decode } from 'cbor2';

export function decodeCbor(bytes: Uint8Array): unknown {
  return decode(bytes);
}
