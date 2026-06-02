// Single source of truth for two seams that wrap, unwrap, and the wire encoder
// MUST agree on byte-for-byte:
//
//   1. How the 1120-byte X-Wing `enc` is split into the ≤ 64-byte byte-string
//      chunks the Cardano ledger requires (`kem_ct`), and the inverse join.
//   2. The canonical-CBOR serialization of the slot array that feeds slots_mac.
//
// Keeping both here means the producer (wrap) and the verifier (unwrap), as well
// as the downstream record encoder, cannot diverge on the bytes the MAC commits
// to — the single highest correctness risk for the hybrid branch, since a
// divergence would leave the ML-KEM ciphertext unauthenticated.

import { encodeCanonicalCbor, type CanonicalCborValue } from '../cbor/canonical';

import type { Mlkem768X25519Slot, X25519Slot } from './wrap';

// The envelope-level KEM discriminator.
export type SealedKem = 'x25519' | 'mlkem768x25519';

// Cardano ledger CDDL caps every `transaction_metadatum` byte string at 64
// bytes, so any value larger than 64 bytes is carried as an array of ≤ 64-byte
// chunks (the `bytes-chunk-array` wire form). This is the identical split rule
// the record encoder applies to chunked COSE bytes.
const CHUNK_MAX_BYTES = 64;

// Split a logical byte string into ≤ 64-byte chunks. Used for the X-Wing
// `enc` → `kem_ct` wire form. Subarrays are views over the input, never copies.
export function chunkKemCt(value: Uint8Array): Uint8Array[] {
  if (value.length === 0) {
    throw new Error('chunkKemCt: refusing to chunk an empty byte string');
  }
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < value.length; i += CHUNK_MAX_BYTES) {
    chunks.push(value.subarray(i, Math.min(i + CHUNK_MAX_BYTES, value.length)));
  }
  return chunks;
}

// Inverse of chunkKemCt: concatenate the chunked `kem_ct` back into the flat
// X-Wing `enc`. Performs NO length validation — the caller (unwrap) gates the
// reassembled length against MLKEM768X25519_ENC_LENGTH before any decapsulation.
export function joinKemCt(chunks: ReadonlyArray<Uint8Array>): Uint8Array {
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

// KEM-driven slot serialization for the slots_mac input.
//
//   • x25519:         each slot → { epk: bstr, wrap: bstr }
//   • mlkem768x25519: each slot → { kem_ct: [ bstr, ... ], wrap: bstr }
//
// The hybrid form uses the SAME chunked-array shape as the wire encoder, so the
// MAC commits to the ciphertext exactly as it appears on-chain. Returns the
// canonical-CBOR bytes ready for HMAC.
export function slotsToMacCbor(
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
  kem: SealedKem,
): Uint8Array {
  let value: CanonicalCborValue;
  if (kem === 'x25519') {
    value = (slots as ReadonlyArray<X25519Slot>).map((s) => ({ epk: s.epk, wrap: s.wrap }));
  } else {
    value = (slots as ReadonlyArray<Mlkem768X25519Slot>).map((s) => ({
      // Canonicalize the chunk boundaries before the MAC commits to them:
      // reassemble the logical ciphertext and re-split into canonical ≤ 64-byte
      // chunks. The on-wire `kem_ct` array is a transport detail (the Cardano
      // ledger's 64-byte metadatum cap), and a hostile or non-canonical chunking
      // ([1, 63, …] instead of [64, …]) reassembles to the SAME bytes — so the
      // MAC must be invariant to it. Committing to the verbatim wire chunks would
      // let an attacker re-chunk an honest envelope and break the slots_mac match
      // for an honest recipient. Honest (already-64B-chunked) records are
      // unchanged; a real byte flip still changes the reassembled bytes and is
      // still rejected.
      kem_ct: chunkKemCt(joinKemCt(s.kem_ct)),
      wrap: s.wrap,
    }));
  }
  return encodeCanonicalCbor(value);
}
