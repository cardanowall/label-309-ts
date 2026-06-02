// CIP-30 / RFC 9052 §7 COSE_Key extraction for the Ed25519 sig path.
//
// CIP-30 wallets that don't put a 32-byte raw Ed25519 pubkey in the COSE_Sign1
// protected header instead deliver the signer key as a separate `cbor<COSE_Key>`
// blob, surfaced in the CIP-309 record under the top-level `signer_keys` field.
// This helper decodes one such blob and returns the underlying 32-byte Ed25519
// pubkey, or `null` when the blob is malformed, uses an unexpected key type /
// curve, or has the wrong `x` length.
//
// The expected COSE_Key shape (RFC 9053 §7.2 + RFC 8152 §13):
//   {
//     1 (kty): 1  // OKP
//     3 (alg): -8 // EdDSA — OPTIONAL but if present MUST be -8
//    -1 (crv): 6  // Ed25519
//    -2 (x):   <32 byte raw public key>
//   }

import { decodeCanonicalCbor } from '../cbor/canonical';

const COSE_KEY_LABEL_KTY = 1;
const COSE_KEY_LABEL_ALG = 3;
const COSE_KEY_LABEL_CRV = -1;
const COSE_KEY_LABEL_X = -2;

const KTY_OKP = 1;
const ALG_EDDSA = -8;
const CRV_ED25519 = 6;

const ED25519_PUBLIC_KEY_LENGTH = 32;

function asMap(value: unknown): Map<unknown, unknown> | null {
  if (value instanceof Map) return value as Map<unknown, unknown>;
  if (value !== null && typeof value === 'object' && (value as object).constructor === Object) {
    return new Map(Object.entries(value as Record<string, unknown>));
  }
  return null;
}

export function parseCoseKeyEd25519(blob: Uint8Array): Uint8Array | null {
  let decoded: unknown;
  try {
    decoded = decodeCanonicalCbor(blob);
  } catch {
    return null;
  }
  const map = asMap(decoded);
  if (map === null) return null;

  const kty = map.get(COSE_KEY_LABEL_KTY);
  if (typeof kty !== 'number' || kty !== KTY_OKP) return null;

  const crv = map.get(COSE_KEY_LABEL_CRV);
  if (typeof crv !== 'number' || crv !== CRV_ED25519) return null;

  if (map.has(COSE_KEY_LABEL_ALG)) {
    const alg = map.get(COSE_KEY_LABEL_ALG);
    if (typeof alg !== 'number' || alg !== ALG_EDDSA) return null;
  }

  const x = map.get(COSE_KEY_LABEL_X);
  if (!(x instanceof Uint8Array) || x.length !== ED25519_PUBLIC_KEY_LENGTH) return null;

  return x;
}
