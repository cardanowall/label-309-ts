// Encodes a raw KEM public key to a bech32 age-style recipient string — the
// form a sender uses to address a sealed PoE record.
//
//   • X25519 (32 bytes)                         → "age1…"
//   • X-Wing / ML-KEM-768 + X25519 (1216 bytes) → "age1pqc…"
//
// The two HRPs make a recipient self-describing: a parser routes to the right
// KEM purely from the bech32 prefix. We use the `age1pqc` HRP for the hybrid
// key (upstream age v1.3.0 claims the shorter `age1pq` HRP for the same X-Wing
// primitive; `age1pqc` avoids colliding with that wire identifier).
//
// The X-Wing public key derives for free from the same identity seed via
// `deriveMlKem768X25519KeypairFromSeed`, so every identity always has one and
// can RECEIVE hybrid sealed records even when it publishes via the classical
// X25519 path.

import { bech32DecodeNoLimit, bech32EncodeNoLimit } from './bech32';

const X25519_HRP = 'age';
const XWING_HRP = 'age1pqc';
const X25519_PUBLIC_KEY_BYTES = 32;
const XWING_PUBLIC_KEY_BYTES = 1216;

// The KEM a recipient string addresses, inferred from its bech32 HRP.
export type RecipientKem = 'x25519' | 'mlkem768x25519';

export interface ParsedAgeRecipient {
  readonly kem: RecipientKem;
  readonly publicKey: Uint8Array;
}

export function encodeAgeX25519Recipient(publicKey: Uint8Array): string {
  if (publicKey.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new Error('encodeAgeX25519Recipient: publicKey must be exactly 32 bytes');
  }
  return bech32EncodeNoLimit(X25519_HRP, publicKey);
}

export function encodeAgeXWingRecipient(publicKey: Uint8Array): string {
  if (publicKey.length !== XWING_PUBLIC_KEY_BYTES) {
    throw new Error('encodeAgeXWingRecipient: publicKey must be exactly 1216 bytes');
  }
  return bech32EncodeNoLimit(XWING_HRP, publicKey);
}

// Decode an age-style recipient string back to its raw KEM public key, routing
// on the bech32 HRP. The inverse of `encodeAgeX25519Recipient` /
// `encodeAgeXWingRecipient`: a sender can take a recipient string a peer shared
// and recover the exact public key (and which KEM it belongs to) needed to seal
// a record to them. Surrounding whitespace is tolerated so pasted strings parse.
// Throws on an unknown HRP, a bad checksum, or a key length that does not match
// the HRP's KEM.
export function parseAgeRecipient(recipient: string): ParsedAgeRecipient {
  if (typeof recipient !== 'string') {
    throw new Error('parseAgeRecipient: recipient must be a string');
  }
  const { hrp, bytes } = bech32DecodeNoLimit(recipient.trim());
  if (hrp === X25519_HRP) {
    if (bytes.length !== X25519_PUBLIC_KEY_BYTES) {
      throw new Error('parseAgeRecipient: age recipient must carry a 32-byte X25519 key');
    }
    return { kem: 'x25519', publicKey: bytes };
  }
  if (hrp === XWING_HRP) {
    if (bytes.length !== XWING_PUBLIC_KEY_BYTES) {
      throw new Error('parseAgeRecipient: age1pqc recipient must carry a 1216-byte X-Wing key');
    }
    return { kem: 'mlkem768x25519', publicKey: bytes };
  }
  throw new Error(`parseAgeRecipient: unrecognized recipient prefix "${hrp}"`);
}
