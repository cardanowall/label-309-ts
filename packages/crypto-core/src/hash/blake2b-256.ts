import { blake2b } from '@noble/hashes/blake2.js';

export function blake2b256(input: Uint8Array): Uint8Array {
  return blake2b(input, { dkLen: 32 });
}

// CIP-19 stake-address derivation, used for the wallet path-2 signer binding,
// requires the 28-byte BLAKE2b digest of the signer's Ed25519 public key.
// The Cardano ledger encodes stake addresses as
//   `network_header_byte || Blake2b-224(stake_vk)`
// per CIP-19, so this output length is fixed by spec.
export function blake2b224(input: Uint8Array): Uint8Array {
  return blake2b(input, { dkLen: 28 });
}
