import { hkdfSha256 } from '../kdf/hkdf';
import { mlkem768x25519Keygen } from '../kem/mlkem768x25519';
import { x25519PublicKey } from '../kem/x25519';
import { getPublicKeyEd25519 } from '../sig/ed25519';

import { SeedDeriveError } from './errors';

// HKDF info constants for the long-term identity keypairs.
// These literal byte sequences are part of the on-wire protocol; every
// conformant implementation MUST hash against these exact ASCII bytes (the
// Python parity twin pins the identical labels).
export const INFO_ED25519: Uint8Array = new TextEncoder().encode('cardano-poe-ed25519-v1');
export const INFO_X25519: Uint8Array = new TextEncoder().encode('cardano-poe-x25519-v1');
export const INFO_MLKEM768X25519: Uint8Array = new TextEncoder().encode(
  'cardano-poe-mlkem768x25519-v1',
);

if (INFO_ED25519.length !== 22) {
  throw new Error('INFO_ED25519 byte-length invariant violated (expected 22)');
}
if (INFO_X25519.length !== 21) {
  throw new Error('INFO_X25519 byte-length invariant violated (expected 21)');
}
if (INFO_MLKEM768X25519.length !== 29) {
  throw new Error('INFO_MLKEM768X25519 byte-length invariant violated (expected 29)');
}

const EMPTY_SALT: Uint8Array = new Uint8Array(0);
const SEED_LENGTH = 32;
const DERIVED_LENGTH = 32;

export interface DerivedEd25519KeyPair {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface DerivedX25519KeyPair {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface DerivedMlKem768X25519KeyPair {
  readonly secretSeed: Uint8Array;
  readonly publicKey: Uint8Array;
}

function assertSeedLength(seed: Uint8Array): void {
  if (seed.length !== SEED_LENGTH) {
    throw new SeedDeriveError(
      'INVALID_SEED_LENGTH',
      `seed must be exactly 32 bytes, got ${seed.length}`,
    );
  }
}

export function deriveEd25519KeypairFromSeed(seed: Uint8Array): DerivedEd25519KeyPair {
  assertSeedLength(seed);
  const secretKey = hkdfSha256({
    ikm: seed,
    salt: EMPTY_SALT,
    info: INFO_ED25519,
    length: DERIVED_LENGTH,
  });
  const publicKey = getPublicKeyEd25519({ seed: secretKey });
  return { secretKey, publicKey };
}

export function deriveX25519KeypairFromSeed(seed: Uint8Array): DerivedX25519KeyPair {
  assertSeedLength(seed);
  const secretKey = hkdfSha256({
    ikm: seed,
    salt: EMPTY_SALT,
    info: INFO_X25519,
    length: DERIVED_LENGTH,
  });
  const publicKey = x25519PublicKey({ secretKey });
  return { secretKey, publicKey };
}

export function deriveMlKem768X25519KeypairFromSeed(
  seed: Uint8Array,
): DerivedMlKem768X25519KeyPair {
  assertSeedLength(seed);
  // The 32-byte HKDF output IS the X-Wing root seed: keygen re-expands the
  // ML-KEM coins and the X25519 scalar from it, so the derived keypair's
  // secretSeed equals this value.
  const xwingSeed = hkdfSha256({
    ikm: seed,
    salt: EMPTY_SALT,
    info: INFO_MLKEM768X25519,
    length: DERIVED_LENGTH,
  });
  return mlkem768x25519Keygen(xwingSeed);
}
