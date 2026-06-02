import { XWing } from '@noble/post-quantum/hybrid.js';

// X-Wing (ML-KEM-768 + X25519) hybrid KEM per draft-connolly-cfrg-xwing-kem-06.
// `XWing` is @noble/post-quantum's alias for `ml_kem768_x25519`. We expose it
// through opts-object wrappers that pin the wire lengths and map noble's field
// names onto the project's vocabulary.
//
// Unlike the bare X25519 KEM, there is no contributory-behaviour rejection to
// translate: X-Wing combines the ML-KEM and X25519 shared secrets through a
// SHA3-256 combiner that also binds the X25519 ephemeral and recipient public
// keys, and ML-KEM's implicit rejection already yields a constant-work
// pseudorandom secret on a malformed ciphertext. Decapsulation therefore never
// throws on attacker-supplied wire data — a wrong shared secret is the correct,
// indistinguishable failure mode, and callers MUST treat it as a non-match
// rather than expecting an exception.

export const MLKEM768X25519_PUBLIC_KEY_LENGTH = 1216 as const;
export const MLKEM768X25519_ENC_LENGTH = 1120 as const;
export const MLKEM768X25519_SHARED_SECRET_LENGTH = 32 as const;
export const MLKEM768X25519_SEED_LENGTH = 32 as const;
export const MLKEM768X25519_ESEED_LENGTH = 64 as const;

export interface Mlkem768X25519KeyPair {
  // The 32-byte root seed IS the secret key in draft-06: the ML-KEM coins and
  // the X25519 scalar are re-expanded from it via SHAKE-256 at decapsulation.
  readonly secretSeed: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface Mlkem768X25519EncapsulateOpts {
  readonly publicKey: Uint8Array;
  // Optional 64-byte encapsulation randomness (msgRand). When supplied the
  // ciphertext and shared secret are fully deterministic; a 32-byte value is
  // rejected by noble, so we pin the length here too.
  readonly eseed?: Uint8Array;
}

export interface Mlkem768X25519Encapsulation {
  readonly enc: Uint8Array;
  readonly ss: Uint8Array;
}

export interface Mlkem768X25519DecapsulateOpts {
  readonly secretSeed: Uint8Array;
  readonly enc: Uint8Array;
}

export function mlkem768x25519Keygen(seed: Uint8Array): Mlkem768X25519KeyPair {
  if (seed.length !== MLKEM768X25519_SEED_LENGTH) {
    throw new Error(
      `mlkem768x25519 seed must be ${MLKEM768X25519_SEED_LENGTH} bytes, got ${seed.length}`,
    );
  }
  const { secretKey, publicKey } = XWing.keygen(seed);
  return { secretSeed: secretKey, publicKey };
}

export function mlkem768x25519Encapsulate(
  opts: Mlkem768X25519EncapsulateOpts,
): Mlkem768X25519Encapsulation {
  if (opts.publicKey.length !== MLKEM768X25519_PUBLIC_KEY_LENGTH) {
    throw new Error(
      `mlkem768x25519 public key must be ${MLKEM768X25519_PUBLIC_KEY_LENGTH} bytes, got ${opts.publicKey.length}`,
    );
  }
  if (opts.eseed !== undefined && opts.eseed.length !== MLKEM768X25519_ESEED_LENGTH) {
    throw new Error(
      `mlkem768x25519 eseed must be ${MLKEM768X25519_ESEED_LENGTH} bytes, got ${opts.eseed.length}`,
    );
  }
  const { cipherText, sharedSecret } = XWing.encapsulate(opts.publicKey, opts.eseed);
  return { enc: cipherText, ss: sharedSecret };
}

export function mlkem768x25519Decapsulate(opts: Mlkem768X25519DecapsulateOpts): Uint8Array {
  // Pre-check both lengths before calling noble: decapsulation must perform a
  // constant amount of work for any caller-supplied ciphertext (implicit
  // rejection), which requires the inputs to be the exact expected sizes.
  if (opts.secretSeed.length !== MLKEM768X25519_SEED_LENGTH) {
    throw new Error(
      `mlkem768x25519 secret seed must be ${MLKEM768X25519_SEED_LENGTH} bytes, got ${opts.secretSeed.length}`,
    );
  }
  if (opts.enc.length !== MLKEM768X25519_ENC_LENGTH) {
    throw new Error(
      `mlkem768x25519 enc must be ${MLKEM768X25519_ENC_LENGTH} bytes, got ${opts.enc.length}`,
    );
  }
  // noble's signature is decapsulate(cipherText, secretKey) — ciphertext first.
  return XWing.decapsulate(opts.enc, opts.secretSeed);
}
