import { x25519 } from '@noble/curves/ed25519.js';

// RFC 7748 §6.1 contributory-behaviour rejection: a small-order (low-order)
// Montgomery `u` coordinate makes the X25519 shared secret all-zero, which
// @noble/curves refuses with `Error: invalid private or public key received`.
// We rethrow that as a *typed* error so callers can distinguish a structurally
// valid-but-malicious peer public key (a property of attacker-supplied wire
// data — trial-decrypt MUST treat the slot as a non-match, not crash) from
// genuine caller misuse such as a wrong-length key (which @noble raises as a
// RangeError and which we deliberately let propagate untouched).
export class X25519LowOrderPointError extends Error {
  readonly code = 'X25519_LOW_ORDER_POINT' as const;
  constructor(options?: { cause?: unknown }) {
    super('x25519 ECDH rejected: peer public key is a small-order point', options);
    this.name = 'X25519LowOrderPointError';
  }
}

// @noble/curves v2 signals a small-order/all-zero shared secret with this exact
// message. Matching on it (rather than the broad Error class) keeps unrelated
// failures — e.g. a future internal assertion — surfacing as themselves.
const NOBLE_LOW_ORDER_MESSAGE = 'invalid private or public key received';

export interface X25519KeyPair {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface X25519PublicKeyOpts {
  readonly secretKey: Uint8Array;
}

export interface X25519EcdhOpts {
  readonly secretKey: Uint8Array;
  readonly theirPublicKey: Uint8Array;
}

export function x25519Keygen(): X25519KeyPair {
  return x25519.keygen();
}

export function x25519PublicKey(opts: X25519PublicKeyOpts): Uint8Array {
  return x25519.getPublicKey(opts.secretKey);
}

export function x25519Ecdh(opts: X25519EcdhOpts): Uint8Array {
  try {
    return x25519.getSharedSecret(opts.secretKey, opts.theirPublicKey);
  } catch (e) {
    // Translate ONLY the contributory-check rejection into our typed error.
    // A wrong-length key throws a RangeError from @noble's length assertion;
    // that is caller misuse, not malicious wire data, so it must propagate.
    if (e instanceof Error && e.message === NOBLE_LOW_ORDER_MESSAGE) {
      throw new X25519LowOrderPointError({ cause: e });
    }
    throw e;
  }
}
