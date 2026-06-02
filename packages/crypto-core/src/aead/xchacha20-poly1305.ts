import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import { AeadVerificationError } from './errors';

export interface XChaCha20Poly1305EncryptOpts {
  readonly key: Uint8Array;
  readonly nonce: Uint8Array;
  readonly aad: Uint8Array;
  readonly plaintext: Uint8Array;
}

export interface XChaCha20Poly1305DecryptOpts {
  readonly key: Uint8Array;
  readonly nonce: Uint8Array;
  readonly aad: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export function xchacha20Poly1305Encrypt(opts: XChaCha20Poly1305EncryptOpts): Uint8Array {
  return xchacha20poly1305(opts.key, opts.nonce, opts.aad).encrypt(opts.plaintext);
}

export function xchacha20Poly1305Decrypt(opts: XChaCha20Poly1305DecryptOpts): Uint8Array {
  try {
    return xchacha20poly1305(opts.key, opts.nonce, opts.aad).decrypt(opts.ciphertext);
  } catch (cause) {
    throw new AeadVerificationError('xchacha20-poly1305 decrypt failed', { cause });
  }
}
