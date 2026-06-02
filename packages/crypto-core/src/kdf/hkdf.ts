import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export interface HkdfSha256Opts {
  readonly ikm: Uint8Array;
  readonly salt: Uint8Array;
  readonly info: Uint8Array;
  readonly length: number;
}

export function hkdfSha256(opts: HkdfSha256Opts): Uint8Array {
  return hkdf(sha256, opts.ikm, opts.salt, opts.info, opts.length);
}
