import { createSHA256, createBLAKE2b } from 'hash-wasm';

import { sha256 } from './sha-256';
import { blake2b256 } from './blake2b-256';

export interface DualHashOutput {
  sha256: Uint8Array;
  blake2b256: Uint8Array;
}

export function dualHash(input: Uint8Array): DualHashOutput {
  return {
    sha256: sha256(input),
    blake2b256: blake2b256(input),
  };
}

export async function dualHashStream(source: AsyncIterable<Uint8Array>): Promise<DualHashOutput> {
  const [sha, blake] = await Promise.all([createSHA256(), createBLAKE2b(256)]);
  sha.init();
  blake.init();
  for await (const chunk of source) {
    sha.update(chunk);
    blake.update(chunk);
  }
  return {
    sha256: sha.digest('binary') as Uint8Array,
    blake2b256: blake.digest('binary') as Uint8Array,
  };
}
