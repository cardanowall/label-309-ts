import { createSHA256 } from 'hash-wasm';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

export function sha256(input: Uint8Array): Uint8Array {
  return nobleSha256(input);
}

/**
 * Stream a source through an incremental SHA-256 and return the 32-byte digest,
 * never holding more than one chunk in memory. Use this when the input is too
 * large to buffer (a multi-gigabyte file read in slices), where `sha256(input)`
 * would force the whole input into a single array first.
 */
export async function sha256Stream(source: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const hasher = await createSHA256();
  hasher.init();
  for await (const chunk of source) {
    hasher.update(chunk);
  }
  return hasher.digest('binary') as Uint8Array;
}
