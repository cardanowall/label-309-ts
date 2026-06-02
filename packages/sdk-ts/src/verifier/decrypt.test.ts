// Behaviour tests for the publicly-exported `tryDecryptions`, focused on the
// post-unwrap plaintext-hash recompute. A successful unwrap is only "hash-ok"
// when the item carries at least one recomputable content hash that matches —
// an empty or unknown-algorithm hashes map must NOT vacuously pass (that would
// certify ciphertext whose integrity was never checked, and it diverges from
// the CLI twin which returns UNSUPPORTED_HASH_ALG).

import { describe, expect, it } from 'vitest';

import { eciesSealedPoeWrap } from '@cardanowall/crypto-core/sealed-poe';
import { x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { sha256 } from '@cardanowall/crypto-core/hash';
import type { ItemEntry, PoeRecord } from '@cardanowall/poe-standard';

import { tryDecryptions } from './decrypt';
import type { FetchOutbound, HttpCallRecord, VerifyTxInput, VerifyUriCheck } from './types';

const NEVER_FETCH: FetchOutbound = async () => {
  throw new Error('tryDecryptions must not fetch when ciphertextBytes are supplied');
};

function makeSeed(byte: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

function sealedItemWithHashes(
  plaintext: Uint8Array,
  recipientPub: Uint8Array,
  hashes: Record<string, Uint8Array>,
): { record: PoeRecord; ciphertext: Uint8Array } {
  const wrapped = eciesSealedPoeWrap({ plaintext, recipientPublicKeys: [recipientPub] });
  const item = { hashes, enc: wrapped.envelope } as unknown as ItemEntry;
  const record = { v: 1, items: [item] } as unknown as PoeRecord;
  return { record, ciphertext: wrapped.ciphertext };
}

async function runDecrypt(
  record: PoeRecord,
  ciphertext: Uint8Array,
  recipientSecretKey: Uint8Array,
): Promise<ReturnType<typeof tryDecryptions>> {
  const httpCalls: HttpCallRecord[] = [];
  const uriChecksOut: VerifyUriCheck[] = [];
  const input: VerifyTxInput = {
    txHash: 'a'.repeat(64),
    decryption: [{ itemIndex: 0, recipientSecretKey }],
    ciphertextBytes: { 0: ciphertext },
  };
  return tryDecryptions({
    record,
    input,
    fetchFn: NEVER_FETCH,
    httpCalls,
    uriChecksOut,
    allowUriFetch: false,
  });
}

describe('tryDecryptions — plaintext-hash recompute', () => {
  const secret = makeSeed(40);
  const pub = x25519PublicKey({ secretKey: secret });
  const plaintext = new TextEncoder().encode('decrypt-me');

  it('plaintext_hash_ok=true when a matching sha2-256 hash is present', async () => {
    const { record, ciphertext } = sealedItemWithHashes(plaintext, pub, {
      'sha2-256': sha256(plaintext),
    });
    const { results } = await runDecrypt(record, ciphertext, secret);
    expect(results[0]?.verdict).toBe('decrypted');
    expect(results[0]?.plaintext_hash_ok).toBe(true);
  });

  it('plaintext_hash_ok=false on an EMPTY hashes map (no integrity check happened)', async () => {
    const { record, ciphertext } = sealedItemWithHashes(plaintext, pub, {});
    const { results } = await runDecrypt(record, ciphertext, secret);
    expect(results[0]?.verdict).toBe('decrypted');
    // The plaintext was recovered, but with nothing to check against the
    // integrity claim is unverified — must NOT report `true`.
    expect(results[0]?.plaintext_hash_ok).toBe(false);
  });

  it('plaintext_hash_ok=false on an UNKNOWN hash algorithm', async () => {
    const { record, ciphertext } = sealedItemWithHashes(plaintext, pub, {
      'sha3-512': sha256(plaintext),
    });
    const { results } = await runDecrypt(record, ciphertext, secret);
    expect(results[0]?.verdict).toBe('decrypted');
    expect(results[0]?.plaintext_hash_ok).toBe(false);
  });
});
