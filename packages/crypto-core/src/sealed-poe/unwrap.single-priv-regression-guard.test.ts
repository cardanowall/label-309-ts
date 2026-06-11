// Single-priv path regression guard.
//
// Structural over wallclock: a never-rotated identity (one private key) MUST
// pay exactly one pass over the slot array — never a hidden multiple of it.
// This is enforced as a structural code-path invariant (the outer-loop counter
// reads exactly 1, the inner counter exactly N) plus a coarse wallclock smoke
// with large headroom. The structural assertion is the load-bearing evidence;
// the smoke catches O(N²)/O(K²) regressions that the counter would miss.
// Wallclock thresholds are deliberately coarse because tight baselines are
// flaky under shared CI load.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { eciesSealedPoeUnwrap } from './unwrap';
import { SEALED_POE_AEAD, type SealedEnvelope, type X25519Slot } from './wrap';
import type { ItemHashes } from './transcript';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

interface Fixture {
  vector: {
    recipient_secrets_hex: string[];
    hashes: Record<string, string>;
    envelope: {
      scheme: 1;
      aead: string;
      kem: 'x25519';
      nonce_hex: string;
      slots: Array<{ epk_hex: string; wrap_hex: string }>;
      slots_mac_hex: string;
    };
    ciphertext_hex: string;
    expected_plaintext_hex: string;
  };
}

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

const corpus = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, 'unwrap-n32.json'), 'utf8'),
) as Fixture;
const v = corpus.vector;
const slots: X25519Slot[] = v.envelope.slots.map((s) => ({
  epk: hexToBytes(s.epk_hex),
  wrap: hexToBytes(s.wrap_hex),
}));
const envelope: SealedEnvelope = {
  scheme: v.envelope.scheme,
  aead: v.envelope.aead as typeof SEALED_POE_AEAD,
  kem: v.envelope.kem,
  nonce: hexToBytes(v.envelope.nonce_hex),
  slots,
  slots_mac: hexToBytes(v.envelope.slots_mac_hex),
};
const ciphertext = hexToBytes(v.ciphertext_hex);
const recipientSecretKey = hexToBytes(v.recipient_secrets_hex[0]!);
const expectedPlaintext = hexToBytes(v.expected_plaintext_hex);

describe('single-priv path cost invariant', () => {
  it('single-priv unwrap performs exactly one outer pass over all N=32 slots', () => {
    const slotsAttemptedOut = { count: 0 };
    const privsAttemptedOut = { count: 0 };
    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: hashesFromHex(v.hashes),
      recipientSecretKey,
      _slotsAttemptedOut: slotsAttemptedOut,
      _privsAttemptedOut: privsAttemptedOut,
    });
    expect(result.matched).toBe(true);
    if (!result.matched) throw new Error('unreachable');
    expect(Array.from(result.plaintext)).toEqual(Array.from(expectedPlaintext));
    // Constant across slots: every slot entered regardless of match position.
    expect(slotsAttemptedOut.count).toBe(32);
    // Exactly ONE pass for a single key — a value above 1 means a refactor
    // made the single-priv form pay multi-key outer-loop cost.
    expect(privsAttemptedOut.count).toBe(1);
  });

  it(
    'single-priv N=32 unwrap stays under coarse wallclock ceiling — pathological regression guard',
    { timeout: 60000 },
    () => {
      // This is a pathological-regression guard, NOT a perf budget. The
      // structural counter assertion above is the load-bearing evidence; this
      // wallclock smoke catches O(N²)/O(K²) regressions that the counter would
      // miss. 100 iterations under 30s on commodity hardware leaves ample
      // headroom for CI-node noise.
      const hashes = hashesFromHex(v.hashes);
      const iters = 100;
      const t0 = performance.now();
      for (let i = 0; i < iters; i++) {
        const res = eciesSealedPoeUnwrap({
          envelope,
          ciphertext,
          hashes,
          recipientSecretKey,
        });
        expect(res.matched).toBe(true);
      }
      const elapsed = performance.now() - t0;
      expect(elapsed).toBeLessThan(30000);
    },
  );
});
