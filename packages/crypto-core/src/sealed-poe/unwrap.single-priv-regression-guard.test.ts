// Single-priv path regression guard.
//
// Structural over wallclock: the multi-priv iterator MUST NOT make the
// single-priv path (`previous_seeds: []`, never-rotated identity) pay any cost
// beyond its own inner loop. This is enforced as a structural code-path
// invariant (the multi-priv outer-loop counter stays untouched) plus a coarse
// wallclock smoke with 100× headroom over the "sub-millisecond per record"
// claim. The structural assertion is the load-bearing evidence; the smoke
// catches O(N²)/O(K²) regressions that the counter would miss.
//
// We assert structural counters rather than a wallclock baseline because
// wallclock thresholds are flaky under shared CI load; the same pattern is used
// in `unwrap.multipriv.perf.test.ts`.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { eciesSealedPoeUnwrap } from './unwrap';
import { type SealedEnvelope, type X25519Slot } from './wrap';

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
    envelope: {
      scheme: 1;
      aead: 'xchacha20-poly1305';
      kem: 'x25519';
      nonce_hex: string;
      slots: Array<{ epk_hex: string; wrap_hex: string }>;
      slots_mac_hex: string;
    };
    ciphertext_hex: string;
    expected_plaintext_hex: string;
  };
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
  aead: v.envelope.aead,
  kem: v.envelope.kem,
  nonce: hexToBytes(v.envelope.nonce_hex),
  slots,
  slots_mac: hexToBytes(v.envelope.slots_mac_hex),
};
const ciphertext = hexToBytes(v.ciphertext_hex);
const recipientSecretKey = hexToBytes(v.recipient_secrets_hex[0]!);
const expectedPlaintext = hexToBytes(v.expected_plaintext_hex);

describe('single-priv path stays unchanged after the multi-priv rework', () => {
  it('single-priv unwrap structural counter check (N=32; multi-priv outer counter MUST stay untouched)', () => {
    const slotsAttemptedOut = { count: 0 };
    const privsAttemptedOut = { count: 0 };
    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      recipientSecretKey,
      _slotsAttemptedOut: slotsAttemptedOut,
      _privsAttemptedOut: privsAttemptedOut,
    });
    expect(result.matched).toBe(true);
    if (!result.matched) throw new Error('unreachable');
    expect(Array.from(result.plaintext)).toEqual(Array.from(expectedPlaintext));
    // Constant-time-N preserved: every slot entered regardless of match position.
    expect(slotsAttemptedOut.count).toBe(32);
    // Multi-priv outer-loop counter is the seam introduced; the
    // single-priv path MUST NOT enter that loop. A non-zero value here
    // would indicate a refactor accidentally widened the single-priv path
    // into the multi-priv outer iteration.
    expect(privsAttemptedOut.count).toBe(0);
  });

  it(
    'single-priv N=32 unwrap stays under coarse wallclock ceiling — pathological regression guard',
    { timeout: 60000 },
    () => {
      // This is a pathological-regression guard, NOT a perf budget. The
      // structural counter assertion above is the load-bearing evidence; this
      // wallclock smoke catches O(N²)/O(K²) regressions that the counter would
      // miss. Threshold mirrors the perf-smoke pattern in
      // `unwrap.multipriv.perf.test.ts`: 100 iterations under 30s on commodity
      // hardware leaves ample headroom for CI-node noise.
      const iters = 100;
      const t0 = performance.now();
      for (let i = 0; i < iters; i++) {
        const res = eciesSealedPoeUnwrap({
          envelope,
          ciphertext,
          recipientSecretKey,
        });
        expect(res.matched).toBe(true);
      }
      const elapsed = performance.now() - t0;
      expect(elapsed).toBeLessThan(30000);
    },
  );
});
