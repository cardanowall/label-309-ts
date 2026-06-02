// Coarse smoke against pathological algorithmic regression — NOT a perf
// budget. Runs the N=32, K=10 worst-case fixture 100 times and asserts the
// total elapsed time stays under a generous ceiling. Measured Node 24 +
// @noble v2 throughput is ~150ms per record (~15s for this loop); the
// ceiling sits several times above that so the test catches O((R×K)²) and
// similar gross blow-ups (which would run 10×+ slower) while tolerating the
// CPU contention a parallel test run inflicts. The exact-correctness
// evidence lives in the structural counter assertions in
// unwrap.multipriv.test.ts — this file only guards the cost curve.

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

describe('sealed-poe unwrap — multi-priv worst-case coarse perf smoke', () => {
  it(
    '100 iterations of N=32, K=10 worst case finishes in < 60000ms total',
    // Generous-but-bounded: ~15s typical, so 60s tolerates heavy host load
    // while still flagging an order-of-magnitude algorithmic regression.
    { timeout: 90000 },
    () => {
      const corpus = JSON.parse(
        fs.readFileSync(path.join(fixturesDir, 'unwrap-multipriv-n32-k10-worst-case.json'), 'utf8'),
      ) as {
        vector: {
          recipient_privs_hex: string[];
          envelope: {
            scheme: 1;
            aead: 'xchacha20-poly1305';
            kem: 'x25519';
            nonce_hex: string;
            slots: { epk_hex: string; wrap_hex: string }[];
            slots_mac_hex: string;
          };
          ciphertext_hex: string;
        };
      };
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
      const privs = v.recipient_privs_hex.map(hexToBytes);

      const start = performance.now();
      for (let i = 0; i < 100; i++) {
        const res = eciesSealedPoeUnwrap({
          envelope,
          ciphertext,
          recipientSecretKeys: privs,
        });
        expect(res.matched).toBe(true);
      }
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(60000);
    },
  );
});
