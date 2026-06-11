import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { EciesSealedPoeError } from './errors';
import { eciesSealedPoeUnwrap, type UnwrapFailureReason } from './unwrap';
import { SEALED_POE_AEAD, type SealedEnvelope, type X25519Slot } from './wrap';
import type { ItemHashes } from './transcript';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

interface SlotHex {
  epk_hex: string;
  wrap_hex: string;
}

interface EnvelopeHex {
  scheme: 1;
  aead: string;
  kem: 'x25519';
  nonce_hex: string;
  slots: SlotHex[];
  slots_mac_hex: string;
}

interface MultiPrivCorpus {
  version: 1;
  primitive: string;
  source: string;
  vector: {
    name: string;
    recipient_privs_hex: string[];
    hashes: Record<string, string>;
    envelope: EnvelopeHex;
    ciphertext_hex: string;
    expected_plaintext_hex: string;
    expected_matching_priv_index: number | null;
    expected_outer_loop_count: number;
    expected_inner_loop_count_per_priv: number;
  };
}

interface NegativeMatchedFalseMultipriv {
  name: string;
  envelope: EnvelopeHex;
  hashes: Record<string, string>;
  ciphertext_hex: string;
  recipient_secret_keys_hex: string[];
  expected_reason: UnwrapFailureReason;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function envelopeFromHex(env: EnvelopeHex): SealedEnvelope {
  const slots: X25519Slot[] = env.slots.map((s) => ({
    epk: hexToBytes(s.epk_hex),
    wrap: hexToBytes(s.wrap_hex),
  }));
  return {
    scheme: env.scheme,
    aead: env.aead as typeof SEALED_POE_AEAD,
    kem: env.kem,
    nonce: hexToBytes(env.nonce_hex),
    slots,
    slots_mac: hexToBytes(env.slots_mac_hex),
  };
}

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

function loadMultipriv(filename: string): MultiPrivCorpus {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, filename), 'utf8')) as MultiPrivCorpus;
}

describe('sealed-poe unwrap — multi-priv current-match', () => {
  const corpus = loadMultipriv('unwrap-multipriv-current-match.json');
  const { vector } = corpus;
  const envelope = envelopeFromHex(vector.envelope);
  const ciphertext = hexToBytes(vector.ciphertext_hex);
  const privs = vector.recipient_privs_hex.map(hexToBytes);

  it('decrypts via the current (first) priv and exits after one outer iteration', () => {
    const slotsAttemptedOut = { count: 0, perPrivCounts: [] as number[] };
    const privsAttemptedOut = { count: 0 };
    const res = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: hashesFromHex(vector.hashes),
      recipientSecretKeys: privs,
      _slotsAttemptedOut: slotsAttemptedOut,
      _privsAttemptedOut: privsAttemptedOut,
    });
    expect(res.matched).toBe(true);
    if (res.matched) {
      expect(bytesToHex(res.plaintext)).toBe(vector.expected_plaintext_hex);
    }
    expect(privsAttemptedOut.count).toBe(vector.expected_outer_loop_count);
    expect(slotsAttemptedOut.count).toBe(vector.expected_inner_loop_count_per_priv);
  });
});

describe('sealed-poe unwrap — multi-priv archived-match', () => {
  const corpus = loadMultipriv('unwrap-multipriv-archived-match.json');
  const { vector } = corpus;
  const envelope = envelopeFromHex(vector.envelope);
  const ciphertext = hexToBytes(vector.ciphertext_hex);
  const privs = vector.recipient_privs_hex.map(hexToBytes);

  it('decrypts via priv index 2 after entering privs 0 and 1 first', () => {
    const slotsAttemptedOut = { count: 0, perPrivCounts: [] as number[] };
    const privsAttemptedOut = { count: 0 };
    const res = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: hashesFromHex(vector.hashes),
      recipientSecretKeys: privs,
      _slotsAttemptedOut: slotsAttemptedOut,
      _privsAttemptedOut: privsAttemptedOut,
    });
    expect(res.matched).toBe(true);
    if (res.matched) {
      expect(bytesToHex(res.plaintext)).toBe(vector.expected_plaintext_hex);
    }
    expect(privsAttemptedOut.count).toBe(vector.expected_outer_loop_count);
    expect(slotsAttemptedOut.perPrivCounts).toEqual([
      vector.expected_inner_loop_count_per_priv,
      vector.expected_inner_loop_count_per_priv,
      vector.expected_inner_loop_count_per_priv,
    ]);
  });
});

describe('sealed-poe unwrap — multi-priv no-match', () => {
  const corpus = loadMultipriv('unwrap-multipriv-no-match.json');
  const { vector } = corpus;
  const envelope = envelopeFromHex(vector.envelope);
  const ciphertext = hexToBytes(vector.ciphertext_hex);
  const privs = vector.recipient_privs_hex.map(hexToBytes);

  it('returns WRONG_RECIPIENT_KEY after exhausting all 4 privs', () => {
    const slotsAttemptedOut = { count: 0, perPrivCounts: [] as number[] };
    const privsAttemptedOut = { count: 0 };
    const res = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: hashesFromHex(vector.hashes),
      recipientSecretKeys: privs,
      _slotsAttemptedOut: slotsAttemptedOut,
      _privsAttemptedOut: privsAttemptedOut,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) {
      expect(res.reason).toBe<UnwrapFailureReason>('WRONG_RECIPIENT_KEY');
    }
    expect(privsAttemptedOut.count).toBe(vector.expected_outer_loop_count);
    expect(slotsAttemptedOut.perPrivCounts).toEqual([
      vector.expected_inner_loop_count_per_priv,
      vector.expected_inner_loop_count_per_priv,
      vector.expected_inner_loop_count_per_priv,
      vector.expected_inner_loop_count_per_priv,
    ]);
  });
});

// The test below asserts the derived 320 AEAD-attempts count via `.reduce`.
// The `expect(total).toBe(320)` line is the load-bearing assertion: worst-case
// trial-decrypt work is R × K = N × K_max = 32 × 10 = 320 inner iterations,
// guarding against an O(N²)/O(K²) regression in the multi-priv loop.
describe('sealed-poe unwrap — multi-priv worst-case N=32 K=10', () => {
  const corpus = loadMultipriv('unwrap-multipriv-n32-k10-worst-case.json');
  const { vector } = corpus;
  const envelope = envelopeFromHex(vector.envelope);
  const ciphertext = hexToBytes(vector.ciphertext_hex);
  const privs = vector.recipient_privs_hex.map(hexToBytes);

  it('enters all 10 privs and all 32 slots per priv (R × K = 320 AEAD attempts)', () => {
    const slotsAttemptedOut = { count: 0, perPrivCounts: [] as number[] };
    const privsAttemptedOut = { count: 0 };
    const res = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: hashesFromHex(vector.hashes),
      recipientSecretKeys: privs,
      _slotsAttemptedOut: slotsAttemptedOut,
      _privsAttemptedOut: privsAttemptedOut,
    });
    expect(res.matched).toBe(true);
    if (res.matched) {
      expect(bytesToHex(res.plaintext)).toBe(vector.expected_plaintext_hex);
    }
    expect(privsAttemptedOut.count).toBe(10);
    expect(slotsAttemptedOut.perPrivCounts.length).toBe(10);
    for (const c of slotsAttemptedOut.perPrivCounts) expect(c).toBe(32);
    const total = slotsAttemptedOut.perPrivCounts.reduce((a, b) => a + b, 0);
    // Evidence — derived R × K = 320 AEAD-attempt count.
    expect(total).toBe(320);
  });
});

describe('sealed-poe unwrap — multi-priv MAC fail returns TAMPERED_HEADER', () => {
  const corpus = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'unwrap-negative.json'), 'utf8'),
  ) as { matched_false_vectors: NegativeMatchedFalseMultipriv[] };
  const macFailVector = corpus.matched_false_vectors.find((v) => v.name === 'multipriv-mac-fail')!;

  it('returns TAMPERED_HEADER when slots_mac is tampered but a CEK was recovered', () => {
    const envelope = envelopeFromHex(macFailVector.envelope);
    const ciphertext = hexToBytes(macFailVector.ciphertext_hex);
    const privs = macFailVector.recipient_secret_keys_hex.map(hexToBytes);
    const res = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes: hashesFromHex(macFailVector.hashes),
      recipientSecretKeys: privs,
    });
    expect(res.matched).toBe(false);
    if (!res.matched) {
      expect(res.reason).toBe<UnwrapFailureReason>('TAMPERED_HEADER');
    }
  });
});

// Constant-across-slots matrix across (matching-priv, matching-slot)
// scenarios. Pins the per-priv `_slotsAttemptedOut.perPrivCounts[i] === N`
// invariant for every priv that entered the loop, independent of WHICH slot
// matched within that priv (the inner loop never short-circuits). The
// cross-priv variable-time channel (which priv matched) is an accepted,
// documented trade-off — this matrix asserts the within-priv invariant only.
describe('multi-priv constant-across-slots matrix (K=5, N=32)', () => {
  const SCENARIOS = [
    {
      filename: 'unwrap-multipriv-ac9-priv0-slot0.json',
      expectedOuter: 1,
      expectedPerPriv: [32],
      matched: true,
    },
    {
      filename: 'unwrap-multipriv-ac9-priv0-slot31.json',
      expectedOuter: 1,
      expectedPerPriv: [32],
      matched: true,
    },
    {
      filename: 'unwrap-multipriv-ac9-priv4-slot0.json',
      expectedOuter: 5,
      expectedPerPriv: [32, 32, 32, 32, 32],
      matched: true,
    },
    {
      filename: 'unwrap-multipriv-ac9-priv4-slot31.json',
      expectedOuter: 5,
      expectedPerPriv: [32, 32, 32, 32, 32],
      matched: true,
    },
    {
      filename: 'unwrap-multipriv-ac9-no-match.json',
      expectedOuter: 5,
      expectedPerPriv: [32, 32, 32, 32, 32],
      matched: false,
    },
  ] as const;

  for (const scenario of SCENARIOS) {
    it(`${scenario.filename} — perPrivCounts matches expected (${scenario.matched ? 'match' : 'no-match'})`, () => {
      const corpus = loadMultipriv(scenario.filename);
      const { vector } = corpus;
      const envelope = envelopeFromHex(vector.envelope);
      const ciphertext = hexToBytes(vector.ciphertext_hex);
      const privs = vector.recipient_privs_hex.map(hexToBytes);
      const slotsAttemptedOut = { count: 0, perPrivCounts: [] as number[] };
      const privsAttemptedOut = { count: 0 };
      const res = eciesSealedPoeUnwrap({
        envelope,
        ciphertext,
        hashes: hashesFromHex(vector.hashes),
        recipientSecretKeys: privs,
        _slotsAttemptedOut: slotsAttemptedOut,
        _privsAttemptedOut: privsAttemptedOut,
      });
      if (scenario.matched) {
        expect(res.matched).toBe(true);
        if (res.matched) {
          expect(bytesToHex(res.plaintext)).toBe(vector.expected_plaintext_hex);
        }
      } else {
        expect(res.matched).toBe(false);
        if (!res.matched) {
          expect(res.reason).toBe<UnwrapFailureReason>('WRONG_RECIPIENT_KEY');
        }
      }
      expect(privsAttemptedOut.count).toBe(scenario.expectedOuter);
      expect(slotsAttemptedOut.perPrivCounts).toEqual([...scenario.expectedPerPriv]);
    });
  }
});

describe('sealed-poe unwrap — multi-priv input-validation raises', () => {
  const positiveCorpus = loadMultipriv('unwrap-multipriv-current-match.json');
  const envelope = envelopeFromHex(positiveCorpus.vector.envelope);
  const ciphertext = hexToBytes(positiveCorpus.vector.ciphertext_hex);
  const validPriv = hexToBytes(positiveCorpus.vector.recipient_privs_hex[0]!);
  const HASHES: ItemHashes = { 'sha2-256': new Uint8Array(32) };

  it('raises INVALID_RECIPIENT_KEY for empty recipientSecretKeys', () => {
    expect(() =>
      eciesSealedPoeUnwrap({
        envelope,
        ciphertext,
        hashes: HASHES,
        recipientSecretKeys: [],
      }),
    ).toThrow(EciesSealedPoeError);
    try {
      eciesSealedPoeUnwrap({ envelope, ciphertext, hashes: HASHES, recipientSecretKeys: [] });
    } catch (err) {
      expect(err).toBeInstanceOf(EciesSealedPoeError);
      if (err instanceof EciesSealedPoeError) {
        expect(err.code).toBe('INVALID_RECIPIENT_KEY');
      }
    }
  });

  it('raises INVALID_RECIPIENT_KEY when both forms supplied', () => {
    try {
      eciesSealedPoeUnwrap({
        envelope,
        ciphertext,
        hashes: HASHES,
        recipientSecretKey: validPriv,
        recipientSecretKeys: [validPriv],
        // The discriminated-union surface forbids this at the type level; the
        // runtime check is what we're testing.
      } as unknown as Parameters<typeof eciesSealedPoeUnwrap>[0]);
      throw new Error('expected EciesSealedPoeError');
    } catch (err) {
      expect(err).toBeInstanceOf(EciesSealedPoeError);
      if (err instanceof EciesSealedPoeError) {
        expect(err.code).toBe('INVALID_RECIPIENT_KEY');
      }
    }
  });

  it('raises INVALID_RECIPIENT_KEY when neither form supplied', () => {
    try {
      eciesSealedPoeUnwrap({
        envelope,
        ciphertext,
        hashes: HASHES,
      } as unknown as Parameters<typeof eciesSealedPoeUnwrap>[0]);
      throw new Error('expected EciesSealedPoeError');
    } catch (err) {
      expect(err).toBeInstanceOf(EciesSealedPoeError);
      if (err instanceof EciesSealedPoeError) {
        expect(err.code).toBe('INVALID_RECIPIENT_KEY');
      }
    }
  });

  it('raises INVALID_RECIPIENT_KEY for wrong-length element in recipientSecretKeys', () => {
    const shortPriv = new Uint8Array(31).fill(0x11);
    try {
      eciesSealedPoeUnwrap({
        envelope,
        ciphertext,
        hashes: HASHES,
        recipientSecretKeys: [validPriv, shortPriv, validPriv],
      });
      throw new Error('expected EciesSealedPoeError');
    } catch (err) {
      expect(err).toBeInstanceOf(EciesSealedPoeError);
      if (err instanceof EciesSealedPoeError) {
        expect(err.code).toBe('INVALID_RECIPIENT_KEY');
      }
    }
  });
});
