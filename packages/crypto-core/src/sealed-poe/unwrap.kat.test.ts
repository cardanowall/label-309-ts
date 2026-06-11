import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { x25519PublicKey } from '../kem/x25519';

import { EciesSealedPoeError, type EciesSealedPoeErrorCode } from './errors';
import { eciesSealedPoeTrialDecrypt, eciesSealedPoeUnwrap } from './unwrap';
import type { UnwrapFailureReason } from './unwrap';
import {
  eciesSealedPoeWrap,
  SEALED_POE_AEAD,
  type Mlkem768X25519Slot,
  type SealedEnvelope,
  type X25519Slot,
} from './wrap';
import type { ItemHashes } from './transcript';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../../tests/fixtures/sealed-poe');

// A fixture slot carries `epk_hex` on the classical path and a single flat
// `kem_ct_hex` on the hybrid path; the loader routes on field presence exactly
// like the reference generator.
interface SlotHex {
  epk_hex?: string;
  kem_ct_hex?: string;
  wrap_hex: string;
}

interface EnvelopeHex {
  scheme: 1 | number;
  aead: string;
  kem: 'x25519' | string;
  nonce_hex: string;
  slots: SlotHex[];
  slots_mac_hex: string;
}

interface UnwrapPositiveVector {
  name: string;
  recipient_secrets_hex: string[];
  hashes: Record<string, string>;
  envelope: EnvelopeHex;
  ciphertext_hex: string;
  expected_plaintext_hex: string;
}

interface UnwrapPositiveCorpus {
  version: number;
  primitive: string;
  source: string;
  vector: UnwrapPositiveVector;
}

interface MatchedFalseVector {
  name: string;
  envelope: EnvelopeHex;
  hashes: Record<string, string>;
  ciphertext_hex: string;
  recipient_secret_hex: string;
  expected_reason: UnwrapFailureReason;
}

interface RaiseVector {
  name: string;
  envelope: EnvelopeHex;
  hashes: Record<string, string>;
  ciphertext_hex: string;
  recipient_secret_hex: string;
  expected_error_code: EciesSealedPoeErrorCode;
}

interface UnwrapNegativeCorpus {
  version: number;
  primitive: string;
  source: string;
  matched_false_vectors: MatchedFalseVector[];
  raise_vectors: RaiseVector[];
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex ${hex.length}`);
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

function hashesFromHex(hashes: Record<string, string>): ItemHashes {
  return Object.fromEntries(Object.entries(hashes).map(([alg, hex]) => [alg, hexToBytes(hex)]));
}

function loadPositive(filename: string): UnwrapPositiveCorpus {
  return JSON.parse(
    fs.readFileSync(path.join(fixturesDir, filename), 'utf8'),
  ) as UnwrapPositiveCorpus;
}

function loadNegative(filename: string): UnwrapNegativeCorpus {
  return JSON.parse(
    fs.readFileSync(path.join(fixturesDir, filename), 'utf8'),
  ) as UnwrapNegativeCorpus;
}

function envelopeFromHex(env: EnvelopeHex): SealedEnvelope {
  if (env.kem === 'mlkem768x25519') {
    const slots: Mlkem768X25519Slot[] = env.slots.map((s) => ({
      kem_ct: hexToBytes(s.kem_ct_hex ?? ''),
      wrap: hexToBytes(s.wrap_hex),
    }));
    return {
      scheme: env.scheme as 1,
      aead: env.aead as typeof SEALED_POE_AEAD,
      kem: 'mlkem768x25519',
      nonce: hexToBytes(env.nonce_hex),
      slots,
      slots_mac: hexToBytes(env.slots_mac_hex),
    };
  }
  const slots: X25519Slot[] = env.slots.map((s) => ({
    epk: hexToBytes(s.epk_hex ?? ''),
    wrap: hexToBytes(s.wrap_hex),
  }));
  return {
    scheme: env.scheme as 1,
    aead: env.aead as typeof SEALED_POE_AEAD,
    kem: env.kem as 'x25519',
    nonce: hexToBytes(env.nonce_hex),
    slots,
    slots_mac: hexToBytes(env.slots_mac_hex),
  };
}

function checkPositive(corpus: UnwrapPositiveCorpus): void {
  const { vector } = corpus;
  const envelope = envelopeFromHex(vector.envelope);
  const ciphertext = hexToBytes(vector.ciphertext_hex);
  const hashes = hashesFromHex(vector.hashes);
  for (const privHex of vector.recipient_secrets_hex) {
    const result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      hashes,
      recipientSecretKey: hexToBytes(privHex),
    });
    expect(result.matched).toBe(true);
    if (result.matched) {
      expect(bytesToHex(result.plaintext)).toBe(vector.expected_plaintext_hex);
    }
  }
}

describe('sealed-poe unwrap — N=1 empty plaintext', () => {
  it('recovers plaintext byte-identical to wrap fixture', () => {
    checkPositive(loadPositive('unwrap-n1-empty.json'));
  });
});

describe('sealed-poe unwrap — N=3 32-byte plaintext', () => {
  it('recovers plaintext for every recipient priv', () => {
    checkPositive(loadPositive('unwrap-n3.json'));
  });
});

describe('sealed-poe unwrap — N=32 recipients', () => {
  it('recovers plaintext for every recipient priv', () => {
    checkPositive(loadPositive('unwrap-n32.json'));
  });
});

describe('sealed-poe unwrap — shadow slot before the honest slot (pinned vector)', () => {
  // Slot 0 wrap-opens under the recipient's key with an attacker-chosen CEK,
  // but that CEK does not reproduce slots_mac, so the per-slot acceptance fold
  // (kem_ok AND wrap_open_ok AND mac_ok) skips it and the honest slot 1 wins.
  // Accepting a slot on wrap-open success alone is non-conformant.
  interface ShadowSlotCorpus extends UnwrapPositiveCorpus {
    vector: UnwrapPositiveVector & { expected_matched_slot_idx: number };
  }

  it('decrypts under the honest CEK and selects the honest slot index', () => {
    const corpus = loadPositive('unwrap-shadow-slot.json') as ShadowSlotCorpus;
    checkPositive(corpus);

    const { vector } = corpus;
    const trial = eciesSealedPoeTrialDecrypt({
      envelope: envelopeFromHex(vector.envelope),
      hashes: hashesFromHex(vector.hashes),
      recipientSecretKeys: vector.recipient_secrets_hex.map(hexToBytes),
    });
    expect(trial.kind).toBe('match');
    if (trial.kind === 'match') {
      expect(trial.slotIdx).toBe(vector.expected_matched_slot_idx);
    }
  });
});

describe('sealed-poe unwrap — structured negative results', () => {
  const negative = loadNegative('unwrap-negative.json');
  // The multi-priv MAC-fail vector lives in the same fixture but
  // consumes the multi-priv API surface; it's exercised by
  // unwrap.multipriv.test.ts. Single-priv shape only here.
  const singlePrivMatchedFalse = negative.matched_false_vectors.filter(
    (v) => typeof v.recipient_secret_hex === 'string',
  );
  for (const v of singlePrivMatchedFalse) {
    it(`returns matched=false reason=${v.expected_reason} for ${v.name}`, () => {
      const result = eciesSealedPoeUnwrap({
        envelope: envelopeFromHex(v.envelope),
        ciphertext: hexToBytes(v.ciphertext_hex),
        hashes: hashesFromHex(v.hashes),
        recipientSecretKey: hexToBytes(v.recipient_secret_hex),
      });
      expect(result.matched).toBe(false);
      if (!result.matched) {
        expect(result.reason).toBe(v.expected_reason);
      }
    });
  }
});

describe('sealed-poe unwrap — input-validation EciesSealedPoeError codes', () => {
  const negative = loadNegative('unwrap-negative.json');
  // The multi-priv input-validation raise vectors live in the
  // same fixture but consume the multi-priv API surface; they are exercised
  // by unwrap.multipriv.test.ts. Skip them here (single-priv shape only).
  const singlePrivRaises = negative.raise_vectors.filter(
    (v) =>
      typeof v.recipient_secret_hex === 'string' &&
      !('recipient_secret_keys_hex' in (v as unknown as Record<string, unknown>)),
  );
  for (const v of singlePrivRaises) {
    it(`raises code=${v.expected_error_code} for ${v.name}`, () => {
      try {
        eciesSealedPoeUnwrap({
          envelope: envelopeFromHex(v.envelope),
          ciphertext: hexToBytes(v.ciphertext_hex),
          hashes: hashesFromHex(v.hashes),
          recipientSecretKey: hexToBytes(v.recipient_secret_hex),
        });
        throw new Error(`${v.name}: expected EciesSealedPoeError, got success`);
      } catch (err) {
        expect(err).toBeInstanceOf(EciesSealedPoeError);
        if (err instanceof EciesSealedPoeError) {
          expect(err.code).toBe(v.expected_error_code);
        }
      }
    });
  }
});

describe('sealed-poe unwrap — property: wrap then unwrap roundtrip N ∈ {1,3,32}', () => {
  it('recovers plaintext for every recipient across all N', () => {
    for (const n of [1, 3, 32] as const) {
      const recipientPrivs: Uint8Array[] = [];
      for (let i = 0; i < n; i++) {
        const priv = new Uint8Array(32);
        for (let j = 0; j < 32; j++) priv[j] = (0x10 + i * 3 + j) & 0xff;
        recipientPrivs.push(priv);
      }
      const recipientPublicKeys = recipientPrivs.map((priv) =>
        x25519PublicKey({ secretKey: priv }),
      );
      const plaintext = new TextEncoder().encode(`unwrap-property-N${String(n)}`);
      const hashes: ItemHashes = { 'sha2-256': sha256(plaintext) };
      const out = eciesSealedPoeWrap({ plaintext, hashes, recipientPublicKeys });
      for (const priv of recipientPrivs) {
        const res = eciesSealedPoeUnwrap({
          envelope: out.envelope,
          ciphertext: out.ciphertext,
          hashes,
          recipientSecretKey: priv,
        });
        expect(res.matched).toBe(true);
        if (res.matched) {
          expect(bytesToHex(res.plaintext)).toBe(bytesToHex(plaintext));
        }
      }
    }
  });
});

describe('sealed-poe unwrap — constant-across-slots iteration count', () => {
  const positive = loadPositive('unwrap-n32.json');

  it('enters all 32 slots regardless of match position', () => {
    const envelope = envelopeFromHex(positive.vector.envelope);
    const ciphertext = hexToBytes(positive.vector.ciphertext_hex);
    const hashes = hashesFromHex(positive.vector.hashes);
    const privs = positive.vector.recipient_secrets_hex.map(hexToBytes);
    // Test against three positions: 0, 15, 31 — different slots that should
    // all open in the N=32 fixture.
    for (const idx of [0, 15, 31]) {
      const slotsAttemptedOut = { count: 0 };
      const res = eciesSealedPoeUnwrap({
        envelope,
        ciphertext,
        hashes,
        recipientSecretKey: privs[idx]!,
        _slotsAttemptedOut: slotsAttemptedOut,
      });
      expect(res.matched).toBe(true);
      expect(slotsAttemptedOut.count).toBe(envelope.slots.length);
    }
  });
});
