// Behaviour tests for the publicly-exported `tryDecryptions`, focused on the
// post-unwrap plaintext-hash recompute. A successful unwrap is only "hash-ok"
// when the item carries at least one recomputable content hash that matches —
// an empty or unknown-algorithm hashes map must NOT vacuously pass (that would
// certify ciphertext whose integrity was never checked, and it diverges from
// the CLI twin which returns UNSUPPORTED_HASH_ALG).

import { describe, expect, it } from 'vitest';

import {
  adContentPassphrase,
  eciesSealedPoeWrap,
  passphrasePayloadKey,
} from '@cardanowall/crypto-core/sealed-poe';
import { x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { argon2idV13 } from '@cardanowall/crypto-core/kdf';
import { xchacha20Poly1305Encrypt } from '@cardanowall/crypto-core/aead';
import { sha256 } from '@cardanowall/crypto-core/hash';
import type { ItemEntry, PoeRecord } from '@cardanowall/poe-standard';

import {
  MAX_PASSPHRASE_INPUT_BYTES,
  normalizePassphrase,
  tryDecryptions,
  UNICODE_WHITE_SPACE,
} from './decrypt';
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

// ---------------------------------------------------------------------------
// Passphrase path.
//
// These build a passphrase-path ciphertext from the same crypto-core primitives
// the producer uses — Argon2id-derived CEK, the passphrase content `payload_key`
// via HKDF, the structured AD_CONTENT_PASSPHRASE AAD, then XChaCha20-Poly1305 —
// and exercise the public `tryDecryptions` passphrase branch end to end.
// Cost-minimal Argon2id params (m=8, t=1, p=1) keep the suite fast; they sit
// below the producer-side floor the validator enforces, but the verifier itself
// does not re-enforce that floor, so the round-trip math is unaffected.
// ---------------------------------------------------------------------------

function buildPassphraseCiphertext(args: {
  passphrase: string;
  salt: Uint8Array;
  m: number;
  t: number;
  p: number;
  nonce: Uint8Array;
  plaintext: Uint8Array;
}): Promise<Uint8Array> {
  return (async () => {
    const { passphrase, salt, m, t, p, nonce, plaintext } = args;
    const cek = await argon2idV13({
      password: normalizePassphrase(passphrase),
      salt,
      memSizeKB: m,
      iterations: t,
      parallelism: p,
      outBytes: 32,
    });
    const payloadKey = passphrasePayloadKey({ cek, nonce });
    const aad = adContentPassphrase({
      nonce,
      passphrase: { alg: 'argon2id', salt, params: { m, t, p } },
    });
    return xchacha20Poly1305Encrypt({ key: payloadKey, nonce, aad, plaintext });
  })();
}

function passphraseRecord(args: {
  hashes: Record<string, Uint8Array>;
  nonce: Uint8Array;
  salt: Uint8Array;
  m: number;
  t: number;
  p: number;
}): PoeRecord {
  const item = {
    hashes: args.hashes,
    enc: {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      nonce: args.nonce,
      passphrase: {
        alg: 'argon2id',
        salt: args.salt,
        params: { m: args.m, t: args.t, p: args.p },
      },
    },
  } as unknown as ItemEntry;
  return { v: 1, items: [item] } as unknown as PoeRecord;
}

async function runPassphraseDecrypt(
  record: PoeRecord,
  ciphertext: Uint8Array,
  passphrase: string,
): Promise<ReturnType<typeof tryDecryptions>> {
  const httpCalls: HttpCallRecord[] = [];
  const uriChecksOut: VerifyUriCheck[] = [];
  const input: VerifyTxInput = {
    txHash: 'b'.repeat(64),
    decryption: [{ itemIndex: 0, passphrase }],
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

function fillBytes(byte: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(byte);
  return out;
}

describe('tryDecryptions — passphrase path', () => {
  it('round-trips: correct passphrase decrypts and the content hash matches', async () => {
    const plaintext = new TextEncoder().encode('passphrase-encrypted message');
    const passphrase = 'correct horse battery staple';
    const salt = fillBytes(0x42, 16);
    const nonce = fillBytes(0x00, 24);
    const ciphertext = await buildPassphraseCiphertext({
      passphrase,
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 1,
      p: 1,
    });
    const { results } = await runPassphraseDecrypt(record, ciphertext, passphrase);
    expect(results[0]?.verdict).toBe('decrypted');
    expect(results[0]?.plaintext_hash_ok).toBe(true);
  });

  it('wrong passphrase surfaces tampered-ciphertext (AEAD cannot tell the two apart)', async () => {
    const plaintext = new TextEncoder().encode('secret');
    const salt = fillBytes(0xaa, 16);
    const nonce = fillBytes(0x00, 24);
    const ciphertext = await buildPassphraseCiphertext({
      passphrase: 'right',
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 1,
      p: 1,
    });
    const { results } = await runPassphraseDecrypt(record, ciphertext, 'wrong');
    // On the passphrase path a wrong passphrase derives a wrong CEK; the AEAD
    // tag check fails identically to a tampered ciphertext, so the verdict is
    // the generic tampered-ciphertext.
    expect(results[0]?.verdict).toBe('tampered-ciphertext');
    expect(results[0]?.reason).toBe('TAMPERED_CIPHERTEXT');
  });

  it('AAD tamper on salt: an altered on-record salt makes the AEAD open fail', async () => {
    const plaintext = new TextEncoder().encode('aad binds salt');
    const passphrase = 'battery horse staple';
    const sealSalt = fillBytes(0x11, 16);
    const nonce = fillBytes(0x00, 24);
    const ciphertext = await buildPassphraseCiphertext({
      passphrase,
      salt: sealSalt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    // The record presents a DIFFERENT salt than the one the ciphertext was
    // sealed under: both the Argon2id-derived CEK and the AAD change, so the
    // open fails — indistinguishable from a tampered ciphertext.
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt: fillBytes(0x22, 16),
      m: 8,
      t: 1,
      p: 1,
    });
    const { results } = await runPassphraseDecrypt(record, ciphertext, passphrase);
    expect(results[0]?.verdict).toBe('tampered-ciphertext');
    expect(results[0]?.reason).toBe('TAMPERED_CIPHERTEXT');
  });

  it('AAD tamper on params: an altered on-record params value makes the AEAD open fail', async () => {
    const plaintext = new TextEncoder().encode('aad binds params');
    const passphrase = 'correct horse';
    const salt = fillBytes(0x33, 16);
    const nonce = fillBytes(0x00, 24);
    // Seal under params (m=8, t=1, p=1).
    const ciphertext = await buildPassphraseCiphertext({
      passphrase,
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    // Present params with t bumped: Argon2id derives a different CEK AND the AAD
    // differs — either way the open fails generically.
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 2,
      p: 1,
    });
    const { results } = await runPassphraseDecrypt(record, ciphertext, passphrase);
    expect(results[0]?.verdict).toBe('tampered-ciphertext');
    expect(results[0]?.reason).toBe('TAMPERED_CIPHERTEXT');
  });

  it('normalization equivalence: exotic-whitespace passphrase variants decrypt the canonical ciphertext', async () => {
    const canonical = 'alpha beta gamma';
    const plaintext = new TextEncoder().encode('whitespace-normalized passphrase');
    const salt = fillBytes(0x44, 16);
    const nonce = fillBytes(0x00, 24);
    const ciphertext = await buildPassphraseCiphertext({
      passphrase: canonical,
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 1,
      p: 1,
    });

    // Variants that all normalize to "alpha beta gamma": a leading NBSP
    // (U+00A0), a tab+space run between alpha/beta, an ideographic space
    // (U+3000) between beta/gamma, a NEL (U+0085), and trailing spaces. Each
    // must open the same ciphertext.
    const variants = [
      ' alpha beta gamma',
      'alpha \t beta　gamma',
      'alphabeta gamma',
      'alpha beta gamma   ',
      '  \talpha \tbeta　gamma \r\n',
    ];
    for (const variant of variants) {
      expect(normalizePassphrase(variant)).toEqual(normalizePassphrase(canonical));
      const { results } = await runPassphraseDecrypt(record, ciphertext, variant);
      expect(results[0]?.verdict).toBe('decrypted');
      expect(results[0]?.plaintext_hash_ok).toBe(true);
    }
  });

  it('U+200B is NOT White_Space and is preserved, so a passphrase carrying it fails to decrypt', async () => {
    const canonical = 'alpha beta gamma';
    const plaintext = new TextEncoder().encode('zero-width is not whitespace');
    const salt = fillBytes(0x55, 16);
    const nonce = fillBytes(0x00, 24);
    const ciphertext = await buildPassphraseCiphertext({
      passphrase: canonical,
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 1,
      p: 1,
    });
    // U+200B ZERO WIDTH SPACE does NOT carry the White_Space property, so it is
    // preserved rather than collapsed: the derived CEK differs from canonical.
    const withZeroWidth = 'alpha​ beta gamma';
    expect(normalizePassphrase(withZeroWidth)).not.toEqual(normalizePassphrase(canonical));
    const { results } = await runPassphraseDecrypt(record, ciphertext, withZeroWidth);
    expect(results[0]?.verdict).toBe('tampered-ciphertext');
    expect(results[0]?.reason).toBe('TAMPERED_CIPHERTEXT');
  });
});

describe('tryDecryptions — pre-KDF passphrase length cap', () => {
  // The cap is enforced on the raw UTF-8 byte length BEFORE normalization and
  // Argon2id, so an oversized passphrase cannot drive unbounded pre-KDF work.
  const salt = fillBytes(0x42, 16);
  const nonce = fillBytes(0x00, 24);
  const plaintext = new TextEncoder().encode('cap test');

  it('pins the cap constant at 4096 UTF-8 bytes', () => {
    expect(MAX_PASSPHRASE_INPUT_BYTES).toBe(4096);
  });

  it('rejects a passphrase whose raw byte length exceeds the cap (kdf-failed)', async () => {
    const oversized = 'a'.repeat(MAX_PASSPHRASE_INPUT_BYTES + 1); // 4097 ASCII bytes
    const ciphertext = await buildPassphraseCiphertext({
      passphrase: oversized,
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 1,
      p: 1,
    });
    const { results } = await runPassphraseDecrypt(record, ciphertext, oversized);
    expect(results[0]?.verdict).toBe('kdf-failed');
    expect(results[0]?.reason).toContain('KDF_DERIVATION_FAILED');
  });

  it('accepts a passphrase exactly at the cap', async () => {
    const atCap = 'a'.repeat(MAX_PASSPHRASE_INPUT_BYTES); // 4096 ASCII bytes
    const ciphertext = await buildPassphraseCiphertext({
      passphrase: atCap,
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 1,
      p: 1,
    });
    const { results } = await runPassphraseDecrypt(record, ciphertext, atCap);
    expect(results[0]?.verdict).toBe('decrypted');
    expect(results[0]?.plaintext_hash_ok).toBe(true);
  });

  it('measures bytes not code points: a short multi-byte string over the byte cap is rejected', async () => {
    // U+1F680 (rocket) is 4 UTF-8 bytes per code point. 1025 of them = 4100
    // bytes but only 1025 code points — well under any char-count limit, over
    // the byte cap.
    const rocket = '\u{1F680}';
    const multiByteOverCap = rocket.repeat(1025);
    expect([...multiByteOverCap].length).toBeLessThan(MAX_PASSPHRASE_INPUT_BYTES);
    expect(new TextEncoder().encode(multiByteOverCap).length).toBeGreaterThan(
      MAX_PASSPHRASE_INPUT_BYTES,
    );
    const ciphertext = await buildPassphraseCiphertext({
      passphrase: multiByteOverCap,
      salt,
      m: 8,
      t: 1,
      p: 1,
      nonce,
      plaintext,
    });
    const record = passphraseRecord({
      hashes: { 'sha2-256': sha256(plaintext) },
      nonce,
      salt,
      m: 8,
      t: 1,
      p: 1,
    });
    const { results } = await runPassphraseDecrypt(record, ciphertext, multiByteOverCap);
    expect(results[0]?.verdict).toBe('kdf-failed');
    expect(results[0]?.reason).toContain('KDF_DERIVATION_FAILED');
  });
});

describe('tryDecryptions — cross-path input shape', () => {
  it('passphrase request against a sealed-recipient (slots) item surfaces WRONG_DECRYPTION_INPUT_SHAPE', async () => {
    const plaintext = new TextEncoder().encode('x');
    const secret = makeSeed(70);
    const pub = x25519PublicKey({ secretKey: secret });
    const { record, ciphertext } = sealedItemWithHashes(plaintext, pub, {
      'sha2-256': sha256(plaintext),
    });
    const httpCalls: HttpCallRecord[] = [];
    const uriChecksOut: VerifyUriCheck[] = [];
    const input: VerifyTxInput = {
      txHash: 'c'.repeat(64),
      decryption: [{ itemIndex: 0, passphrase: 'anything' }],
      ciphertextBytes: { 0: ciphertext },
    };
    const { results } = await tryDecryptions({
      record,
      input,
      fetchFn: NEVER_FETCH,
      httpCalls,
      uriChecksOut,
      allowUriFetch: false,
    });
    expect(results[0]?.verdict).toBe('wrong-input-shape');
    expect(results[0]?.reason).toBe('WRONG_DECRYPTION_INPUT_SHAPE');
  });
});

describe('normalizePassphrase — White_Space property set', () => {
  it('pins the membership to exactly the 25 Unicode 16.0 White_Space codepoints', () => {
    // The producer and every verifier must collapse exactly this set; a regex
    // `\s` class or a language `isWhitespace` predicate matches a different set,
    // which would derive a different CEK from the same passphrase and break
    // cross-implementation decryption. Pinned the same way the Python twin pins
    // its frozenset.
    const expected = [
      0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680, 0x2000, 0x2001,
      0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
      0x202f, 0x205f, 0x3000,
    ];
    expect(expected.length).toBe(25);
    expect([...UNICODE_WHITE_SPACE].sort((a, b) => a - b)).toEqual(expected);
    // U+200B ZERO WIDTH SPACE must NOT be a member.
    expect(UNICODE_WHITE_SPACE.has(0x200b)).toBe(false);
  });

  it('collapses a maximal run of mixed White_Space to a single U+0020 and trims', () => {
    const typed = '\t alpha \tbeta　gamma \r\n';
    expect(normalizePassphrase(typed)).toEqual(new TextEncoder().encode('alpha beta gamma'));
  });
});
