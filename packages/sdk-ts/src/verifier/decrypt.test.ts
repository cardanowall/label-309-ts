// Behaviour tests for the per-item decryption step (`decryptItem`): keyring
// dispatch on the on-wire key path, the post-decryption plaintext-hash
// recheck, and the failure taxonomy (WRONG_DECRYPTION_INPUT_SHAPE /
// WRONG_RECIPIENT_KEY / TAMPERED_CIPHERTEXT / CIPHERTEXT_UNAVAILABLE).
// Out-of-band ciphertext is attributable by definition, so every mismatch
// here is record-attributable.

import { describe, expect, it } from 'vitest';

import { sha256 } from '@cardanowall/crypto-core/hash';
import { x25519PublicKey } from '@cardanowall/crypto-core/kem';
import { eciesSealedPoeWrap, passphraseSealedPoeSeal } from '@cardanowall/crypto-core/sealed-poe';
import type { ItemEntry } from '@cardanowall/poe-standard';

import type { ContentFetchContext } from './content';
import { decryptItem } from './decrypt';
import { IssueSink } from './issues';
import type { FetchOutbound } from './types';

const NEVER_FETCH: FetchOutbound = async () => {
  throw new Error('decryptItem must not fetch when out-of-band ciphertext is supplied');
};

function makeSeed(byte: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

function mkCtx(): { ctx: ContentFetchContext; issues: IssueSink } {
  const issues = new IssueSink();
  return {
    ctx: {
      fetchFn: NEVER_FETCH,
      arweaveGateways: ['https://arweave.example'],
      ipfsGateways: [],
      issues,
    },
    issues,
  };
}

function sealedSlotsItem(
  plaintext: Uint8Array,
  recipientPub: Uint8Array,
  hashes: Record<string, Uint8Array>,
): { item: ItemEntry; ciphertext: Uint8Array } {
  const wrapped = eciesSealedPoeWrap({ plaintext, hashes, recipientPublicKeys: [recipientPub] });
  const env = wrapped.envelope;
  const slots =
    env.kem === 'mlkem768x25519'
      ? env.slots.map((s) => ({ kem_ct: s.kem_ct, wrap: s.wrap }))
      : env.slots.map((s) => ({ epk: s.epk, wrap: s.wrap }));
  const item = {
    hashes,
    enc: {
      scheme: env.scheme,
      aead: env.aead,
      kem: env.kem,
      nonce: env.nonce,
      slots,
      slots_mac: env.slots_mac,
    },
  } as unknown as ItemEntry;
  return { item, ciphertext: wrapped.ciphertext };
}

describe('decryptItem — slots path with out-of-band ciphertext', () => {
  const secret = makeSeed(40);
  const pub = x25519PublicKey({ secretKey: secret });
  const plaintext = new TextEncoder().encode('decrypt-me');

  it('decrypts and the plaintext-hash recheck passes', async () => {
    const { item, ciphertext } = sealedSlotsItem(plaintext, pub, {
      'sha2-256': sha256(plaintext),
    });
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ recipientSecretKey: secret }],
      outOfBandCiphertext: ciphertext,
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('checked');
    expect(result.decryption).toEqual({ decrypted: true, plaintextHashOk: true });
    expect(issues.sorted()).toEqual([]);
  });

  it('post-decryption hash mismatch → URI_INTEGRITY_MISMATCH, contentCheck mismatched', async () => {
    // The envelope binds the item's hashes map into the transcript, so the
    // slot accepts — but the committed digest is not the plaintext's digest,
    // and the post-decryption recheck condemns the record.
    const wrongDigest = new Uint8Array(32).fill(0xee);
    const { item, ciphertext } = sealedSlotsItem(plaintext, pub, { 'sha2-256': wrongDigest });
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ recipientSecretKey: secret }],
      outOfBandCiphertext: ciphertext,
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('mismatched');
    expect(result.decryption).toEqual({
      decrypted: true,
      plaintextHashOk: false,
      code: 'URI_INTEGRITY_MISMATCH',
    });
    expect(issues.sorted().map((i) => i.code)).toEqual(['URI_INTEGRITY_MISMATCH']);
  });

  it('every keyring credential is attempted independently (second key opens)', async () => {
    const { item, ciphertext } = sealedSlotsItem(plaintext, pub, {
      'sha2-256': sha256(plaintext),
    });
    const { ctx } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ recipientSecretKey: makeSeed(99) }, { recipientSecretKey: secret }],
      outOfBandCiphertext: ciphertext,
      fetchContent: false,
      ctx,
    });
    expect(result.decryption).toEqual({ decrypted: true, plaintextHashOk: true });
  });

  it('no slot accepts the key → WRONG_RECIPIENT_KEY', async () => {
    const { item, ciphertext } = sealedSlotsItem(plaintext, pub, {
      'sha2-256': sha256(plaintext),
    });
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ recipientSecretKey: makeSeed(99) }],
      outOfBandCiphertext: ciphertext,
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('not_checked');
    expect(result.decryption).toEqual({ decrypted: false, code: 'WRONG_RECIPIENT_KEY' });
    expect(issues.sorted().map((i) => i.code)).toEqual(['WRONG_RECIPIENT_KEY']);
  });

  it('tampered out-of-band blob (attributable) → TAMPERED_CIPHERTEXT, mismatched', async () => {
    const { item, ciphertext } = sealedSlotsItem(plaintext, pub, {
      'sha2-256': sha256(plaintext),
    });
    const tampered = new Uint8Array(ciphertext);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1]! + 1) & 0xff;
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ recipientSecretKey: secret }],
      outOfBandCiphertext: tampered,
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('mismatched');
    expect(result.decryption).toEqual({ decrypted: false, code: 'TAMPERED_CIPHERTEXT' });
    expect(issues.sorted().map((i) => i.code)).toEqual(['TAMPERED_CIPHERTEXT']);
  });

  it('keyring holds only passphrases → WRONG_DECRYPTION_INPUT_SHAPE', async () => {
    const { item, ciphertext } = sealedSlotsItem(plaintext, pub, {
      'sha2-256': sha256(plaintext),
    });
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ passphrase: 'inapplicable' }],
      outOfBandCiphertext: ciphertext,
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('not_checked');
    expect(result.decryption).toEqual({
      decrypted: false,
      code: 'WRONG_DECRYPTION_INPUT_SHAPE',
    });
    expect(issues.sorted().map((i) => i.code)).toEqual(['WRONG_DECRYPTION_INPUT_SHAPE']);
  });

  it('no out-of-band bytes, fetch suppressed → CIPHERTEXT_UNAVAILABLE', async () => {
    const { item } = sealedSlotsItem(plaintext, pub, { 'sha2-256': sha256(plaintext) });
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ recipientSecretKey: secret }],
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('not_checked');
    expect(result.decryption).toEqual({ decrypted: false, code: 'CIPHERTEXT_UNAVAILABLE' });
    expect(issues.sorted().map((i) => i.code)).toEqual(['CIPHERTEXT_UNAVAILABLE']);
  });
});

describe('decryptItem — passphrase path', () => {
  const plaintext = new TextEncoder().encode('passphrase sealed payload');
  const hashes = { 'sha2-256': sha256(plaintext) };
  // The registry floors; parallelism 1 keeps the suite fast.
  const params = { m: 65536, t: 3, p: 1 };
  const salt = new Uint8Array(16).fill(0x42);
  const passphrase = 'correct horse battery staple';

  async function passphraseItem(): Promise<{ item: ItemEntry; blob: Uint8Array }> {
    const sealed = await passphraseSealedPoeSeal({ plaintext, hashes, passphrase, salt, params });
    const env = sealed.envelope;
    const item = {
      hashes,
      enc: {
        scheme: env.scheme,
        aead: env.aead,
        nonce: env.nonce,
        passphrase: {
          alg: env.passphrase.alg,
          salt: env.passphrase.salt,
          params: env.passphrase.params,
        },
      },
    } as unknown as ItemEntry;
    return { item, blob: sealed.blob };
  }

  it('decrypts end-to-end with the matching passphrase', async () => {
    const { item, blob } = await passphraseItem();
    const { ctx } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ passphrase }],
      outOfBandCiphertext: blob,
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('checked');
    expect(result.decryption).toEqual({ decrypted: true, plaintextHashOk: true });
  });

  it('wrong passphrase → TAMPERED_CIPHERTEXT (single generic failure)', async () => {
    const { item, blob } = await passphraseItem();
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ passphrase: 'incorrect horse' }],
      outOfBandCiphertext: blob,
      fetchContent: false,
      ctx,
    });
    expect(result.contentCheck).toBe('mismatched');
    expect(result.decryption).toEqual({ decrypted: false, code: 'TAMPERED_CIPHERTEXT' });
    expect(issues.sorted().map((i) => i.code)).toEqual(['TAMPERED_CIPHERTEXT']);
  });

  it('keyring holds only recipient keys → WRONG_DECRYPTION_INPUT_SHAPE', async () => {
    const { item, blob } = await passphraseItem();
    const { ctx } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ recipientSecretKey: makeSeed(7) }],
      outOfBandCiphertext: blob,
      fetchContent: false,
      ctx,
    });
    expect(result.decryption).toEqual({
      decrypted: false,
      code: 'WRONG_DECRYPTION_INPUT_SHAPE',
    });
  });

  it('a whitespace-only passphrase → ENC_PASSPHRASE_EMPTY before any blob work', async () => {
    const { item, blob } = await passphraseItem();
    const { ctx, issues } = mkCtx();
    const result = await decryptItem({
      item,
      itemIndex: 0,
      credentials: [{ passphrase: '  　 ' }],
      outOfBandCiphertext: blob,
      fetchContent: false,
      ctx,
    });
    expect(result.decryption.decrypted).toBe(false);
    expect(result.decryption.code).toBe('ENC_PASSPHRASE_EMPTY');
    expect(issues.sorted().map((i) => i.code)).toEqual(['ENC_PASSPHRASE_EMPTY']);
  });
});
