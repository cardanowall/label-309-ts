// Secret-safety regression: no SDK-produced value that holds a recipient
// private key or a passphrase surfaces the secret through its string form. A
// `String(...)`, a `console.log` (Node `util.inspect`), an error chain, or a
// `JSON.stringify` dump must never leak the key bytes, the passphrase, or the
// sealed plaintext. Mirrors the Rust reference's redacting `Debug` on the
// sealed/verifier secret-bearing types.

import { inspect } from 'node:util';

import { describe, expect, it } from 'vitest';

import { passphraseSealPrepare } from '../client/sealed';
import { bytesToHex } from '../hex';

import { deriveKeysFromSeed, recipientKeyBundleFromSeed } from './seed-identity';

const SEED = new Uint8Array(32).fill(0xad);

describe('recipientKeyBundleFromSeed redacts the recipient private keys', () => {
  const keys = deriveKeysFromSeed(SEED);
  const x25519Hex = bytesToHex(keys.x25519.secretKey);
  const seedHex = bytesToHex(keys.mlkem768x25519.secretSeed);
  const bundle = recipientKeyBundleFromSeed(SEED);

  const stringForms = [
    String(bundle),
    `${bundle}`,
    JSON.stringify(bundle),
    inspect(bundle),
    inspect({ nested: bundle }),
  ];

  it('never surfaces the key bytes in any string form', () => {
    for (const form of stringForms) {
      expect(form).not.toContain(x25519Hex);
      expect(form).not.toContain(seedHex);
    }
  });

  it('renders a count-only redacted summary', () => {
    expect(String(bundle)).toContain('redacted');
    expect(String(bundle)).toContain('1 key(s)');
    expect(String(bundle)).toContain('1 seed(s)');
  });

  it('keeps the key lists accessible for the unwrap dispatch', () => {
    expect(bytesToHex(bundle.x25519PrivateKeys[0]!)).toBe(x25519Hex);
    expect(bytesToHex(bundle.mlkem768x25519SecretSeeds[0]!)).toBe(seedHex);
  });
});

describe('the prepared passphrase seal never holds the passphrase or plaintext', () => {
  const passphrase = 'correct horse battery staple';
  const plaintext = new TextEncoder().encode('a distinctive sealed plaintext marker');

  it('leaks neither the passphrase nor the plaintext in any string form', async () => {
    const prepared = await passphraseSealPrepare({
      items: [{ content: plaintext }],
      passphrase,
    });
    const plaintextHex = bytesToHex(plaintext);
    for (const form of [
      String(prepared),
      `${prepared}`,
      JSON.stringify(prepared),
      inspect(prepared),
      inspect({ nested: prepared }),
      JSON.stringify(prepared.items),
      inspect(prepared.items),
    ]) {
      expect(form).not.toContain(passphrase);
      expect(form).not.toContain(plaintextHex);
    }
  });
});
