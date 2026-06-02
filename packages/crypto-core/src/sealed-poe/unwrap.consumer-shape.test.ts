// Type-only assertion that a consumer's unlocked-key bundle shape
// (`x25519PrivateKeys: ReadonlyArray<Uint8Array>`) is assignable to the
// iterator's `recipientSecretKeys` parameter after the caller-side newest-first
// reversal `[keys[0]!, ...keys.slice(1).reverse()]`.
//
// crypto-core is a leaf package and must not depend on application code; the
// consumer bundle shape is mirrored locally as a structural type alias.

import { describe, expectTypeOf, it } from 'vitest';

import {
  type RecipientKeyBundle,
  type TrialDecryptOnlyArgs,
  type TrialDecryptOnlyResult,
  type UnwrapArgs,
  type UnwrapArgsMultiPriv,
} from './unwrap';
import { type SealedEnvelope } from './wrap';

interface UnlockedIdentityKeysShape {
  readonly x25519PrivateKeys: ReadonlyArray<Uint8Array>;
  readonly mlkem768x25519SecretSeed: Uint8Array;
}

describe('iterator surface consumer-shape contract', () => {
  it('reversed-newest-first ordering is assignable to recipientSecretKeys', () => {
    const keys: UnlockedIdentityKeysShape['x25519PrivateKeys'] = [
      new Uint8Array(32),
      new Uint8Array(32),
    ];
    const ordered: ReadonlyArray<Uint8Array> = [keys[0]!, ...keys.slice(1).reverse()];
    expectTypeOf(ordered).toExtend<ReadonlyArray<Uint8Array>>();

    const envelope: SealedEnvelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'x25519',
      nonce: new Uint8Array(24),
      slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
      slots_mac: new Uint8Array(32),
    };
    const args: UnwrapArgsMultiPriv = {
      envelope,
      ciphertext: new Uint8Array(0),
      recipientSecretKeys: ordered,
    };
    expectTypeOf(args).toExtend<UnwrapArgs>();
  });

  it('TrialDecryptOnlyArgs accepts the reversed-newest-first ordering', () => {
    const keys: UnlockedIdentityKeysShape['x25519PrivateKeys'] = [
      new Uint8Array(32),
      new Uint8Array(32),
    ];
    const ordered: ReadonlyArray<Uint8Array> = [keys[0]!, ...keys.slice(1).reverse()];
    const envelope: SealedEnvelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'x25519',
      nonce: new Uint8Array(24),
      slots: [{ epk: new Uint8Array(32), wrap: new Uint8Array(48) }],
      slots_mac: new Uint8Array(32),
    };
    const args: TrialDecryptOnlyArgs = {
      envelope,
      recipientSecretKeys: ordered,
    };
    expectTypeOf(args).toExtend<TrialDecryptOnlyArgs>();
    expectTypeOf<TrialDecryptOnlyResult>().toExtend<
      | { readonly kind: 'match'; readonly slotIdx: number; readonly cek: Uint8Array }
      | { readonly kind: 'no_aead_pass' }
      | { readonly kind: 'aead_pass_no_mac_match' }
    >();
  });

  it('an unlocked-identity bundle (x25519 chain + single hybrid seed) is assignable to RecipientKeyBundle', () => {
    // The consumer holds the X25519 chain plus a SINGLE current X-Wing seed.
    // The bundle wants a list for the hybrid path, so the consumer wraps the
    // single seed in a one-element array at the boundary.
    const unlocked: UnlockedIdentityKeysShape = {
      x25519PrivateKeys: [new Uint8Array(32), new Uint8Array(32)],
      mlkem768x25519SecretSeed: new Uint8Array(32),
    };
    const bundle: RecipientKeyBundle = {
      x25519PrivateKeys: [
        unlocked.x25519PrivateKeys[0]!,
        ...unlocked.x25519PrivateKeys.slice(1).reverse(),
      ],
      mlkem768x25519SecretSeeds: [unlocked.mlkem768x25519SecretSeed],
    };
    const envelope: SealedEnvelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'mlkem768x25519',
      nonce: new Uint8Array(24),
      slots: [{ kem_ct: [new Uint8Array(64)], wrap: new Uint8Array(48) }],
      slots_mac: new Uint8Array(32),
    };
    const trialArgs: TrialDecryptOnlyArgs = { envelope, recipientKeyBundle: bundle };
    expectTypeOf(trialArgs).toExtend<TrialDecryptOnlyArgs>();
    const unwrapArgs: UnwrapArgs = {
      envelope,
      ciphertext: new Uint8Array(0),
      recipientKeyBundle: bundle,
    };
    expectTypeOf(unwrapArgs).toExtend<UnwrapArgs>();
  });
});
