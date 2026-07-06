// Raw-seed identity surface. A developer holding a 32-byte seed (e.g. the
// decoded hex of a key exported from another tool) can derive every keypair,
// obtain their age recipient strings, get a path-1 Signer, build the
// RecipientKeyBundle the unwrap dispatch consumes, and decrypt a sealed PoE —
// all from the public SDK, without a web account envelope.
//
// The seed is the only secret this module touches. Callers are responsible for
// sourcing it securely; the SDK never persists or logs it.

import {
  deriveEd25519KeypairFromSeed,
  deriveX25519KeypairFromSeed,
  deriveMlKem768X25519KeypairFromSeed,
  type DerivedEd25519KeyPair,
  type DerivedX25519KeyPair,
  type DerivedMlKem768X25519KeyPair,
} from '@cardanowall/crypto-core/seed-derive';
import {
  encodeAgeX25519Recipient,
  encodeAgeXWingRecipient,
} from '@cardanowall/crypto-core/recipient';
import {
  eciesSealedPoeUnwrap,
  type ItemHashes,
  type RecipientKeyBundle,
  type SealedEnvelope,
  type UnwrapResult,
} from '@cardanowall/crypto-core/sealed-poe';
import { signEd25519 } from '@cardanowall/crypto-core/sig';

import type { Signer } from '../client/types';

export interface SeedKeys {
  readonly ed25519: DerivedEd25519KeyPair;
  readonly x25519: DerivedX25519KeyPair;
  readonly mlkem768x25519: DerivedMlKem768X25519KeyPair;
}

// Derive the three identity keypairs from a 32-byte seed: Ed25519 (record
// signing), X25519 (classical KEM), and ML-KEM-768 + X25519 / X-Wing (hybrid
// post-quantum KEM). Each keypair is the same byte-for-byte value the account
// envelope would expose — the seed alone fully determines the identity.
export function deriveKeysFromSeed(seed: Uint8Array): SeedKeys {
  return {
    ed25519: deriveEd25519KeypairFromSeed(seed),
    x25519: deriveX25519KeypairFromSeed(seed),
    mlkem768x25519: deriveMlKem768X25519KeypairFromSeed(seed),
  };
}

export interface SeedRecipients {
  /** Classical age recipient ("age1…") for the X25519 KEM. */
  readonly age: string;
  /** X-Wing hybrid recipient ("age1pqc…") for the ML-KEM-768 + X25519 KEM. */
  readonly age1pqc: string;
}

// The recipient strings other senders use to address this identity. Both
// always exist for any seed: the X-Wing keypair derives for free, so every
// identity can receive hybrid sealed records even when it publishes via the
// classical X25519 path.
export function recipientsFromSeed(seed: Uint8Array): SeedRecipients {
  const keys = deriveKeysFromSeed(seed);
  return {
    age: encodeAgeX25519Recipient(keys.x25519.publicKey),
    age1pqc: encodeAgeXWingRecipient(keys.mlkem768x25519.publicKey),
  };
}

// An in-memory path-1 Signer for the publish helpers / off-host signing
// surface. The derived Ed25519 secret lives only inside this closure; the
// SDK's publish path touches just `signerPubkey` (public) and the 64-byte
// signature (public). The 32-byte HKDF output IS the noble Ed25519 seed, so it
// feeds `signEd25519` directly.
export function signerFromSeed(seed: Uint8Array): Signer {
  const { secretKey, publicKey } = deriveEd25519KeypairFromSeed(seed);
  return {
    signerPubkey: publicKey,
    async sign(sigStructureBytes: Uint8Array): Promise<Uint8Array> {
      return signEd25519({ seed: secretKey, message: sigStructureBytes });
    },
  };
}

// The unified RecipientKeyBundle for the trial-decrypt / unwrap dispatch. A
// single active identity contributes a one-element X25519 private-key chain and
// a one-element X-Wing secret-seed list; the unwrap dispatch selects the right
// list from `envelope.kem`.
//
// The bundle holds recipient private keys — the material a sealed record is
// decrypted with — so the SDK-produced bundle self-redacts: `toString`,
// `console.log` (Node inspect), and `JSON.stringify` all render a
// count-only summary and never the key bytes. Field access
// (`bundle.x25519PrivateKeys`) is unaffected, so the unwrap dispatch reads the
// keys normally; only the string forms are redacted, so a stray log line, an
// error chain, or a serialized dump can never surface the secret.
export function recipientKeyBundleFromSeed(seed: Uint8Array): RecipientKeyBundle {
  const keys = deriveKeysFromSeed(seed);
  return redactRecipientKeyBundle([keys.x25519.secretKey], [keys.mlkem768x25519.secretSeed]);
}

/**
 * Wrap the two secret-key lists in a `RecipientKeyBundle` whose every string
 * form redacts the key bytes while keeping the list counts observable (a bundle
 * stays useful to log). Field access is untouched; only `toString` / Node
 * inspect / `JSON.stringify` are intercepted.
 */
function redactRecipientKeyBundle(
  x25519PrivateKeys: ReadonlyArray<Uint8Array>,
  mlkem768x25519SecretSeeds: ReadonlyArray<Uint8Array>,
): RecipientKeyBundle {
  const summary = (): string =>
    `RecipientKeyBundle { x25519PrivateKeys: <redacted ${x25519PrivateKeys.length} key(s)>, ` +
    `mlkem768x25519SecretSeeds: <redacted ${mlkem768x25519SecretSeeds.length} seed(s)> }`;
  const bundle: RecipientKeyBundle = { x25519PrivateKeys, mlkem768x25519SecretSeeds };
  Object.defineProperties(bundle, {
    toString: { value: summary, enumerable: false },
    toJSON: { value: summary, enumerable: false },
    [Symbol.for('nodejs.util.inspect.custom')]: { value: summary, enumerable: false },
  });
  return bundle;
}

export interface DecryptSealedFromSeedArgs {
  readonly seed: Uint8Array;
  readonly envelope: SealedEnvelope;
  readonly ciphertext: Uint8Array;
  // The item's plaintext-hash claim, exactly as carried in the record body.
  // Load-bearing for decryption: the hashes map is bound into the slots
  // transcript, so a slot only accepts when the envelope sits under the same
  // hashes claim it was sealed for.
  readonly hashes: ItemHashes;
}

// Decrypt a sealed PoE envelope + ciphertext from the seed. Builds the bundle
// and routes through the existing unwrap dispatch, which selects the correct
// secret list from `envelope.kem` — so the same call decrypts both classical
// (x25519) and hybrid (mlkem768x25519) records. Returns the discriminated
// UnwrapResult; it never throws on an authentication failure (wrong key,
// tampered header, tampered ciphertext) — callers branch on `result.matched`.
export function decryptSealedFromSeed(args: DecryptSealedFromSeedArgs): UnwrapResult {
  return eciesSealedPoeUnwrap({
    envelope: args.envelope,
    ciphertext: args.ciphertext,
    hashes: args.hashes,
    recipientKeyBundle: recipientKeyBundleFromSeed(args.seed),
  });
}
