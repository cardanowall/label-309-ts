// Error precedence of passphraseSealedPoeOpen, pinned identically across the
// SDKs: typed caller-input rejections — the item's hash claim, then passphrase
// normalization, then the envelope shape — strictly precede the blob
// structural floor, and the floor precedes the Argon2id derivation. The
// expensive KDF therefore runs only for a call whose inputs are well-formed
// and whose blob could possibly be a passphrase-path ciphertext.

import { describe, expect, it, vi } from 'vitest';

import { argon2idV13 } from '../kdf/argon2id';

import { passphraseSealedPoeOpen } from './passphrase';
import { SEALED_POE_AEAD } from './wrap';
import type { PassphraseParams, PassphraseSealedEnvelope } from './passphrase';
import type { ItemHashes } from './transcript';

// Spy on the KDF module (real implementation preserved) so the tests can
// assert that a rejected call never reached the derivation.
vi.mock('../kdf/argon2id', { spy: true });

const VALID_PARAMS: PassphraseParams = { m: 65536, t: 3, p: 1 };
const BELOW_FLOOR_PARAMS: PassphraseParams = { m: 8, t: 1, p: 1 };
// U+0378 is unassigned in Unicode 16.0, so the pinned normalization profile
// rejects the passphrase as unnormalizable.
const UNNORMALIZABLE_PASSPHRASE = 'pass͸word';
const VALID_PASSPHRASE = 'correct horse battery staple';
const HASHES: ItemHashes = { 'sha2-256': new Uint8Array(32).fill(0x5a) };
// One byte below the 48-byte floor (32-byte commitment + a lone 16-byte tag).
const SHORT_BLOB = new Uint8Array(47);

function envelopeWith(params: PassphraseParams): PassphraseSealedEnvelope {
  return {
    scheme: 1,
    aead: SEALED_POE_AEAD,
    nonce: new Uint8Array(24).fill(0x42),
    passphrase: { alg: 'argon2id', salt: new Uint8Array(16).fill(0x24), params },
  };
}

describe('passphrase sealed PoE — open error precedence', () => {
  it('the hash claim is validated before normalization, the envelope, and the blob', async () => {
    vi.mocked(argon2idV13).mockClear();
    await expect(
      passphraseSealedPoeOpen({
        envelope: envelopeWith(BELOW_FLOOR_PARAMS),
        blob: SHORT_BLOB,
        passphrase: UNNORMALIZABLE_PASSPHRASE,
        hashes: {},
      }),
    ).rejects.toMatchObject({ code: 'ENC_REQUIRES_CONTENT_HASH' });
    expect(argon2idV13).not.toHaveBeenCalled();
  });

  it('normalization is validated before the envelope and the blob', async () => {
    vi.mocked(argon2idV13).mockClear();
    await expect(
      passphraseSealedPoeOpen({
        envelope: envelopeWith(BELOW_FLOOR_PARAMS),
        blob: SHORT_BLOB,
        passphrase: UNNORMALIZABLE_PASSPHRASE,
        hashes: HASHES,
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_UNNORMALIZABLE' });
    expect(argon2idV13).not.toHaveBeenCalled();
  });

  it('the envelope shape is validated before the blob floor', async () => {
    vi.mocked(argon2idV13).mockClear();
    await expect(
      passphraseSealedPoeOpen({
        envelope: envelopeWith(BELOW_FLOOR_PARAMS),
        blob: SHORT_BLOB,
        passphrase: VALID_PASSPHRASE,
        hashes: HASHES,
      }),
    ).rejects.toMatchObject({ code: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW' });
    expect(argon2idV13).not.toHaveBeenCalled();
  });

  it('a below-floor blob fails generically WITHOUT invoking the KDF', async () => {
    vi.mocked(argon2idV13).mockClear();
    const result = await passphraseSealedPoeOpen({
      envelope: envelopeWith(VALID_PARAMS),
      blob: SHORT_BLOB,
      passphrase: VALID_PASSPHRASE,
      hashes: HASHES,
    });
    expect(result.matched).toBe(false);
    if (!result.matched) expect(result.reason).toBe('TAMPERED_CIPHERTEXT');
    expect(argon2idV13).not.toHaveBeenCalled();
  });
});
