// TS KAT verifier test for per-wallet COSE_Sign1 fixtures.
//
// Loads each of the 24 fixtures (6 positive + 18 tamper variants) from
// `../fixtures/wallet-cose/`, drives them through `verifyRecordSignatures`,
// normalises the verifier output via `toNormalizedSigVerdict`, and asserts
// deep-equal against the fixture's `expected_normalized_verdict`. Both the
// positive and tamper paths thus check the load-bearing `WALLET_ADDRESS_MISMATCH`
// step 7.5 binding logic in `src/verifier/signatures.ts`.
//
// MALFORMED_SIG_COSE_SIGN1 (canonical-CBOR ordering deviations) is asserted
// IMPLICITLY: a wallet that ships a non-canonical COSE_Sign1 / COSE_Key
// encoding would surface at the loader's `hexToBytes` + `parseCoseKeyEd25519` /
// `decodeCoseSign1` step and fail the sanity invariants or the verifier
// verdict assertion. No explicit "tamper the CBOR encoding" fixture is needed
// — the loader / verifier path already exercises it on every fixture.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type CanonicalCborValue,
} from '@cardanowall/crypto-core/cbor';
import {
  CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES,
  parseCoseKeyEd25519,
} from '@cardanowall/crypto-core/cose';
import { blake2b224 } from '@cardanowall/crypto-core/hash';
import { hexToBytes } from '@cardanowall/crypto-core/util';
import { chunkBytes, type ChunkedBytesArray, type PoeRecord } from '@cardanowall/poe-standard';
import { verifyRecordSignatures } from '@cardanowall/sdk-ts/verifier';

import { toNormalizedSigVerdict, type NormalizedSigVerdict } from './normalized-verdict';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.resolve(HERE, '../fixtures/wallet-cose');

const WALLETS = ['eternl', 'lace', 'nami', 'typhon', 'yoroi', 'nufi'] as const;
type Wallet = (typeof WALLETS)[number];

const MAINNET_STAKE_NETWORK_BYTE = 0xe1;
const STAKE_ADDRESS_LENGTH = 29;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const BLAKE2B_224_LENGTH = 28;

interface PositiveFixture {
  readonly wallet: Wallet;
  readonly cardano_network: 'mainnet';
  readonly record_body_cbor_hex: string;
  readonly to_sign_bytes_hex: string;
  readonly stake_addr_hex: string;
  readonly cose_sign1_bytes_hex: string;
  readonly cose_key_bytes_hex: string;
  readonly expected_signer_pubkey_hex: string;
  readonly expected_normalized_verdict: NormalizedSigVerdict;
}

interface TamperFixture {
  readonly wallet: Wallet;
  readonly tamper_variant: 'tampered-address' | 'missing-address' | 'wrong-network-header';
  readonly record_body_cbor_hex: string;
  readonly cose_sign1_bytes_hex: string;
  readonly cose_key_bytes_hex: string;
  readonly tamper_signer_pubkey_hex: string;
  readonly expected_normalized_verdict: NormalizedSigVerdict;
}

function loadJson<T>(filename: string): T {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, filename), 'utf8')) as T;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function buildRecord(coseSign1Bytes: Uint8Array, coseKeyBytes: Uint8Array): PoeRecord {
  return {
    v: 1,
    items: [{ hashes: { 'sha2-256': new Uint8Array(32) } }],
    sigs: [
      {
        cose_sign1: chunkBytes(coseSign1Bytes) as ChunkedBytesArray,
        cose_key: chunkBytes(coseKeyBytes) as ChunkedBytesArray,
      },
    ],
  };
}

describe.each(WALLETS)('wallet-cose KAT — %s positive fixture', (wallet) => {
  const fixture = loadJson<PositiveFixture>(`${wallet}-cose.json`);

  it('verifies and projects to expected verdict', async () => {
    const coseSign1 = hexToBytes(fixture.cose_sign1_bytes_hex);
    const coseKey = hexToBytes(fixture.cose_key_bytes_hex);
    const record = buildRecord(coseSign1, coseKey);
    const out = await verifyRecordSignatures({
      record,
      input: { txHash: '0'.repeat(64), cardanoNetwork: 'mainnet' },
    });
    expect(out).toHaveLength(1);
    expect(toNormalizedSigVerdict(out[0]!)).toEqual(fixture.expected_normalized_verdict);
  });

  it('sanity invariants hold', () => {
    // Invariant 1 — record_body_cbor_hex is canonical CBOR (round-trips).
    const bodyBytes = hexToBytes(fixture.record_body_cbor_hex);
    const reencoded = encodeCanonicalCbor(decodeCanonicalCbor(bodyBytes) as CanonicalCborValue);
    expect(bytesToHex(reencoded)).toBe(fixture.record_body_cbor_hex);

    // Invariant 2 — to_sign_bytes_hex.length === 25 + record_body length, and
    // its first 25 bytes are the UTF-8 domain prefix.
    const toSign = hexToBytes(fixture.to_sign_bytes_hex);
    expect(toSign.length).toBe(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length + bodyBytes.length);
    const prefix = toSign.slice(0, CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length);
    expect(bytesToHex(prefix)).toBe(bytesToHex(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES));
    const bodyTail = toSign.slice(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length);
    expect(bytesToHex(bodyTail)).toBe(fixture.record_body_cbor_hex);

    // Invariant 3 — stake_addr_hex is 29 bytes; first byte is 0xe1 (mainnet).
    const stakeAddr = hexToBytes(fixture.stake_addr_hex);
    expect(stakeAddr.length).toBe(STAKE_ADDRESS_LENGTH);
    expect(stakeAddr[0]).toBe(MAINNET_STAKE_NETWORK_BYTE);

    // Invariant 4 — expected_signer_pubkey_hex is 32 bytes and equals
    // parseCoseKeyEd25519(cose_key).
    const coseKey = hexToBytes(fixture.cose_key_bytes_hex);
    const parsedPub = parseCoseKeyEd25519(coseKey);
    expect(parsedPub).not.toBeNull();
    expect(parsedPub!.length).toBe(ED25519_PUBLIC_KEY_LENGTH);
    expect(bytesToHex(parsedPub!)).toBe(fixture.expected_signer_pubkey_hex);

    // Invariant 5 — Blake2b-224(signer_pub) binds to stake_addr_hex[1:29].
    const hash = blake2b224(parsedPub!);
    expect(hash.length).toBe(BLAKE2B_224_LENGTH);
    expect(bytesToHex(hash)).toBe(bytesToHex(stakeAddr.slice(1)));
  });
});

const TAMPER_VARIANTS = ['tampered-address', 'missing-address', 'wrong-network-header'] as const;

describe.each(WALLETS)('wallet-cose KAT — %s tamper variants', (wallet) => {
  for (const variant of TAMPER_VARIANTS) {
    const filename = `${wallet}-cose-${variant}.json`;
    it(`${variant} emits WALLET_ADDRESS_MISMATCH`, async () => {
      const fixture = loadJson<TamperFixture>(filename);
      const coseSign1 = hexToBytes(fixture.cose_sign1_bytes_hex);
      const coseKey = hexToBytes(fixture.cose_key_bytes_hex);
      const record = buildRecord(coseSign1, coseKey);
      const out = await verifyRecordSignatures({
        record,
        input: { txHash: '0'.repeat(64), cardanoNetwork: 'mainnet' },
      });
      expect(out).toHaveLength(1);
      expect(toNormalizedSigVerdict(out[0]!)).toEqual(fixture.expected_normalized_verdict);

      // Sanity: parseCoseKeyEd25519 yields tamper_signer_pubkey_hex.
      const parsedPub = parseCoseKeyEd25519(coseKey);
      expect(parsedPub).not.toBeNull();
      expect(bytesToHex(parsedPub!)).toBe(fixture.tamper_signer_pubkey_hex);
    });
  }
});
