// Label 309 record-level signature verifier.
//
// One verification per `record.sigs[i]`. v1 has NO per-item signature slot —
// the only signature surface is the record-level array. Two on-wire signer-key
// paths (mutually exclusive on the wire, enforced by the structural
// validator as `SIG_ENTRY_KID_COSE_KEY_CONFLICT`):
//
//   Path 1 — protected-header `kid` is exactly 32 bytes (raw Ed25519 pubkey).
//   Path 2 — `sigs[i].cose_key` is a chunked `cbor<COSE_Key>` blob carrying
//            the wallet's public key. The protected header carries a 29-byte
//            CIP-19 stake address at label `"address"`; the verifier
//            recomputes `address_derived = network_header || Blake2b-224(pub)`
//            and rejects on mismatch (`WALLET_ADDRESS_MISMATCH`).
//
// The signed-payload construction (`Sig_structure[3] = "cardano-poe-record-sig-v1" ||
// canonicalCbor(record_body)`, `Sig_structure[2] = h''`) is enforced by the
// `coseSign1Label309Verify` helper in `@cardanowall/crypto-core/cose` — this
// verifier never sees the prefix directly.

import {
  bytesChunkArrayConcat,
  encodeRecordBodyForSigning,
  type PoeRecord,
  type SigEntry,
} from '@cardanowall/poe-standard';
import {
  coseSign1Label309Verify,
  decodeCoseSign1,
  parseCoseKeyEd25519,
  type CoseSign1Decoded,
} from '@cardanowall/crypto-core/cose';
import { blake2b224 } from '@cardanowall/crypto-core/hash';
import { compareCt } from '@cardanowall/crypto-core/util';

import { bytesToHex } from '../hex';
import type { SignatureFailureReason, VerifyRecordSignature, VerifyTxInput } from './types';

// v1 wallet-path constraint: stake (reward) addresses only. The 29-byte CIP-19
// layout is `network_header_byte || Blake2b-224(stake_vk)`. CIP-19
// stake-address network bytes: mainnet = 0xe1, testnet = 0xe0 (preprod and
// preview share the testnet header). Product policy is mainnet-only; the
// preprod branch exists only so dev environments can replay records anchored
// on preprod against the same standalone verifier.
const CARDANO_MAINNET_STAKE_NETWORK_BYTE = 0xe1;
const CARDANO_PREPROD_STAKE_NETWORK_BYTE = 0xe0;
const CARDANO_STAKE_ADDRESS_LENGTH = 29;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const BLAKE2B_224_LENGTH = 28;

export interface VerifyRecordSignaturesArgs {
  readonly record: PoeRecord;
  readonly input: VerifyTxInput;
}

export async function verifyRecordSignatures(
  args: VerifyRecordSignaturesArgs,
): Promise<VerifyRecordSignature[]> {
  const { record, input } = args;
  // The signed payload is canonical-CBOR(record_body), where record_body =
  // record minus `sigs`. We use the encoder helper to keep the wire shape and
  // key sort in lockstep with producer-side signing.
  const recordBodyCbor = encodeRecordBodyForSigning(record);
  const list = record.sigs ?? [];
  const out: VerifyRecordSignature[] = [];
  for (let i = 0; i < list.length; i++) {
    out.push(await verifyOneSig(i, list[i]!, recordBodyCbor, input));
  }
  return out;
}

async function verifyOneSig(
  index: number,
  entry: SigEntry,
  recordBodyCbor: Uint8Array,
  input: VerifyTxInput,
): Promise<VerifyRecordSignature> {
  const coseBytes = bytesChunkArrayConcat(entry.cose_sign1);
  let cose: CoseSign1Decoded;
  try {
    cose = decodeCoseSign1(coseBytes);
  } catch {
    return { index, verdict: 'invalid', reason: 'MALFORMED_SIG_COSE_SIGN1' };
  }

  // Resolve the signer's 32-byte Ed25519 pubkey (path 1 vs path 2).
  const resolved = resolveSignerKey(cose, entry);
  if (resolved.kind === 'unresolved') {
    return { index, verdict: 'unresolved', reason: 'SIGNER_KEY_UNRESOLVED' };
  }
  const { pub, signerType } = resolved;

  // Strict Ed25519 verify via the Label 309-pinned helper.
  const verifyResult = coseSign1Label309Verify({
    message: coseBytes,
    detachedRecordBodyCbor: recordBodyCbor,
    expectedSignerKey: pub,
  });

  if (!verifyResult.ok) {
    const reason = mapVerifyError(verifyResult.error.code);
    if (reason === 'SIGNATURE_UNSUPPORTED') {
      return {
        index,
        verdict: 'unsupported',
        signer_type: signerType,
        signer_pub: bytesToHex(pub),
        reason,
      };
    }
    return {
      index,
      verdict: 'invalid',
      signer_type: signerType,
      signer_pub: bytesToHex(pub),
      reason,
    };
  }

  // Path-2 wallet `address` ↔ `cose_key` binding. Path-1 entries skip this
  // check entirely.
  if (signerType === 'wallet-inline-key') {
    const addressOk = checkWalletAddressBinding(cose, pub, input);
    if (!addressOk) {
      return {
        index,
        verdict: 'invalid',
        signer_type: signerType,
        signer_pub: bytesToHex(pub),
        reason: 'WALLET_ADDRESS_MISMATCH',
      };
    }
  }

  return {
    index,
    verdict: 'valid',
    signer_type: signerType,
    signer_pub: bytesToHex(pub),
  };
}

interface ResolvedPathOne {
  readonly kind: 'in-signature-kid';
  readonly pub: Uint8Array;
  readonly signerType: 'in-signature-kid';
}
interface ResolvedPathTwo {
  readonly kind: 'wallet-inline-key';
  readonly pub: Uint8Array;
  readonly signerType: 'wallet-inline-key';
}
type ResolvedKey = ResolvedPathOne | ResolvedPathTwo | { readonly kind: 'unresolved' };

function resolveSignerKey(cose: CoseSign1Decoded, entry: SigEntry): ResolvedKey {
  // Path 1 — protected-header label 4 (`kid`) as the 32-byte raw Ed25519
  // pubkey. Unprotected-header `kid` values are NEVER consulted: they sit
  // outside the COSE integrity envelope and an attacker could rewrite them.
  const protectedKid = cose.protectedHeader.get(4) as unknown;
  if (
    protectedKid instanceof Uint8Array &&
    protectedKid.length === ED25519_PUBLIC_KEY_LENGTH &&
    entry.cose_key === undefined
  ) {
    return {
      kind: 'in-signature-kid',
      pub: protectedKid,
      signerType: 'in-signature-kid',
    };
  }
  // Path 2 — chunked `cbor<COSE_Key>` carrying the wallet pubkey.
  if (entry.cose_key !== undefined) {
    const blob = bytesChunkArrayConcat(entry.cose_key);
    const pub = parseCoseKeyEd25519(blob);
    if (pub !== null && pub.length === ED25519_PUBLIC_KEY_LENGTH) {
      return { kind: 'wallet-inline-key', pub, signerType: 'wallet-inline-key' };
    }
  }
  return { kind: 'unresolved' };
}

function mapVerifyError(code: string): SignatureFailureReason {
  switch (code) {
    case 'MALFORMED_SIG_COSE':
    case 'MALFORMED_SIG_COSE_SIGN1':
      return 'MALFORMED_SIG_COSE_SIGN1';
    case 'UNSUPPORTED_SIG_ALG':
      return 'SIGNATURE_UNSUPPORTED';
    case 'KID_UNRESOLVED':
      return 'SIGNER_KEY_UNRESOLVED';
    case 'SIGNATURE_INVALID':
      return 'SIGNATURE_INVALID';
    default:
      return 'SIGNATURE_INVALID';
  }
}

// Recompute the 29-byte stake address from the resolved Ed25519 pubkey and
// compare it byte-exact (constant-time) to the path-2 protected-header
// `address` field. The wallet path binds to stake (reward) addresses only in
// v1 — base/enterprise/pointer/payment addresses are rejected (the recomputed
// 29-byte stake address fails the equality check against any other
// format/length).
function checkWalletAddressBinding(
  cose: CoseSign1Decoded,
  pub: Uint8Array,
  input: VerifyTxInput,
): boolean {
  const networkByte =
    (input.cardanoNetwork ?? 'mainnet') === 'preprod'
      ? CARDANO_PREPROD_STAKE_NETWORK_BYTE
      : CARDANO_MAINNET_STAKE_NETWORK_BYTE;
  const rawAddress = cose.protectedHeader.get('address') as unknown;
  if (!(rawAddress instanceof Uint8Array)) {
    // Address-less path-2 records are non-conformant with CIP-30 signData
    // (a wallet signature without an address claim cannot be safely surfaced
    // as wallet-bound). Treat as WALLET_ADDRESS_MISMATCH.
    return false;
  }
  if (rawAddress.length !== CARDANO_STAKE_ADDRESS_LENGTH) return false;
  if (rawAddress[0] !== networkByte) return false;
  const stakeKeyHash = blake2b224(pub);
  if (stakeKeyHash.length !== BLAKE2B_224_LENGTH) {
    // Defensive guard — `blake2b224` is byte-pinned to 28 bytes.
    return false;
  }
  const derived = new Uint8Array(CARDANO_STAKE_ADDRESS_LENGTH);
  derived[0] = networkByte;
  derived.set(stakeKeyHash, 1);
  return compareCt(derived, rawAddress);
}
