// Label 309 record-level signature verifier.
//
// One verification per `record.sigs[i]`. v1 has NO per-item signature slot —
// the only signature surface is the record-level array. Two on-wire signer-key
// paths (mutually exclusive on the wire, enforced by the structural
// validator as `SIG_ENTRY_KID_COSE_KEY_CONFLICT`):
//
//   Path 1 — protected-header `kid` is exactly 32 bytes (raw Ed25519 pubkey).
//   Path 2 — `sigs[i].cose_key` is a single `cbor<COSE_Key>` byte string
//            carrying the wallet's public key. The protected header carries a
//            29-byte CIP-19 stake address at label `"address"`; the verifier
//            recomputes `expected_network_header || Blake2b-224(pub)` —
//            deriving the network byte from the CONTAINING TRANSACTION's
//            network, never echoing the byte found in the record — and
//            rejects on any of the 29 bytes (`WALLET_ADDRESS_MISMATCH`).
//
// The producer's protected-header bytes are used VERBATIM as
// `Sig_structure[1]` — never re-encoded or re-canonicalised (RFC 9052 §4.4) —
// and the signing body is the canonical de-chunked record body with `sigs`
// removed; both rules are enforced by `coseSign1Label309Verify` in
// `@cardanowall/crypto-core/cose`. Ed25519 verification is strict per
// RFC 8032 §5.1.7 (canonical R/S, low-order rejection, no cofactor
// multiplication).
//
// Record signatures are OPTIONAL: a public hash-only PoE remains valid even
// when every signature entry is unverifiable (SIGNATURE_UNSUPPORTED, info).
// Every `unsupported` per-signature verdict puts SIGNATURE_UNSUPPORTED (info)
// at ['sigs', i] EXACTLY ONCE: the structural validator contributes the same
// issue for UNREGISTERED algorithms, while a registered-but-unimplemented
// algorithm is only detected here, so this pass emits idempotently against
// the sink. Error-class failures (SIGNATURE_INVALID, SIGNER_KEY_UNRESOLVED,
// WALLET_ADDRESS_MISMATCH, MALFORMED_SIG_COSE_SIGN1) raise issues into the
// run's sink and fail the record.

import {
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
import type { IssueSink } from './issues';
import type { SignatureFailureReason, VerifyRecordSignature } from './types';

// v1 wallet-path constraint: stake (reward) addresses only. The 29-byte
// CIP-19 layout is `network_header_byte || Blake2b-224(stake_vk)`; stake
// network bytes: mainnet = 0xe1, testnet = 0xe0 (preprod and preview share
// the testnet header).
const CARDANO_MAINNET_STAKE_NETWORK_BYTE = 0xe1;
const CARDANO_PREPROD_STAKE_NETWORK_BYTE = 0xe0;
const CARDANO_STAKE_ADDRESS_LENGTH = 29;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const BLAKE2B_224_LENGTH = 28;

export interface VerifyRecordSignaturesArgs {
  readonly record: PoeRecord;
  readonly cardanoNetwork: 'mainnet' | 'preprod';
  readonly issues: IssueSink;
}

export function verifyRecordSignatures(args: VerifyRecordSignaturesArgs): VerifyRecordSignature[] {
  const { record } = args;
  // The signed payload is canonical-CBOR(record_body), where record_body =
  // record minus `sigs`. The encoder helper keeps the wire shape and key sort
  // in lockstep with producer-side signing.
  const recordBodyCbor = encodeRecordBodyForSigning(record);
  const list = record.sigs ?? [];
  const out: VerifyRecordSignature[] = [];
  for (let i = 0; i < list.length; i++) {
    const result = verifyOneSig(i, list[i]!, recordBodyCbor, args.cardanoNetwork);
    out.push(result);
    if (result.verdict === 'invalid' || result.verdict === 'unresolved') {
      args.issues.add(
        result.reason ?? 'SIGNATURE_INVALID',
        ['sigs', i],
        signatureFailureMessage(result),
      );
    } else if (result.verdict === 'unsupported') {
      // An unsupported entry MUST surface as exactly one SIGNATURE_UNSUPPORTED
      // (info) at ['sigs', i]. The idempotent add covers both ways an entry
      // gets here: an UNREGISTERED algorithm (the structural validator already
      // contributed the identical issue) and a registered algorithm this
      // verifier does not implement (only this pass detects it).
      args.issues.addOnce(
        'SIGNATURE_UNSUPPORTED',
        ['sigs', i],
        'the COSE_Sign1 signature algorithm is not implemented by this verifier; the entry is unsupported, not invalid',
      );
    }
  }
  return out;
}

function signatureFailureMessage(result: VerifyRecordSignature): string {
  switch (result.reason) {
    case 'MALFORMED_SIG_COSE_SIGN1':
      return 'the cose_sign1 blob is not a verifiable detached COSE_Sign1';
    case 'SIGNER_KEY_UNRESOLVED':
      return 'neither key-resolution path yielded a 32-byte Ed25519 public key';
    case 'WALLET_ADDRESS_MISMATCH':
      return 'the wallet-path protected-header address does not equal the recomputed network_header || Blake2b-224(pubkey)';
    default:
      return 'strict Ed25519 verification failed against the resolved public key';
  }
}

function verifyOneSig(
  index: number,
  entry: SigEntry,
  recordBodyCbor: Uint8Array,
  cardanoNetwork: 'mainnet' | 'preprod',
): VerifyRecordSignature {
  const coseBytes = entry.cose_sign1;
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

  // Strict Ed25519 verify; Sig_structure[1] is the producer's protected bytes
  // verbatim.
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
        signerType,
        signerPub: bytesToHex(pub),
        reason,
      };
    }
    return {
      index,
      verdict: 'invalid',
      signerType,
      signerPub: bytesToHex(pub),
      reason,
    };
  }

  // Path-2 wallet `address` ↔ `cose_key` binding. Path-1 entries skip this
  // check entirely.
  if (signerType === 'wallet-inline-key') {
    const addressOk = checkWalletAddressBinding(cose, pub, cardanoNetwork);
    if (!addressOk) {
      return {
        index,
        verdict: 'invalid',
        signerType,
        signerPub: bytesToHex(pub),
        reason: 'WALLET_ADDRESS_MISMATCH',
      };
    }
  }

  return {
    index,
    verdict: 'valid',
    signerType,
    signerPub: bytesToHex(pub),
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
  // Path 2 — a single `cbor<COSE_Key>` byte string carrying the wallet pubkey.
  if (entry.cose_key !== undefined) {
    const pub = parseCoseKeyEd25519(entry.cose_key);
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
// v1 — base/enterprise/pointer/payment addresses fail the equality check
// against the recomputed 29-byte stake address.
function checkWalletAddressBinding(
  cose: CoseSign1Decoded,
  pub: Uint8Array,
  cardanoNetwork: 'mainnet' | 'preprod',
): boolean {
  const networkByte =
    cardanoNetwork === 'preprod'
      ? CARDANO_PREPROD_STAKE_NETWORK_BYTE
      : CARDANO_MAINNET_STAKE_NETWORK_BYTE;
  const rawAddress = cose.protectedHeader.get('address') as unknown;
  if (!(rawAddress instanceof Uint8Array)) {
    // `address` is REQUIRED on the wallet path: a wallet signature without an
    // address claim cannot be safely surfaced as wallet-bound.
    return false;
  }
  if (rawAddress.length !== CARDANO_STAKE_ADDRESS_LENGTH) return false;
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
