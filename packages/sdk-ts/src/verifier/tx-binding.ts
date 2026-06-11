// Transaction-reference integrity binding.
//
// Before reading anything out of a fetched transaction, the verifier MUST
// bind the fetched bytes to the caller-supplied transaction reference:
//
//   1. blake2b-256 over the transaction-body bytes — by ledger definition,
//      the transaction id — must equal the requested transaction hash;
//   2. blake2b-256 over the auxiliary-data bytes must equal the
//      `auxiliary_data_hash` field of the now-verified body.
//
// Both digests are computed over the bytes EXACTLY as fetched, never over a
// re-encoding. A response that fails either check carries provably wrong
// bytes: the caller discards it and tries the next provider; if no provider
// survives, the run reports TX_INTEGRITY_MISMATCH — provider-attributable,
// verdict `unverifiable`, because no record bytes were ever obtained and the
// record cannot be condemned by bytes a provider fabricated.
//
// After the binding holds, every byte of the record body and of the
// surrounding transaction is cryptographically committed to the requested
// transaction hash; no explorer can substitute, amend, or truncate the record
// without producing a blake2b-256 second preimage. The chain facts the
// binding does NOT establish — inclusion, height, depth, slot, time — stay
// explorer-asserted.

import { blake2b256 } from '@cardanowall/crypto-core/hash';
import { compareCt } from '@cardanowall/crypto-core/util';

import { auxiliaryDataHashFromTxBody } from './cbor-walker';

export type TxBindingResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly check: 'tx_hash' | 'auxiliary_data_hash';
      readonly message: string;
    };

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function hexToBytesOrNull(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bindTransactionBytes(args: {
  // 32-byte transaction hash, lowercase/uppercase hex accepted.
  readonly requestedTxHashHex: string;
  readonly txBody: Uint8Array;
  readonly auxiliaryData: Uint8Array | null;
}): TxBindingResult {
  const requested = hexToBytesOrNull(args.requestedTxHashHex.toLowerCase());
  const computedTxHash = blake2b256(args.txBody);
  if (requested === null || !compareCt(computedTxHash, requested)) {
    return {
      ok: false,
      check: 'tx_hash',
      message: `blake2b-256 of the fetched transaction body is ${bytesToHex(computedTxHash)}, not the requested ${args.requestedTxHashHex.toLowerCase()}`,
    };
  }

  let committed: Uint8Array | null;
  try {
    committed = auxiliaryDataHashFromTxBody(args.txBody);
  } catch (e) {
    return {
      ok: false,
      check: 'auxiliary_data_hash',
      message: e instanceof Error ? e.message : String(e),
    };
  }

  if (args.auxiliaryData === null) {
    if (committed !== null) {
      // The verified body commits to auxiliary data the response does not
      // carry: the provider served a provably incomplete transaction.
      return {
        ok: false,
        check: 'auxiliary_data_hash',
        message:
          'the verified transaction body carries auxiliary_data_hash but the response carries no auxiliary data',
      };
    }
    return { ok: true };
  }

  if (committed === null) {
    // Auxiliary data present but the body never committed to it — such a
    // transaction cannot exist on chain.
    return {
      ok: false,
      check: 'auxiliary_data_hash',
      message:
        'auxiliary data is present but the verified transaction body carries no auxiliary_data_hash',
    };
  }
  const computedAuxHash = blake2b256(args.auxiliaryData);
  if (!compareCt(computedAuxHash, committed)) {
    return {
      ok: false,
      check: 'auxiliary_data_hash',
      message: `blake2b-256 of the fetched auxiliary data is ${bytesToHex(computedAuxHash)}, not the body-committed ${bytesToHex(committed)}`,
    };
  }
  return { ok: true };
}
