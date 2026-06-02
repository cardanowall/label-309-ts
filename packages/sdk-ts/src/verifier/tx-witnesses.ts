// Transaction-level decode for the CIP-309 verifier.
//
// This module surfaces the Cardano TRANSACTION that carried a PoE record: which
// wallet vkey(s) signed it, the fee, the outputs, and the co-published metadata
// labels. It answers "who authorised and paid for this anchoring" — distinct
// from the record-level COSE authorship signatures handled in `signatures.ts`.
//
// Unlike label-309 extraction, this decode is purely INFORMATIONAL: it is not
// fed back into the structural validator, so it is not subject to the
// canonical-CBOR byte-faithfulness concern that forces `cbor-walker` to slice
// rather than decode. We therefore decode the body + witness-set slices with
// the permissive CBOR decoder. The slices themselves are still byte-faithful —
// `decodeTxWitnesses` verifies each signature against `blake2b256(txBody)`,
// which only equals the on-chain transaction hash when the body bytes are
// exactly as produced.

import { decodeCbor } from '@cardanowall/crypto-core/cbor';
import { blake2b224, blake2b256 } from '@cardanowall/crypto-core/hash';
import { verifyEd25519 } from '@cardanowall/crypto-core/sig';

import { bytesToHex } from '../hex';
import type { VerifyTxOutput, VerifyTxSummary, VerifyTxWitness } from './types';

const ED25519_PUBLIC_KEY_LENGTH = 32;
const ED25519_SIGNATURE_LENGTH = 64;

// Conway-era transaction body map keys (RFC-style integer keys).
const BODY_KEY_INPUTS = 0;
const BODY_KEY_OUTPUTS = 1;
const BODY_KEY_FEE = 2;
const BODY_KEY_INVALID_HEREAFTER = 3; // ttl
const BODY_KEY_INVALID_BEFORE = 8; // validity_interval_start
const BODY_KEY_REQUIRED_SIGNERS = 14;
const BODY_KEY_NETWORK_ID = 15;

// Witness-set map keys. Key 0 is the vkey witness set; every other key
// (native scripts, bootstrap witnesses, Plutus v1/v2/v3) is counted as a
// "script/other" witness without being deep-decoded.
const WITNESS_KEY_VKEY = 0;

// inputs, vkey_witnesses, and required_signers are CBOR sets (tag 258). The
// permissive decoder may surface a set as a JS `Set` or an `Array` depending
// on how the producer encoded it; normalise both to an array.
function asArray(v: unknown): unknown[] {
  if (v instanceof Set) return [...v];
  if (Array.isArray(v)) return v;
  return [];
}

function asMap(v: unknown): Map<unknown, unknown> | null {
  return v instanceof Map ? v : null;
}

/**
 * Decode the vkey witnesses of a transaction and verify each signature against
 * the transaction body.
 *
 * Each Cardano vkey witness is `[vkey(32B), signature(64B)]`; the signed
 * message is `blake2b256(txBody)` (the transaction hash). A witness whose vkey
 * or signature is malformed, or whose signature does not verify, is reported
 * with `signature_valid: false` rather than dropped — the caller surfaces it
 * informationally and never fails the record on it.
 */
export function decodeTxWitnesses(
  witnessSetBytes: Uint8Array,
  txBodyBytes: Uint8Array,
): VerifyTxWitness[] {
  const witnessSet = asMap(decodeCbor(witnessSetBytes));
  if (witnessSet === null) return [];
  const vkeyWitnesses = asArray(witnessSet.get(WITNESS_KEY_VKEY));
  const txHash = blake2b256(txBodyBytes);

  const out: VerifyTxWitness[] = [];
  for (const entry of vkeyWitnesses) {
    const pair = asArray(entry);
    const vkey = pair[0];
    const signature = pair[1];
    if (
      !(vkey instanceof Uint8Array) ||
      vkey.length !== ED25519_PUBLIC_KEY_LENGTH ||
      !(signature instanceof Uint8Array) ||
      signature.length !== ED25519_SIGNATURE_LENGTH
    ) {
      // A structurally malformed witness still describes an attempted
      // authorisation; surface what we can (when the vkey is a valid pubkey)
      // and mark the signature invalid.
      if (vkey instanceof Uint8Array && vkey.length === ED25519_PUBLIC_KEY_LENGTH) {
        out.push({
          type: 'vkey',
          vkey: bytesToHex(vkey),
          key_hash: bytesToHex(blake2b224(vkey)),
          signature_valid: false,
        });
      }
      continue;
    }
    let signatureValid: boolean;
    try {
      signatureValid = verifyEd25519({ publicKey: vkey, message: txHash, signature });
    } catch {
      signatureValid = false;
    }
    out.push({
      type: 'vkey',
      vkey: bytesToHex(vkey),
      key_hash: bytesToHex(blake2b224(vkey)),
      signature_valid: signatureValid,
    });
  }
  return out;
}

/**
 * Count the witness-set entries that are NOT vkey witnesses (native scripts,
 * bootstrap witnesses, Plutus v1/v2/v3). These are summed as a single
 * "script/other" count without deep-decoding their contents.
 */
function countScriptWitnesses(witnessSetBytes: Uint8Array): number {
  const witnessSet = asMap(decodeCbor(witnessSetBytes));
  if (witnessSet === null) return 0;
  let count = 0;
  for (const [key, value] of witnessSet) {
    if (key === WITNESS_KEY_VKEY) continue;
    count += asArray(value).length;
  }
  return count;
}

/**
 * Decode a transaction body into a JSON-safe summary: fee, input/output counts,
 * the output addresses + lovelace amounts, validity interval, required signer
 * key hashes, and network id.
 *
 * All lovelace amounts are serialised as DECIMAL STRINGS so they survive JSON
 * round-trips exactly (Cardano coin values can exceed `Number.MAX_SAFE_INTEGER`
 * and BigInt is not JSON-native). Coin math is performed with BigInt internally.
 */
export function decodeTxSummary(
  txBodyBytes: Uint8Array,
  witnessSetBytes: Uint8Array,
  network: 'mainnet' | 'preprod',
): VerifyTxSummary {
  const body = asMap(decodeCbor(txBodyBytes));
  if (body === null) {
    throw new RangeError('MALFORMED_CBOR: tx body is not a CBOR map');
  }

  const inputs = asArray(body.get(BODY_KEY_INPUTS));
  const outputsRaw = asArray(body.get(BODY_KEY_OUTPUTS));

  const outputs: VerifyTxOutput[] = [];
  let totalOutput = 0n;
  for (const o of outputsRaw) {
    const { addressBytes, lovelace } = readOutput(o);
    totalOutput += lovelace;
    outputs.push({
      address: encodeCardanoAddress(addressBytes, network),
      lovelace: lovelace.toString(),
    });
  }

  const requiredSigners = asArray(body.get(BODY_KEY_REQUIRED_SIGNERS))
    .filter((s): s is Uint8Array => s instanceof Uint8Array)
    .map((s) => bytesToHex(s));

  const summary: {
    -readonly [K in keyof VerifyTxSummary]: VerifyTxSummary[K];
  } = {
    fee_lovelace: coinToString(body.get(BODY_KEY_FEE)),
    input_count: inputs.length,
    output_count: outputs.length,
    outputs,
    total_output_lovelace: totalOutput.toString(),
    script_witness_count: countScriptWitnesses(witnessSetBytes),
  };

  const invalidBefore = body.get(BODY_KEY_INVALID_BEFORE);
  if (typeof invalidBefore === 'number') summary.invalid_before = invalidBefore;
  else if (typeof invalidBefore === 'bigint') summary.invalid_before = Number(invalidBefore);

  const invalidHereafter = body.get(BODY_KEY_INVALID_HEREAFTER);
  if (typeof invalidHereafter === 'number') summary.invalid_hereafter = invalidHereafter;
  else if (typeof invalidHereafter === 'bigint') summary.invalid_hereafter = Number(invalidHereafter);

  if (requiredSigners.length > 0) summary.required_signer_key_hashes = requiredSigners;

  const networkId = body.get(BODY_KEY_NETWORK_ID);
  if (typeof networkId === 'number') summary.network_id = networkId;
  else if (typeof networkId === 'bigint') summary.network_id = Number(networkId);

  return summary;
}

// A transaction output is EITHER a legacy array `[address, amount]` OR a map
// `{0: address, 1: amount}` (post-Babbage). `amount` is either a bare coin
// (uint) or a `[coin, multiasset]` pair — only the coin (lovelace) component is
// summarised here.
function readOutput(output: unknown): { addressBytes: Uint8Array; lovelace: bigint } {
  let address: unknown;
  let amount: unknown;
  if (Array.isArray(output)) {
    address = output[0];
    amount = output[1];
  } else if (output instanceof Map) {
    address = output.get(0);
    amount = output.get(1);
  } else {
    throw new RangeError('MALFORMED_CBOR: tx output is neither a CBOR array nor a CBOR map');
  }
  if (!(address instanceof Uint8Array)) {
    throw new RangeError('MALFORMED_CBOR: tx output address is not a byte string');
  }
  const lovelace = Array.isArray(amount) ? toBigInt(amount[0]) : toBigInt(amount);
  return { addressBytes: address, lovelace };
}

function coinToString(v: unknown): string {
  return toBigInt(v).toString();
}

function toBigInt(v: unknown): bigint {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isInteger(v)) return BigInt(v);
  throw new RangeError(`MALFORMED_CBOR: expected an integer coin value, got ${typeof v}`);
}

// -----------------------------------------------------------------------------
// Cardano address bech32 encoding (BIP-173, the CIP-19 bech32 form).
// -----------------------------------------------------------------------------
//
// Implemented inline so the published SDK keeps a minimal, auditable dependency
// surface (the verifier's only third-party deps are the cryptographic core).
// The header byte's high nibble is the address type and its low nibble is the
// network id (0 = testnet, 1 = mainnet). Payment-address types 0–7 use the
// `addr` HRP; stake/reward types 14–15 use the `stake` HRP. The header's
// network nibble is authoritative for the `_test` suffix; the caller's
// `network` argument is the fallback when a header is ambiguous.

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function encodeCardanoAddress(addressBytes: Uint8Array, network: 'mainnet' | 'preprod'): string {
  if (addressBytes.length === 0) {
    throw new RangeError('MALFORMED_CBOR: empty address byte string');
  }
  const header = addressBytes[0]!;
  const addressType = header >> 4;
  const networkNibble = header & 0x0f;
  const isStake = addressType === 14 || addressType === 15;
  // The header's network nibble is authoritative. Fall back to the caller's
  // network only when the nibble is not the canonical 0 (testnet) / 1 (mainnet).
  const isTestnet =
    networkNibble === 0 ? true : networkNibble === 1 ? false : network === 'preprod';
  const base = isStake ? 'stake' : 'addr';
  const hrp = isTestnet ? `${base}_test` : base;
  return bech32Encode(hrp, addressBytes);
}

function bech32Polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const value of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= generators[i]!;
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

// 8-bit → 5-bit regrouping with zero-padding of the final group (the encode
// direction always pads).
function bech32ToWords(data: Uint8Array): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << 5) - 1;
  for (const value of data) {
    acc = (acc << 8) | value;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >> bits) & maxv);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & maxv);
  return out;
}

function bech32Encode(hrp: string, data: Uint8Array): string {
  const words = bech32ToWords(data);
  const polymodInput = bech32HrpExpand(hrp).concat(words, [0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(polymodInput) ^ 1;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
  let result = `${hrp}1`;
  for (const w of words.concat(checksum)) result += BECH32_CHARSET.charAt(w);
  return result;
}
