// Sealed-PoE decryption.
//
// Two mutually-exclusive on-wire paths:
//   * `enc.slots[]` (sealed-recipient, X25519 ECIES) — invokes
//     `eciesSealedPoeUnwrap` from `@cardanowall/crypto-core/sealed-poe`.
//   * `enc.passphrase` (Argon2id-derived CEK) — derives the CEK and runs
//     the AEAD primitive directly (empty AAD on the passphrase path).
//
// After successful unwrap (either path), the verifier recomputes every
// content-hash entry in `item.hashes` and compares to the recovered plaintext.
// Mismatch surfaces as `URI_INTEGRITY_MISMATCH`.

import { argon2idV13 } from '@cardanowall/crypto-core/kdf';
import { xchacha20Poly1305Decrypt, AeadVerificationError } from '@cardanowall/crypto-core/aead';
import { blake2b256, sha256 } from '@cardanowall/crypto-core/hash';
import { eciesSealedPoeUnwrap, sealedEnvelopeFromParsed } from '@cardanowall/crypto-core/sealed-poe';
import { compareCt } from '@cardanowall/crypto-core/util';
import type { ItemEntry, PoeRecord } from '@cardanowall/poe-standard';

import { fetchItemCiphertext } from './fetch';
import type {
  DecryptionVerdict,
  FetchOutbound,
  HttpCallRecord,
  VerifyItemDecryption,
  VerifyTxInput,
  VerifyUriCheck,
} from './types';

// The v1 passphrase KDF registry has a single member.
const PASSPHRASE_KDF_ARGON2ID = 'argon2id' as const;

// Content-AEAD AAD is an empty bstr on the passphrase path.
const EMPTY_AAD = new Uint8Array(0);

export interface TryDecryptionsArgs {
  readonly record: PoeRecord;
  readonly input: VerifyTxInput;
  readonly fetchFn: FetchOutbound;
  readonly httpCalls: HttpCallRecord[];
  readonly uriChecksOut: VerifyUriCheck[];
  // When `false`, the verifier is running offline: it MUST NOT fetch a sealed
  // item's on-record `uris[]` ciphertext. Decryption then succeeds only for
  // items whose ciphertext the caller supplied out-of-band (`ciphertextBytes`);
  // others surface as `ciphertext-unavailable` with no outbound egress.
  readonly allowUriFetch: boolean;
}

export interface TryDecryptionsResult {
  readonly results: VerifyItemDecryption[];
}

export async function tryDecryptions(args: TryDecryptionsArgs): Promise<TryDecryptionsResult> {
  const { record, input } = args;
  const items = (record.items ?? []) as ItemEntry[];
  const out: VerifyItemDecryption[] = [];
  const reqs = input.decryption ?? [];

  for (const req of reqs) {
    const idx = req.itemIndex;
    if (!Number.isInteger(idx) || idx < 0 || idx >= items.length) {
      out.push({
        item_index: idx,
        verdict: 'no-enc-envelope',
        reason: 'itemIndex out of range',
      });
      continue;
    }
    const item = items[idx]!;
    const enc = item.enc as unknown;
    if (enc === undefined || enc === null || typeof enc !== 'object') {
      out.push({ item_index: idx, verdict: 'no-enc-envelope' });
      continue;
    }
    const encShape = enc as {
      readonly slots?: unknown;
      readonly passphrase?: unknown;
    };
    const hasSlots = Array.isArray(encShape.slots);
    const hasPassphrase = encShape.passphrase !== undefined && encShape.passphrase !== null;
    const reqHasSecret = 'recipientSecretKey' in req;
    const reqHasPassphrase = 'passphrase' in req;
    if (hasSlots && !reqHasSecret) {
      out.push({
        item_index: idx,
        verdict: 'wrong-input-shape',
        reason: 'WRONG_DECRYPTION_INPUT_SHAPE',
      });
      continue;
    }
    if (hasPassphrase && !reqHasPassphrase) {
      out.push({
        item_index: idx,
        verdict: 'wrong-input-shape',
        reason: 'WRONG_DECRYPTION_INPUT_SHAPE',
      });
      continue;
    }

    // Ciphertext acquisition: out-of-band bytes first, then (when fetching is
    // allowed) on-record `item.uris[]`, then `CIPHERTEXT_UNAVAILABLE`. Offline
    // mode (`allowUriFetch === false`) never reaches the network branch.
    const oobBytes = input.ciphertextBytes?.[idx];
    let ciphertext: Uint8Array | null;
    if (oobBytes !== undefined) {
      ciphertext = oobBytes;
    } else if (args.allowUriFetch && Array.isArray(item.uris) && item.uris.length > 0) {
      try {
        ciphertext = await fetchItemCiphertext({
          uris: item.uris as ReadonlyArray<ReadonlyArray<string>>,
          arweaveGateways: input.arweaveGatewayChain,
          ipfsGateways: input.ipfsGatewayChain,
          fetchFn: args.fetchFn,
          uriChecksOut: args.uriChecksOut,
          itemIndex: idx,
        });
      } catch (e) {
        const code = e instanceof Error ? e.message : 'CONTENT_UNAVAILABLE';
        const verdict: DecryptionVerdict =
          code === 'URI_TARGET_FORBIDDEN' ? 'ciphertext-unavailable' : 'content-unavailable';
        out.push({ item_index: idx, verdict, reason: code });
        continue;
      }
    } else {
      out.push({
        item_index: idx,
        verdict: 'ciphertext-unavailable',
        reason: 'CIPHERTEXT_UNAVAILABLE',
      });
      continue;
    }
    if (ciphertext === null) {
      out.push({
        item_index: idx,
        verdict: 'ciphertext-unavailable',
        reason: 'CIPHERTEXT_UNAVAILABLE',
      });
      continue;
    }

    let plaintext: Uint8Array | null = null;
    let failure: { verdict: DecryptionVerdict; reason: string } | null = null;
    if (reqHasSecret) {
      // Build the discriminated SealedEnvelope from the on-wire `enc` block,
      // dispatching on `enc.kem` (classical `{epk, wrap}` vs hybrid
      // `{kem_ct, wrap}`). A null result means the envelope isn't a sealed
      // recipient envelope we can unwrap — surface it as wrong-input-shape.
      const envelope = sealedEnvelopeFromParsed(enc as Parameters<typeof sealedEnvelopeFromParsed>[0]);
      if (envelope === null) {
        out.push({
          item_index: idx,
          verdict: 'wrong-input-shape',
          reason: 'WRONG_DECRYPTION_INPUT_SHAPE',
        });
        continue;
      }
      // ECIES sealed-PoE unwrap. The single-priv standalone-verifier form takes
      // the one secret matching the envelope's KEM (X25519 priv for classical,
      // X-Wing secret seed for hybrid); the per-slot loop inside dispatches on
      // `envelope.kem`. The helper returns a discriminated result — never throws
      // on auth failure.
      const unwrap = eciesSealedPoeUnwrap({
        envelope,
        ciphertext,
        recipientSecretKey: (req as { recipientSecretKey: Uint8Array }).recipientSecretKey,
      });
      if (unwrap.matched) {
        plaintext = unwrap.plaintext;
      } else {
        const map: Record<string, { verdict: DecryptionVerdict; reason: string }> = {
          WRONG_RECIPIENT_KEY: { verdict: 'wrong-key', reason: 'WRONG_RECIPIENT_KEY' },
          TAMPERED_HEADER: { verdict: 'tampered-header', reason: 'TAMPERED_HEADER' },
          TAMPERED_CIPHERTEXT: { verdict: 'tampered-ciphertext', reason: 'TAMPERED_CIPHERTEXT' },
        };
        failure = map[unwrap.reason] ?? {
          verdict: 'tampered-ciphertext',
          reason: 'TAMPERED_CIPHERTEXT',
        };
      }
    } else {
      try {
        plaintext = await decryptPassphrase({
          enc: enc as PassphraseEncEnvelope,
          ciphertext,
          passphrase: (req as { passphrase: string }).passphrase,
        });
      } catch (e) {
        if (e instanceof AeadVerificationError) {
          failure = { verdict: 'tampered-ciphertext', reason: 'TAMPERED_CIPHERTEXT' };
        } else if (e instanceof Error && e.message.startsWith('KDF_')) {
          failure = { verdict: 'kdf-failed', reason: e.message };
        } else {
          failure = {
            verdict: 'tampered-ciphertext',
            reason: e instanceof Error ? e.message : 'TAMPERED_CIPHERTEXT',
          };
        }
      }
    }

    if (failure !== null) {
      out.push({ item_index: idx, verdict: failure.verdict, reason: failure.reason });
      continue;
    }
    if (plaintext === null) {
      // Defensive — failure path should already have returned above.
      out.push({ item_index: idx, verdict: 'tampered-ciphertext', reason: 'TAMPERED_CIPHERTEXT' });
      continue;
    }

    // Post-unwrap plaintext-hash recompute: re-hash the recovered plaintext
    // under every content-hash entry the item carries and compare. Every
    // `enc`-bearing item carries at least one content-hash entry (the
    // structural validator enforces ENC_REQUIRES_CONTENT_HASH), so this is a
    // concrete boolean on successful decryption.
    const plaintextHashOk = recomputeHashes(item, plaintext);
    out.push({ item_index: idx, verdict: 'decrypted', plaintext_hash_ok: plaintextHashOk });
  }

  return { results: out };
}

interface PassphraseEncEnvelope {
  readonly scheme: number;
  readonly aead: string;
  readonly nonce: Uint8Array;
  readonly passphrase: {
    readonly alg: string;
    readonly salt: Uint8Array;
    readonly params: { readonly m: number; readonly t: number; readonly p: number };
  };
}

async function decryptPassphrase(args: {
  enc: PassphraseEncEnvelope;
  ciphertext: Uint8Array;
  passphrase: string;
}): Promise<Uint8Array> {
  const { enc, ciphertext, passphrase } = args;
  if (enc.passphrase.alg !== PASSPHRASE_KDF_ARGON2ID) {
    throw new Error(`KDF_DERIVATION_FAILED: unsupported passphrase alg ${enc.passphrase.alg}`);
  }
  // Passphrase normalisation: NFKC → collapse whitespace → trim → UTF-8. Must
  // match the producer's normalisation exactly or the derived CEK won't match.
  const normalised = passphrase.normalize('NFKC').replace(/\s+/g, ' ').trim();
  const password = new TextEncoder().encode(normalised);
  let cek: Uint8Array;
  try {
    cek = await argon2idV13({
      password,
      salt: enc.passphrase.salt,
      memSizeKB: enc.passphrase.params.m,
      iterations: enc.passphrase.params.t,
      parallelism: enc.passphrase.params.p,
      outBytes: 32,
    });
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new Error(`KDF_DERIVATION_FAILED: ${reason}`, { cause });
  }
  if (enc.aead !== 'xchacha20-poly1305') {
    throw new Error(`KDF_DERIVATION_FAILED: unsupported aead ${enc.aead}`);
  }
  return xchacha20Poly1305Decrypt({
    key: cek,
    nonce: enc.nonce,
    aad: EMPTY_AAD,
    ciphertext,
  });
}

function recomputeHashes(item: ItemEntry, plaintext: Uint8Array): boolean {
  // `item.hashes` is a text-keyed map of algorithm id → expected digest;
  // cbor2 surfaces it as a plain JS object. The recovered plaintext is
  // "hash-ok" only when there is at least one entry AND every entry names a
  // hash we can recompute AND its digest matches. An empty map, or any entry
  // whose alg we don't recognise, is NOT silently treated as a pass: returning
  // `true` there would vacuously certify ciphertext whose integrity we never
  // actually checked. (Mirrors the CLI's `recomputeItemHashes`, which returns
  // `UNSUPPORTED_HASH_ALG` on an unknown alg.)
  const entries = Object.entries(item.hashes);
  if (entries.length === 0) return false;
  for (const [alg, digest] of entries) {
    if (alg === 'sha2-256') {
      if (!compareCt(sha256(plaintext), digest)) return false;
    } else if (alg === 'blake2b-256') {
      if (!compareCt(blake2b256(plaintext), digest)) return false;
    } else {
      // Unknown/unsupported hash alg — cannot certify integrity.
      return false;
    }
  }
  return true;
}
