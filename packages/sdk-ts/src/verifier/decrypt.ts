// Sealed-PoE decryption.
//
// Two mutually-exclusive on-wire paths:
//   * `enc.slots[]` (sealed-recipient, X25519 ECIES) — invokes
//     `eciesSealedPoeUnwrap` from `@cardanowall/crypto-core/sealed-poe`.
//   * `enc.passphrase` (Argon2id-derived CEK) — derives the CEK, derives a
//     content `payload_key` from it, and opens the AEAD under a structured AAD
//     that binds the passphrase-KDF parameters.
//
// After successful unwrap (either path), the verifier recomputes every
// content-hash entry in `item.hashes` and compares to the recovered plaintext.
// Mismatch surfaces as `URI_INTEGRITY_MISMATCH`.

import { argon2idV13 } from '@cardanowall/crypto-core/kdf';
import { xchacha20Poly1305Decrypt, AeadVerificationError } from '@cardanowall/crypto-core/aead';
import { blake2b256, sha256 } from '@cardanowall/crypto-core/hash';
import {
  adContentPassphrase,
  assertCiphertextWithinBound,
  eciesSealedPoeUnwrap,
  passphrasePayloadKey,
  sealedEnvelopeFromParsed,
} from '@cardanowall/crypto-core/sealed-poe';
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

// Maximum raw passphrase length, in UTF-8 bytes, enforced BEFORE normalization
// and the Argon2id KDF. An oversized passphrase would otherwise drive
// unbounded NFKC / whitespace-collapse work and a large Argon2id input before
// any cost-bounded primitive runs; capping the raw input closes that pre-KDF
// DoS. The bound is byte length (not code-point count), so a short string of
// wide multi-byte characters is still measured by its encoded size. 4096 bytes
// is far above any human-chosen passphrase. Identical across every SDK.
export const MAX_PASSPHRASE_INPUT_BYTES = 4096;

// The 25 codepoints carrying the Unicode `White_Space` property under Unicode
// 16.0. The passphrase normalization profile collapses every maximal run of
// these to a single U+0020. This is an explicit set on purpose: neither a regex
// `\s` class nor a language `isWhitespace` predicate matches this set exactly,
// and the CEK derivation must be byte-identical across implementations. Exported
// so the exact membership can be pinned by a test, the same way the Python twin
// pins its frozenset.
export const UNICODE_WHITE_SPACE = new Set<number>([
  0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680, 0x2000, 0x2001, 0x2002,
  0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f,
  0x3000,
]);

// Passphrase normalization profile `cardano-poe-pw-norm-v1`, applied in order:
// NFKC (UAX #15, Unicode 16.0), collapse every maximal run of White_Space to a
// single U+0020, trim leading/trailing, then UTF-8. The producer applies the
// identical transform, so a single divergence here yields a CEK that fails to
// decrypt an honest record. Exported so the cross-implementation normalization
// contract can be pinned directly by tests, independent of a full decrypt run.
export function normalizePassphrase(passphrase: string): Uint8Array {
  const nfkc = passphrase.normalize('NFKC');
  let collapsed = '';
  let inRun = false;
  for (const ch of nfkc) {
    if (UNICODE_WHITE_SPACE.has(ch.codePointAt(0)!)) {
      if (!inRun) {
        collapsed += ' ';
        inRun = true;
      }
    } else {
      collapsed += ch;
      inRun = false;
    }
  }
  // Trim a single leading/trailing collapsed U+0020 (runs already collapsed).
  if (collapsed.startsWith(' ')) collapsed = collapsed.slice(1);
  if (collapsed.endsWith(' ')) collapsed = collapsed.slice(0, -1);
  return new TextEncoder().encode(collapsed);
}

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
      const envelope = sealedEnvelopeFromParsed(
        enc as Parameters<typeof sealedEnvelopeFromParsed>[0],
      );
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
  // Pre-KDF input cap: reject an oversized raw passphrase before normalization
  // or Argon2id, so it cannot drive unbounded pre-KDF work. Byte length of the
  // raw UTF-8 encoding, not code-point count.
  const rawPassphraseBytes = new TextEncoder().encode(passphrase).length;
  if (rawPassphraseBytes > MAX_PASSPHRASE_INPUT_BYTES) {
    throw new Error(
      `KDF_DERIVATION_FAILED: passphrase length ${rawPassphraseBytes} bytes exceeds the maximum ${MAX_PASSPHRASE_INPUT_BYTES} bytes`,
    );
  }
  const password = normalizePassphrase(passphrase);
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
  // Reject an over-large ciphertext before the single-shot AEAD open.
  assertCiphertextWithinBound(ciphertext.length);
  // Content is opened under a derived payload_key, with a structured AAD that
  // binds the passphrase-KDF parameters: tampering with `salt` or any `params`
  // value after encryption changes the AAD and makes the AEAD open fail. The
  // normalization profile id is pinned into the AAD as a scheme-fixed constant.
  const payloadKey = passphrasePayloadKey({ cek, nonce: enc.nonce });
  const aad = adContentPassphrase({
    nonce: enc.nonce,
    passphrase: {
      alg: enc.passphrase.alg,
      salt: enc.passphrase.salt,
      params: enc.passphrase.params,
    },
  });
  return xchacha20Poly1305Decrypt({
    key: payloadKey,
    nonce: enc.nonce,
    aad,
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
