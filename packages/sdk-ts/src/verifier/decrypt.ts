// Sealed-PoE decryption (recipient verifier).
//
// For each `enc`-bearing item — when the run's decryption keyring is
// non-empty — the verifier acquires the ciphertext blob (out-of-band bytes,
// or fetched from `item.uris[]`), dispatches on the item's on-wire key path,
// and attempts every applicable keyring credential independently:
//
//   * `enc.slots`      — the sealed-PoE trial-decrypt loop: per-slot
//                        acceptance folds the KEM validity bit, the
//                        wrap-open, and the slot-set MAC over `slots_hash`
//                        into one constant-time decision, then the recovered
//                        CEK opens the segmented STREAM chunk by chunk.
//   * `enc.passphrase` — Argon2id over the pinned-normalization passphrase,
//                        the leading 32-byte key-commitment header verified
//                        in constant time BEFORE any chunk opens, then the
//                        same STREAM open.
//
// Failure attribution:
//
//   * WRONG_RECIPIENT_KEY / TAMPERED_HEADER bind to ON-CHAIN data (the slot
//     set and its MAC), so they are terminal for the item no matter which
//     blob was tried.
//   * TAMPERED_CIPHERTEXT is blob-dependent: it holds the blob against the
//     record only when the blob is ATTRIBUTABLE (out-of-band, or fetched
//     with a verified content-address binding). The same failure over an
//     unattributable fetched blob is URI_PROVIDER_INTEGRITY_MISMATCH
//     (warning) and the remaining sources are tried; exhaustion without an
//     attributable blob ends as CIPHERTEXT_UNAVAILABLE (verdict
//     `unverifiable`).
//   * The post-decryption plaintext-hash recheck needs no attribution
//     qualifier: ciphertext that opens under the authenticated envelope is
//     attributed by the AEAD itself, so a recheck mismatch is always
//     URI_INTEGRITY_MISMATCH and the record's verdict is `failed` — no
//     "decrypted" surface may outrank it.

import {
  EciesSealedPoeError,
  eciesSealedPoeUnwrap,
  passphraseSealedPoeOpen,
  sealedEnvelopeFromParsed,
  type PassphraseSealedEnvelope,
  type UnwrapFailureReason,
} from '@cardanowall/crypto-core/sealed-poe';
import type { ErrorCode } from '@cardanowall/poe-standard';
import type { ItemEntry } from '@cardanowall/poe-standard';

import {
  iterateBlobSources,
  providerMismatchPath,
  type BlobIterationFlags,
  type ContentFetchContext,
} from './content';
import { recomputeItemHashes } from './items';
import type { IssuePath } from './issues';
import type { ContentCheck, DecryptionCredential, DecryptionOutcome } from './types';

export interface ItemDecryptionResult {
  readonly contentCheck: ContentCheck;
  readonly decryption: DecryptionOutcome;
}

type AttemptOutcome =
  | { readonly kind: 'opened'; readonly plaintext: Uint8Array }
  // Bound to on-chain data — retrying with a different blob cannot change it.
  | { readonly kind: 'header_failure'; readonly code: 'WRONG_RECIPIENT_KEY' | 'TAMPERED_HEADER' }
  // Blob-dependent: subject to the attribution split.
  | { readonly kind: 'blob_failure'; readonly code: 'TAMPERED_CIPHERTEXT' }
  // A caller-input / KDF problem independent of the blob — terminal.
  | { readonly kind: 'input_failure'; readonly code: ErrorCode; readonly message: string };

// Map a construction-API rejection to the wire error-code vocabulary. Codes
// that exist in the wire registry pass through verbatim; the
// construction-local pre-KDF input bound maps to KDF_DERIVATION_FAILED (the
// KDF input was rejected before derivation could run).
function inputFailureFrom(e: EciesSealedPoeError): AttemptOutcome {
  const code: ErrorCode =
    e.code === 'ENC_PASSPHRASE_UNNORMALIZABLE' ||
    e.code === 'ENC_PASSPHRASE_EMPTY' ||
    e.code === 'KDF_DERIVATION_FAILED'
      ? e.code
      : 'KDF_DERIVATION_FAILED';
  return { kind: 'input_failure', code, message: e.message };
}

async function attemptSlotsPath(args: {
  readonly enc: unknown;
  readonly hashes: Readonly<Record<string, Uint8Array>>;
  readonly ciphertext: Uint8Array;
  readonly secretKeys: ReadonlyArray<Uint8Array>;
}): Promise<AttemptOutcome> {
  const envelope = sealedEnvelopeFromParsed(
    args.enc as Parameters<typeof sealedEnvelopeFromParsed>[0],
  );
  if (envelope === null) {
    // Unreachable on a structurally validated record (the recipient-role
    // validator hard-rejects every envelope it cannot fully validate);
    // defensively classed as a header failure.
    return { kind: 'header_failure', code: 'TAMPERED_HEADER' };
  }
  let result;
  try {
    result = eciesSealedPoeUnwrap({
      envelope,
      ciphertext: args.ciphertext,
      hashes: args.hashes,
      recipientSecretKeys: args.secretKeys,
    });
  } catch (e) {
    if (e instanceof EciesSealedPoeError) return inputFailureFrom(e);
    throw e;
  }
  if (result.matched) {
    return { kind: 'opened', plaintext: result.plaintext };
  }
  const reason: UnwrapFailureReason = result.reason;
  if (reason === 'TAMPERED_CIPHERTEXT') {
    return { kind: 'blob_failure', code: 'TAMPERED_CIPHERTEXT' };
  }
  return { kind: 'header_failure', code: reason };
}

async function attemptPassphrasePath(args: {
  readonly enc: unknown;
  readonly hashes: Readonly<Record<string, Uint8Array>>;
  readonly blob: Uint8Array;
  readonly passphrases: ReadonlyArray<string>;
}): Promise<AttemptOutcome> {
  let firstFailure: AttemptOutcome | null = null;
  for (const passphrase of args.passphrases) {
    let outcome: AttemptOutcome;
    try {
      const result = await passphraseSealedPoeOpen({
        envelope: args.enc as PassphraseSealedEnvelope,
        blob: args.blob,
        passphrase,
        hashes: args.hashes,
      });
      outcome = result.matched
        ? { kind: 'opened', plaintext: result.plaintext }
        : // Wrong passphrase, tampered salt/params/header fields, a spliced
          // envelope, or a tampered stream — indistinguishable by design.
          { kind: 'blob_failure', code: 'TAMPERED_CIPHERTEXT' };
    } catch (e) {
      if (!(e instanceof EciesSealedPoeError)) throw e;
      outcome = inputFailureFrom(e);
    }
    if (outcome.kind === 'opened') return outcome;
    firstFailure ??= outcome;
  }
  // The keyring is non-empty by construction (the caller filtered applicable
  // credentials before dispatching here).
  return firstFailure!;
}

export async function decryptItem(args: {
  readonly item: ItemEntry;
  readonly itemIndex: number;
  readonly credentials: ReadonlyArray<DecryptionCredential>;
  readonly outOfBandCiphertext?: Uint8Array | undefined;
  readonly fetchContent: boolean;
  readonly ctx: ContentFetchContext;
}): Promise<ItemDecryptionResult> {
  const { item, itemIndex, ctx } = args;
  const basePath: IssuePath = ['items', itemIndex, 'enc'];
  const enc = item.enc as { slots?: unknown; passphrase?: unknown };
  const isSlotsPath = Array.isArray(enc.slots);

  // Applicable credentials for the item's on-wire key path. The two paths are
  // mutually exclusive on a validated record (ENC_EXCLUSIVITY_VIOLATION).
  const secretKeys: Uint8Array[] = [];
  const passphrases: string[] = [];
  for (const credential of args.credentials) {
    if ('recipientSecretKey' in credential) secretKeys.push(credential.recipientSecretKey);
    else passphrases.push(credential.passphrase);
  }
  const applicable = isSlotsPath ? secretKeys.length : passphrases.length;
  if (applicable === 0) {
    ctx.issues.add(
      'WRONG_DECRYPTION_INPUT_SHAPE',
      basePath,
      isSlotsPath
        ? 'the keyring holds no recipient secret key for this slots-path item'
        : 'the keyring holds no passphrase for this passphrase-path item',
    );
    return {
      contentCheck: 'not_checked',
      decryption: { decrypted: false, code: 'WRONG_DECRYPTION_INPUT_SHAPE' },
    };
  }

  const flags: BlobIterationFlags = { limitExceeded: false };
  for await (const blob of iterateBlobSources({
    outOfBand: args.outOfBandCiphertext,
    uris: item.uris ?? [],
    allowFetch: args.fetchContent,
    basePath: ['items', itemIndex],
    ctx,
    flags,
  })) {
    const outcome = isSlotsPath
      ? await attemptSlotsPath({
          enc,
          hashes: item.hashes,
          ciphertext: blob.bytes,
          secretKeys,
        })
      : await attemptPassphrasePath({
          enc,
          hashes: item.hashes,
          blob: blob.bytes,
          passphrases,
        });

    switch (outcome.kind) {
      case 'opened': {
        const plaintextHashOk = recomputeItemHashes(item.hashes, outcome.plaintext);
        if (!plaintextHashOk) {
          ctx.issues.add(
            'URI_INTEGRITY_MISMATCH',
            ['items', itemIndex],
            'decryption succeeded but the post-decryption plaintext-hash recheck failed; decrypted bytes are attributed by the AEAD itself, so the record is condemned',
          );
          return {
            contentCheck: 'mismatched',
            decryption: { decrypted: true, plaintextHashOk: false, code: 'URI_INTEGRITY_MISMATCH' },
          };
        }
        return { contentCheck: 'checked', decryption: { decrypted: true, plaintextHashOk: true } };
      }
      case 'header_failure': {
        ctx.issues.add(
          outcome.code,
          basePath,
          outcome.code === 'WRONG_RECIPIENT_KEY'
            ? 'no slot accepted any supplied recipient key — the key is not a recipient of this sealed PoE'
            : 'a slot wrap-opened but no candidate content-encryption key reproduces slots_mac — the authenticated envelope header fails its integrity check',
        );
        return {
          // `contentCheck` reports the plaintext-vs-hash comparison, which a
          // header failure never reaches — the claim is unchecked either way.
          // TAMPERED_HEADER still condemns the record through its issue.
          contentCheck: 'not_checked',
          decryption: { decrypted: false, code: outcome.code },
        };
      }
      case 'blob_failure': {
        if (blob.attributable()) {
          ctx.issues.add(
            'TAMPERED_CIPHERTEXT',
            basePath,
            'the ciphertext blob failed the decryption layer and is attributable (out-of-band, or content-address-bound to its URI); the record is condemned',
          );
          return {
            contentCheck: 'mismatched',
            decryption: { decrypted: false, code: 'TAMPERED_CIPHERTEXT' },
          };
        }
        ctx.issues.add(
          'URI_PROVIDER_INTEGRITY_MISMATCH',
          providerMismatchPath(['items', itemIndex], blob),
          `ciphertext bytes fetched from "${blob.uri ?? 'unknown source'}" fail the decryption layer and could not be attributed to the URI's content address; the serving provider is indicted, not the record`,
        );
        continue;
      }
      case 'input_failure': {
        ctx.issues.add(outcome.code, basePath, outcome.message);
        return {
          contentCheck: 'not_checked',
          decryption: { decrypted: false, code: outcome.code },
        };
      }
    }
  }

  const endCode: ErrorCode = flags.limitExceeded
    ? 'CONTENT_FETCH_LIMIT_EXCEEDED'
    : 'CIPHERTEXT_UNAVAILABLE';
  ctx.issues.add(
    endCode,
    ['items', itemIndex],
    flags.limitExceeded
      ? 'a ciphertext fetch for this item was aborted at the maxFetchBytes ceiling; decryption could not proceed'
      : 'no out-of-band ciphertext was supplied and no URI yielded an attributable blob; decryption could not proceed',
  );
  return { contentCheck: 'not_checked', decryption: { decrypted: false, code: endCode } };
}
