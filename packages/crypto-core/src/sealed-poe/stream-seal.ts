// High-level streaming sealed-PoE seal / unwrap. These wrap the incremental
// `StreamSealer` / `StreamOpener` seam (see `stream.ts`) and the envelope layer
// (`buildSealedEnvelope` / `eciesSealedPoeTrialDecrypt`) into one async-iterable
// API, so a multi-gigabyte payload is sealed or opened without ever buffering
// the whole plaintext or ciphertext. The output is byte-identical to the
// buffered `eciesSealedPoeWrap` / `streamSeal` path for the same CEK + nonce:
// the envelope is produced up front (it depends only on CEK, nonce, recipients,
// and hashes — never on the plaintext), then the body is re-chunked to exactly
// CHUNK_SIZE and driven through the same per-chunk AEAD.
//
// The source's read boundaries are NOT the STREAM chunk boundaries: an
// `AsyncIterable` may hand over bytes in any sizes. Both directions therefore
// re-chunk with a one-block EOF lookahead (`rechunk.ts`, shared with the
// streaming passphrase pair) — a full-size block is kept PENDING and only
// marked `final` once the next read proves end-of-input — because the STREAM
// final flag lives in the nonce and a final chunk may itself be full size. An
// exact multiple of the chunk size has NO trailing empty chunk; only a truly
// empty input is the single empty-final case.
//
// Integrity contract (the SDK half of integrity-before-release): per-chunk
// Poly1305 plus the final-flag give per-segment authentication and truncation
// resistance, so each yielded plaintext block is individually verified. But the
// WHOLE-item hash recompute is the caller's release gate, and this API does NOT
// perform it (it is per-item, caller-owned). Bytes yielded by `unwrapStream`'s
// `plaintext` iterable are therefore TENTATIVE: the caller MUST await `outcome`,
// confirm it is `Matched`, AND recompute the plaintext item hash against the
// record's `hashes` before treating the bytes as released. A consumer should
// write them to a quarantine, not a final destination, until both checks pass.

import { rechunkPlaintext, rechunkSealed } from './rechunk';
import { StreamOpener, StreamSealer, StreamTamperedError } from './stream';
import { slotsPayloadKey, type ItemHashes } from './transcript';
import {
  eciesSealedPoeTrialDecrypt,
  type RecipientKeyBundle,
  type UnwrapFailureReason,
} from './unwrap';
import { buildSealedEnvelope, type EnvelopeArgs, type SealedEnvelope } from './wrap';

// Input to `sealStream`: the same envelope inputs as `eciesSealedPoeWrap` minus
// the buffered `plaintext`, which is supplied as an async stream instead. The
// deterministic overrides (`cek` / `nonce` / `ephemeralSecrets` / `eseeds` /
// `skipShuffle`) carry through unchanged so a vector can pin the streamed output
// against the buffered one. `signal` is the house cancellation primitive — it is
// checked at every chunk boundary while the body streams.
export interface SealStreamArgs extends EnvelopeArgs {
  readonly plaintext: AsyncIterable<Uint8Array>;
  readonly signal?: AbortSignal;
}

export interface SealStreamResult {
  // Fully resolved before the first body byte is read.
  readonly envelope: SealedEnvelope;
  // Drains the sealed body, CHUNK_SIZE plaintext at a time. Consume it to
  // completion to emit the whole ciphertext; the concatenation is byte-identical
  // to `eciesSealedPoeWrap(...).ciphertext` for the same CEK + nonce.
  readonly ciphertext: AsyncIterable<Uint8Array>;
}

// Recipient key material for `unwrapStream`, mirroring the three forms
// `eciesSealedPoeUnwrap` accepts (exactly one MUST be supplied):
//
//   • `recipientSecretKey`  — single X25519 private key (standalone verifier).
//   • `recipientSecretKeys` — flat, KEM-pre-selected private-key chain
//                             (current + archived, newest first).
//   • `recipientKeyBundle`  — both KEMs' secret lists; the dispatch selects the
//                             right one from `envelope.kem`.
export type UnwrapStreamKeys =
  | { readonly recipientSecretKey: Uint8Array }
  | { readonly recipientSecretKeys: ReadonlyArray<Uint8Array> }
  | { readonly recipientKeyBundle: RecipientKeyBundle };

export interface UnwrapStreamArgs {
  readonly envelope: SealedEnvelope;
  readonly ciphertext: AsyncIterable<Uint8Array>;
  // The item's plaintext-hash claim, bound into the slots transcript. An
  // envelope spliced onto a different hashes map fails per-slot acceptance.
  readonly hashes: ItemHashes;
  readonly keys: UnwrapStreamKeys;
  readonly signal?: AbortSignal;
}

// The decrypt outcome the caller MUST check. `Matched` means every sealed chunk
// authenticated and the stream was not truncated — but the bytes stay tentative
// until the caller's whole-item hash recompute passes. `NotMatched` carries the
// (locally diagnostic) failure reason: `WRONG_RECIPIENT_KEY` when trial-decrypt
// found no readable slot (nothing is written), `TAMPERED_CIPHERTEXT` when a
// sealed chunk failed its tag or the stream was truncated mid-body.
export type StreamUnwrapOutcome =
  | { readonly matched: true }
  | { readonly matched: false; readonly reason: UnwrapFailureReason };

export interface UnwrapStreamResult {
  // Resolves (never rejects) once the `plaintext` iterable has been fully driven
  // — or immediately, with `WRONG_RECIPIENT_KEY`, when trial-decrypt found no
  // readable slot. A mid-stream tamper resolves this to `TAMPERED_CIPHERTEXT`
  // AND throws from the `plaintext` iterable, so neither a draining nor a
  // checking consumer can miss it.
  readonly outcome: Promise<StreamUnwrapOutcome>;
  // Yields verified plaintext, CHUNK_SIZE at a time. TENTATIVE until `outcome`
  // is `Matched` and the caller's item-hash recompute passes (see file header).
  readonly plaintext: AsyncIterable<Uint8Array>;
}

/**
 * Seal a sealed-PoE record while streaming its body. The envelope (slots +
 * slots_mac) is built up front and returned immediately; the `ciphertext` async
 * iterable drives the body seal lazily as it is consumed. Concatenating every
 * yielded chunk produces bytes byte-identical to
 * `eciesSealedPoeWrap(...).ciphertext` for the same CEK + nonce. Peak memory is
 * one CHUNK_SIZE plaintext block plus one sealed (CHUNK_SIZE + TAG_SIZE) block.
 *
 * `signal` aborts the body seal at the next chunk boundary; the envelope is
 * already resolved, so aborting only stops the (not-yet-published) ciphertext.
 */
export async function sealStream(args: SealStreamArgs): Promise<SealStreamResult> {
  args.signal?.throwIfAborted();
  const { envelope, payloadKey } = buildSealedEnvelope(args);

  async function* drive(): AsyncGenerator<Uint8Array> {
    const sealer = new StreamSealer(payloadKey);
    for await (const { chunk, final } of rechunkPlaintext(args.plaintext, args.signal)) {
      yield sealer.sealChunk(chunk, final);
    }
  }

  return { envelope, ciphertext: drive() };
}

/**
 * Unwrap a sealed-PoE record while streaming its body. Trial-decrypt runs up
 * front (header-only): a structural envelope/key error throws synchronously from
 * this call (as in `eciesSealedPoeUnwrap`); a no-match resolves `outcome` to
 * `WRONG_RECIPIENT_KEY` and the `plaintext` iterable yields nothing. On a match
 * the body is opened CHUNK_SIZE at a time, each chunk authenticated before its
 * plaintext is yielded. A tag failure or truncation mid-body resolves `outcome`
 * to `TAMPERED_CIPHERTEXT` and throws from the iterable.
 *
 * Yielded bytes are TENTATIVE: the caller MUST await `outcome`, confirm
 * `Matched`, and recompute the whole-item hash against the record's `hashes`
 * before releasing them (see the file header).
 */
export function unwrapStream(args: UnwrapStreamArgs): UnwrapStreamResult {
  args.signal?.throwIfAborted();
  const { envelope, hashes } = args;

  // Run the header-only trial-decrypt eagerly: structural errors (unsupported
  // KEM, malformed slots, bad key length) throw from here, exactly as the
  // buffered unwrap throws them, before any iterable is handed back.
  const trial =
    'recipientSecretKey' in args.keys
      ? eciesSealedPoeTrialDecrypt({
          envelope,
          hashes,
          recipientSecretKeys: [args.keys.recipientSecretKey],
        })
      : 'recipientSecretKeys' in args.keys
        ? eciesSealedPoeTrialDecrypt({
            envelope,
            hashes,
            recipientSecretKeys: args.keys.recipientSecretKeys,
          })
        : eciesSealedPoeTrialDecrypt({
            envelope,
            hashes,
            recipientKeyBundle: args.keys.recipientKeyBundle,
          });

  let resolveOutcome!: (outcome: StreamUnwrapOutcome) => void;
  const outcome = new Promise<StreamUnwrapOutcome>((resolve) => {
    resolveOutcome = resolve;
  });

  if (trial.kind === 'no_match') {
    // No readable slot — nothing is written. Per the streaming contract, the
    // trial-decrypt no-match (wrong key, tampered header, or CEK conflict, which
    // it does not distinguish) surfaces as WRONG_RECIPIENT_KEY.
    resolveOutcome({ matched: false, reason: 'WRONG_RECIPIENT_KEY' });
    // eslint-disable-next-line require-yield -- an empty body: nothing to yield.
    const empty = (async function* (): AsyncGenerator<Uint8Array> {
      return;
    })();
    return { outcome, plaintext: empty };
  }

  const payloadKey = slotsPayloadKey({ cek: trial.cek, nonce: envelope.nonce });

  async function* drive(): AsyncGenerator<Uint8Array> {
    const opener = new StreamOpener(payloadKey);
    try {
      for await (const { chunk, final } of rechunkSealed(args.ciphertext, args.signal)) {
        yield opener.openChunk(chunk, final);
      }
    } catch (e) {
      if (e instanceof StreamTamperedError) {
        // A per-chunk tag failure or a truncated/over-long stream: the bytes
        // already yielded are quarantine the caller discards. Settle the outcome
        // AND re-throw so a draining consumer cannot mistake it for success.
        resolveOutcome({ matched: false, reason: 'TAMPERED_CIPHERTEXT' });
      }
      throw e;
    }
    resolveOutcome({ matched: true });
  }

  return { outcome, plaintext: drive() };
}
