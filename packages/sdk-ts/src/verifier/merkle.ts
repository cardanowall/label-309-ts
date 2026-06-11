// Merkle list-commitment verification.
//
// For each `record.merkle[i]` the verifier obtains the leaves-list document
// (caller-supplied bytes, or fetched from `merkle[i].uris[]` under the same
// first-success / attribution / fetch-ceiling semantics as item content),
// validates it against the normative CBOR leaves-list container — the ONLY
// accepted wire form — recomputes the RFC 9162 §2.1.1 root, and compares
// byte-exact against the on-chain commitment.
//
// The record-attributable codes (SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED /
// SCHEMA_MERKLE_LEAVES_MALFORMED / SCHEMA_MERKLE_LEAF_COUNT_MISMATCH /
// MERKLE_ROOT_MISMATCH) hold the record to account only for an ATTRIBUTABLE
// leaves-list — supplied out-of-band, or fetched with a verified
// content-address binding. An unattributable fetched document failing them is
// URI_PROVIDER_INTEGRITY_MISMATCH (warning) and the remaining sources are
// tried.
//
// A claim left with no attributable leaves-list is MERKLE_LEAVES_UNAVAILABLE,
// whose severity is context-dependent (the commitment floor): warning when at
// least one other content commitment of the record was verified, error
// (network class, verdict `unverifiable`) when the unavailability leaves the
// record with no verified content commitment. Because the floor needs the
// whole-record picture, this module returns the unavailability as a PENDING
// marker and the report assembly emits the issue once every content check has
// run.

import { merkleSha2256Root } from '@cardanowall/crypto-core/hash';
import { decodeLeavesList, MerkleLeavesListError } from '@cardanowall/crypto-core/merkle';
import { compareCt } from '@cardanowall/crypto-core/util';
import type { MerkleCommit } from '@cardanowall/poe-standard';

import {
  iterateBlobSources,
  providerMismatchPath,
  type BlobIterationFlags,
  type ContentFetchContext,
} from './content';
import type { IssuePath } from './issues';
import type { ContentCheck } from './types';

// v1 registers exactly one Merkle commitment algorithm; this verifier
// implements it, so MERKLE_UNSUPPORTED never fires here (an unregistered
// identifier is already rejected by the structural validator with
// UNSUPPORTED_MERKLE_COMMIT_ALG).
const MERKLE_ALG = 'rfc9162-sha256';

export interface MerkleCommitOutcome {
  readonly contentCheck: ContentCheck;
  // Set when the claim ended unchecked because no attributable leaves-list
  // could be obtained; the report assembly emits MERKLE_LEAVES_UNAVAILABLE
  // (or CONTENT_FETCH_LIMIT_EXCEEDED) with floor-resolved severity.
  readonly unavailable?: {
    readonly path: IssuePath;
    readonly limitExceeded: boolean;
  };
}

type LeavesValidation =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code:
        | 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED'
        | 'SCHEMA_MERKLE_LEAVES_MALFORMED'
        | 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH'
        | 'MERKLE_ROOT_MISMATCH';
      readonly message: string;
    };

// Validate one acquired leaves-list document against the on-chain commitment:
// container grammar, document-internal consistency, RFC 9162 root recompute,
// and the leaf-count binding.
function validateLeavesDocument(bytes: Uint8Array, commit: MerkleCommit): LeavesValidation {
  let decoded;
  try {
    decoded = decodeLeavesList(bytes);
  } catch (e) {
    if (e instanceof MerkleLeavesListError) {
      const code =
        e.code === 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED' ||
        e.code === 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH' ||
        e.code === 'MERKLE_ROOT_MISMATCH'
          ? e.code
          : ('SCHEMA_MERKLE_LEAVES_MALFORMED' as const);
      return { ok: false, code, message: e.message };
    }
    return {
      ok: false,
      code: 'SCHEMA_MERKLE_LEAVES_MALFORMED',
      message: e instanceof Error ? e.message : String(e),
    };
  }
  if (BigInt(decoded.leafCount) !== BigInt(commit.leaf_count)) {
    return {
      ok: false,
      code: 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH',
      message: `leaves-list carries ${decoded.leafCount} leaves but the on-chain commitment declares ${commit.leaf_count}`,
    };
  }
  const recomputed = merkleSha2256Root(decoded.leaves);
  if (!compareCt(recomputed, commit.root)) {
    return {
      ok: false,
      code: 'MERKLE_ROOT_MISMATCH',
      message: 'the RFC 9162 root recomputed from the leaves-list does not equal the on-chain root',
    };
  }
  return { ok: true };
}

export async function checkMerkleCommit(args: {
  readonly commit: MerkleCommit;
  readonly commitIndex: number;
  readonly outOfBand?: Uint8Array | undefined;
  readonly fetchContent: boolean;
  readonly ctx: ContentFetchContext;
}): Promise<MerkleCommitOutcome> {
  const { commit, commitIndex, ctx } = args;
  const basePath: IssuePath = ['merkle', commitIndex];

  if (commit.alg !== MERKLE_ALG) {
    // Defence-in-depth: the structural validator already rejected unknown
    // identifiers, so an unimplemented-but-registered algorithm cannot occur
    // in v1 (the registry has exactly one member).
    ctx.issues.add(
      'UNSUPPORTED_MERKLE_COMMIT_ALG',
      [...basePath, 'alg'],
      `merkle commitment algorithm "${commit.alg}" is not implemented`,
    );
    return { contentCheck: 'not_checked' };
  }

  const uris = commit.uris ?? [];
  // Offline with no out-of-band document: the claim is simply not checked —
  // the fetch was suppressed by policy, not unavailable.
  if (!args.fetchContent && args.outOfBand === undefined) {
    return { contentCheck: 'not_checked' };
  }

  const flags: BlobIterationFlags = { limitExceeded: false };
  for await (const blob of iterateBlobSources({
    outOfBand: args.outOfBand,
    uris,
    allowFetch: args.fetchContent,
    basePath,
    ctx,
    flags,
  })) {
    const validation = validateLeavesDocument(blob.bytes, commit);
    if (validation.ok) {
      return { contentCheck: 'checked' };
    }
    if (blob.attributable()) {
      ctx.issues.add(validation.code, basePath, validation.message);
      return { contentCheck: 'mismatched' };
    }
    ctx.issues.add(
      'URI_PROVIDER_INTEGRITY_MISMATCH',
      providerMismatchPath(basePath, blob),
      `leaves-list bytes fetched from "${blob.uri ?? 'unknown source'}" fail validation (${validation.code}) and could not be attributed to the URI's content address; the serving provider is indicted, not the record`,
    );
  }

  return {
    contentCheck: 'not_checked',
    unavailable: { path: basePath, limitExceeded: flags.limitExceeded },
  };
}
