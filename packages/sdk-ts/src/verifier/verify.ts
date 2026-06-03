// CIP-309 standalone verifier entry point.
//
// Pipeline (steps run sequentially; the verdict is the worst outcome across them):
//   1. Resolve Cardano gateway + raw tx CBOR + confirmation depth.
//   2. Byte-faithful extract of label-309 metadata.
//   3. Structural validator (Part A; never throws).
//   4. Confirmation-depth check → INSUFFICIENT_CONFIRMATIONS / verdict 'pending'.
//   5. Profile-gated work (signed: signatures; sealed: enc structure;
//      recipient-sealed: decrypt). Out-of-profile fields emit
//      OUT_OF_PROFILE_SKIPPED (info) — not SCHEMA_UNKNOWN_FIELD.
//   6. Merkle list-commitment verification (awaited after step 5).
//   7. Three-state verdict emission with exit-code mapping.

import { SEVERITY, validatePoeRecord, type ValidationIssue } from '@cardanowall/poe-standard';

import { tryDecryptions } from './decrypt';
import { defaultFetchOutbound, wrapFetchOutbound } from './fetch';
import { verifyMerkleCommitments } from './merkle';
import { DEFAULT_PROFILE, planProfileSkips } from './profile';
import { extractLabel309Metadata, NotACip309RecordError, resolveCardanoTx } from './resolve';
import { verifyRecordSignatures } from './signatures';
import { sliceTxComponents } from './cbor-walker';
import { decodeTxSummary, decodeTxWitnesses } from './tx-witnesses';
import type {
  ExitCode,
  FetchOutbound,
  HttpCallRecord,
  Profile,
  VerifyItemDecryption,
  VerifyMerkleCheck,
  VerifyRecordSignature,
  VerifyReport,
  VerifyTxInput,
  VerifyUriCheck,
  Verdict,
} from './types';

export const CONFIRMATION_DEPTH_THRESHOLD_DEFAULT = 15;

type MutableReport = { -readonly [K in keyof VerifyReport]: VerifyReport[K] };

export async function verifyTx(input: VerifyTxInput): Promise<VerifyReport> {
  const profile = input.profile ?? DEFAULT_PROFILE;
  const threshold = input.confirmationDepthThreshold ?? CONFIRMATION_DEPTH_THRESHOLD_DEFAULT;
  const httpCalls: HttpCallRecord[] = [];
  const fetchFn = wrapFetchOutbound(
    input.fetchOutbound ?? defaultFetchOutbound,
    httpCalls,
    input.denyHosts,
  );

  const base = (
    over: Partial<VerifyReport> & Pick<VerifyReport, 'verdict' | 'exit_code'>,
  ): VerifyReport => ({
    tx_hash: input.txHash,
    network: 'cardano:mainnet',
    profile,
    num_confirmations: 0,
    confirmation_depth_threshold: threshold,
    metadata_present: false,
    validation: { valid: false },
    http_calls: httpCalls,
    ...over,
  });

  // 1. Resolve Cardano gateway + raw tx CBOR.
  let resolved;
  try {
    resolved = await resolveCardanoTx({ input, fetchFn });
  } catch (e) {
    if (e instanceof NotACip309RecordError) {
      return base({
        verdict: 'failed',
        exit_code: 1,
        validation: {
          valid: false,
          issues: [issueOf('METADATA_NOT_FOUND', [], e.message)],
        },
      });
    }
    return base({
      verdict: 'failed',
      exit_code: 2,
      validation: {
        valid: false,
        issues: [issueOf('PROVIDER_UNAVAILABLE', [], (e as Error).message)],
      },
    });
  }

  // 2. Byte-faithful label-309 extraction.
  let metadataBytes: Uint8Array | null;
  try {
    metadataBytes = extractLabel309Metadata(resolved.txCbor);
  } catch (e) {
    return base({
      verdict: 'failed',
      exit_code: 1,
      num_confirmations: resolved.numConfirmations,
      block_time: resolved.blockTime,
      block_slot: resolved.blockSlot,
      validation: {
        valid: false,
        issues: [issueOf('MALFORMED_CBOR', [], (e as Error).message)],
      },
    });
  }
  if (metadataBytes === null) {
    return base({
      verdict: 'failed',
      exit_code: 1,
      num_confirmations: resolved.numConfirmations,
      block_time: resolved.blockTime,
      block_slot: resolved.blockSlot,
      metadata_present: false,
      validation: {
        valid: false,
        issues: [issueOf('METADATA_NOT_FOUND', [], 'no label-309 metadata on this tx')],
      },
    });
  }

  return verifyResolvedRecord({
    input,
    metadataBytes,
    txCbor: resolved.txCbor,
    numConfirmations: resolved.numConfirmations,
    blockTime: resolved.blockTime,
    blockSlot: resolved.blockSlot,
    httpCalls,
    fetchFn,
  });
}

/**
 * `verifyResolved` — same pipeline as `verifyTx` starting from step 3
 * (structural validator). The caller has already resolved the label-309
 * metadata bytes + block-info tuple from somewhere other than a live chain
 * fetch (typically an indexer database mirror).
 *
 * Use this when you trust an upstream indexer for the (metadataCbor,
 * blockTime, blockSlot, numConfirmations) tuple and want to skip the
 * /tx_cbor + /tx_info round-trip. The caller is responsible for the
 * confidence that the supplied bytes actually came from a CIP-309 label-309
 * metadata field of a confirmed Cardano transaction.
 */
export async function verifyResolved(input: {
  txHash: string;
  metadataCbor: Uint8Array;
  // Raw on-chain transaction CBOR. When supplied, the report also carries the
  // transaction-level description (tx_witnesses, tx_summary, metadata_labels);
  // when absent, those three fields are left undefined. The label-309 record
  // is always taken from `metadataCbor`, never re-derived from `txCbor`.
  txCbor?: Uint8Array;
  numConfirmations: number;
  blockTime?: number;
  blockSlot?: number;
  network?: VerifyReport['network'];
  cardanoNetwork?: VerifyTxInput['cardanoNetwork'];
  profile?: Profile;
  confirmationDepthThreshold?: number;
  fetchOutbound?: FetchOutbound;
  denyHosts?: ReadonlyArray<string>;
  decryption?: VerifyTxInput['decryption'];
  // Mirrors `VerifyTxInput.verifyMerkle`. SSR callers pass `false` so the
  // viewer renders from indexed CBOR alone with no Arweave/IPFS leaves-list
  // fetch (deferred to a user-initiated client-side action instead).
  verifyMerkle?: boolean;
}): Promise<VerifyReport> {
  const httpCalls: HttpCallRecord[] = [];
  const fetchFn = wrapFetchOutbound(
    input.fetchOutbound ?? defaultFetchOutbound,
    httpCalls,
    input.denyHosts,
  );
  // Reuse the post-resolve pipeline by adapting the caller's args back into
  // the VerifyTxInput shape that signature/decryption/merkle helpers expect.
  const verifyTxInput: VerifyTxInput = {
    txHash: input.txHash,
    ...(input.profile !== undefined ? { profile: input.profile } : {}),
    ...(input.cardanoNetwork !== undefined ? { cardanoNetwork: input.cardanoNetwork } : {}),
    ...(input.confirmationDepthThreshold !== undefined
      ? { confirmationDepthThreshold: input.confirmationDepthThreshold }
      : {}),
    ...(input.fetchOutbound !== undefined ? { fetchOutbound: input.fetchOutbound } : {}),
    ...(input.denyHosts !== undefined ? { denyHosts: input.denyHosts } : {}),
    ...(input.decryption !== undefined ? { decryption: input.decryption } : {}),
    ...(input.verifyMerkle !== undefined ? { verifyMerkle: input.verifyMerkle } : {}),
  };
  const report = await verifyResolvedRecord({
    input: verifyTxInput,
    metadataBytes: input.metadataCbor,
    ...(input.txCbor !== undefined ? { txCbor: input.txCbor } : {}),
    numConfirmations: input.numConfirmations,
    ...(input.blockTime !== undefined ? { blockTime: input.blockTime } : {}),
    ...(input.blockSlot !== undefined ? { blockSlot: input.blockSlot } : {}),
    httpCalls,
    fetchFn,
  });
  if (input.network !== undefined) {
    return { ...report, network: input.network };
  }
  return report;
}

async function verifyResolvedRecord(args: {
  input: VerifyTxInput;
  metadataBytes: Uint8Array;
  txCbor?: Uint8Array;
  numConfirmations: number;
  blockTime?: number;
  blockSlot?: number;
  httpCalls: HttpCallRecord[];
  fetchFn: ReturnType<typeof wrapFetchOutbound>;
}): Promise<VerifyReport> {
  const {
    input,
    metadataBytes,
    txCbor,
    numConfirmations,
    blockTime,
    blockSlot,
    httpCalls,
    fetchFn,
  } = args;
  const profile = input.profile ?? DEFAULT_PROFILE;
  const threshold = input.confirmationDepthThreshold ?? CONFIRMATION_DEPTH_THRESHOLD_DEFAULT;

  // Transaction-level description — who authorised/paid for the anchoring,
  // distinct from record-level authorship. Decoded once when the raw tx CBOR
  // is available, then merged into every report shape below. This is pure
  // description: it never gates on profile and never changes the verdict.
  const txDescription = txCbor !== undefined ? decodeTxDescription(txCbor, input) : {};

  const base = (
    over: Partial<VerifyReport> & Pick<VerifyReport, 'verdict' | 'exit_code'>,
  ): VerifyReport => ({
    tx_hash: input.txHash,
    network: 'cardano:mainnet',
    profile,
    num_confirmations: 0,
    confirmation_depth_threshold: threshold,
    metadata_present: false,
    validation: { valid: false },
    http_calls: httpCalls,
    ...txDescription,
    ...over,
  });

  // 3. Structural validator (Part A).
  const validation = validatePoeRecord(metadataBytes);
  if (!validation.ok) {
    return base({
      verdict: 'failed',
      exit_code: 1,
      num_confirmations: numConfirmations,
      ...(blockTime !== undefined ? { block_time: blockTime } : {}),
      ...(blockSlot !== undefined ? { block_slot: blockSlot } : {}),
      metadata_present: true,
      validation: { valid: false, issues: validation.issues },
    });
  }
  const record = validation.record;

  // 4. Confirmation-depth — a record below the reorg-safety threshold is
  // well-formed but not yet final, so INSUFFICIENT_CONFIRMATIONS short-circuits
  // to verdict `'pending'` (exit 3), NOT `'failed'`.
  if (numConfirmations < threshold) {
    return base({
      verdict: 'pending',
      exit_code: 3,
      num_confirmations: numConfirmations,
      ...(blockTime !== undefined ? { block_time: blockTime } : {}),
      ...(blockSlot !== undefined ? { block_slot: blockSlot } : {}),
      metadata_present: true,
      record,
      validation: {
        valid: false,
        issues: [
          issueOf('INSUFFICIENT_CONFIRMATIONS', [], `${numConfirmations} < threshold ${threshold}`),
        ],
      },
    });
  }

  // 5. Build optimistic report; mutate verdict on per-check failure.
  const initialWarnings = (validation.warnings ?? []).slice();
  const initialInfo = (validation.info ?? []).slice();
  const plan = planProfileSkips(profile, record);
  initialInfo.push(...plan.skips);

  // (Note: a `MERKLE_UNSUPPORTED` escalation — a verifier reading a
  // merkle-only record without implementing Merkle — never fires here because
  // this reference verifier always runs the Merkle subsystem at every profile.
  // A future `core - merkle` opt-out would emit MERKLE_UNSUPPORTED at info
  // severity when items[] also commits content, error severity otherwise.)

  const reportShape: VerifyReport = {
    tx_hash: input.txHash,
    network: 'cardano:mainnet',
    profile,
    num_confirmations: numConfirmations,
    confirmation_depth_threshold: threshold,
    ...(blockTime !== undefined ? { block_time: blockTime } : {}),
    ...(blockSlot !== undefined ? { block_slot: blockSlot } : {}),
    metadata_present: true,
    validation: composeValidation(true, undefined, initialWarnings, initialInfo),
    record,
    ...txDescription,
    http_calls: httpCalls,
    verdict: 'valid',
    exit_code: 0,
  };
  const report: MutableReport = { ...reportShape };
  const uriChecks: VerifyUriCheck[] = [];

  // `verifyMerkle === false` is the offline switch: it suppresses EVERY
  // outbound URI fetch the verifier would otherwise issue past the
  // chain/indexer resolve step — both the sealed-item ciphertext download in
  // decryption (5b) and the Merkle leaves-list fetch (6). Offline callers
  // (server-rendered viewers, CLI `--no-fetch`) get a report built from
  // indexed CBOR plus any caller-supplied out-of-band bytes alone.
  const allowUriFetch = input.verifyMerkle ?? true;

  // 5a. Record-level signatures (profile >= 'signed').
  if (plan.verifySignatures && record.sigs && record.sigs.length > 0) {
    const sigOut: VerifyRecordSignature[] = await verifyRecordSignatures({ record, input });
    report.record_signatures = sigOut;
    if (recordSignaturesShouldFail(sigOut)) {
      report.verdict = 'failed';
      report.exit_code = 1;
    }
  }

  // 5b. Decryption (profile >= 'recipient-sealed' AND caller supplied keys).
  if (plan.verifyDecrypt && input.decryption && input.decryption.length > 0) {
    const dec = await tryDecryptions({
      record,
      input,
      fetchFn,
      httpCalls,
      uriChecksOut: uriChecks,
      allowUriFetch,
    });
    report.item_decryptions = dec.results;
    const decFailure = decryptionsShouldFail(dec.results);
    if (decFailure !== null) {
      report.verdict = 'failed';
      report.exit_code = decFailure === 'network' ? 2 : 1;
    }
  }

  // 6. Merkle commitments (always in `core` and above; only escalates verdict
  // to `'failed'` on `MERKLE_ROOT_MISMATCH` / leaf-count mismatch — leaves
  // unavailability stays at warning).
  //
  // Suppressed entirely when the offline switch is set (see `allowUriFetch`)
  // so a server-rendered viewer produces a VerifyReport from indexed CBOR
  // alone, with zero outbound fetches to Arweave/IPFS gateways. The on-record
  // `merkle[]` data (alg, root, leaf_count, uris) survives unchanged on
  // `report.record`; only the defence-in-depth re-root + leaf-count check is
  // suppressed. A user-initiated client-side flow performs the same
  // verification at click time.
  if (allowUriFetch && Array.isArray(record.merkle) && record.merkle.length > 0) {
    const merkle = await verifyMerkleCommitments({
      record,
      input,
      fetchFn,
      uriChecksOut: uriChecks,
    });
    report.merkle_checks = merkle.checks;
    const merkleFailure = merkleChecksShouldFail(merkle.checks);
    if (merkleFailure && report.verdict === 'valid') {
      report.verdict = 'failed';
      report.exit_code = 1;
    }
  }

  if (uriChecks.length > 0) {
    report.uri_checks = uriChecks;
  }

  return report;
}

// ─── Internals ────────────────────────────────────────────────────────────────

// Decode the transaction-level description (witnesses, summary, co-published
// metadata labels) from raw tx CBOR. This is purely informational, so a decode
// failure must NOT propagate into the verdict — it degrades to omitting the
// affected fields. The label-309 record is validated separately from
// `metadataBytes`; this view only describes the carrying transaction.
type TxDescriptionFields = Pick<VerifyReport, 'tx_witnesses' | 'tx_summary' | 'metadata_labels'>;
function decodeTxDescription(txCbor: Uint8Array, input: VerifyTxInput): TxDescriptionFields {
  const network = input.cardanoNetwork ?? 'mainnet';
  const out: { -readonly [K in keyof TxDescriptionFields]: TxDescriptionFields[K] } = {};
  let components;
  try {
    components = sliceTxComponents(txCbor);
  } catch {
    return out;
  }
  out.metadata_labels = components.auxMetadataLabels;
  try {
    out.tx_witnesses = decodeTxWitnesses(components.witnessSet, components.txBody);
  } catch {
    // leave tx_witnesses undefined
  }
  try {
    out.tx_summary = decodeTxSummary(components.txBody, components.witnessSet, network);
  } catch {
    // leave tx_summary undefined
  }
  return out;
}

// A public hash-only PoE stays valid even when every signature entry is
// SIGNATURE_UNSUPPORTED — the content claim does not depend on signer identity,
// so an unverifiable algorithm is informational, not fatal. Any OTHER failure
// (MALFORMED_SIG_COSE_SIGN1, SIGNER_KEY_UNRESOLVED, SIGNATURE_INVALID,
// WALLET_ADDRESS_MISMATCH) fails the record.
function recordSignaturesShouldFail(sigs: ReadonlyArray<VerifyRecordSignature>): boolean {
  return sigs.some((s) => s.verdict === 'invalid' || s.verdict === 'unresolved');
}

// Returns null on success, 'network' for CONTENT_UNAVAILABLE / IPFS-no-gateway
// (exit 2), or 'integrity' for any other failure (exit 1).
function decryptionsShouldFail(
  results: ReadonlyArray<VerifyItemDecryption>,
): 'network' | 'integrity' | null {
  let saw: 'network' | 'integrity' | null = null;
  for (const d of results) {
    if (d.verdict === 'decrypted' && d.plaintext_hash_ok !== false) continue;
    if (d.verdict === 'content-unavailable' || d.verdict === 'ciphertext-unavailable') {
      saw = saw === 'integrity' ? 'integrity' : 'network';
      continue;
    }
    saw = 'integrity';
  }
  return saw;
}

function merkleChecksShouldFail(checks: ReadonlyArray<VerifyMerkleCheck>): boolean {
  for (const c of checks) {
    if (c.verdict === 'mismatch') return true;
    // `unavailable`, `format-unsupported`, and `unsupported` are warning/
    // info-severity — the on-chain root is structurally valid on its own, so
    // they do NOT escalate to verdict 'failed'.
  }
  return false;
}

function issueOf(
  code: keyof typeof SEVERITY,
  path: ReadonlyArray<string | number>,
  message: string,
): ValidationIssue {
  return { code, path, message, severity: SEVERITY[code] };
}

function composeValidation(
  valid: boolean,
  issues: ReadonlyArray<ValidationIssue> | undefined,
  warnings: ReadonlyArray<ValidationIssue>,
  info: ReadonlyArray<ValidationIssue>,
): VerifyReport['validation'] {
  const out: {
    valid: boolean;
    issues?: ReadonlyArray<ValidationIssue>;
    warnings?: ReadonlyArray<ValidationIssue>;
    info?: ReadonlyArray<ValidationIssue>;
  } = { valid };
  if (issues !== undefined && issues.length > 0) out.issues = issues;
  if (warnings.length > 0) out.warnings = warnings;
  if (info.length > 0) out.info = info;
  return out;
}

// Convenience re-export so callers can map verdicts to exit codes without
// importing the union shape.
export function exitCodeForVerdict(report: VerifyReport): ExitCode {
  return report.exit_code;
}

export type { Verdict, ExitCode };
