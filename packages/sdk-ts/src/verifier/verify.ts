// Label 309 standalone verifier — the Part B pipeline.
//
// `verifyTx` executes, in order; a step whose outcome forecloses the rest
// short-circuits the pipeline:
//
//   1.  Resolve the transaction via the explorer chain (raw tx CBOR, never a
//       JSON projection). Negative outcomes split three ways: TX_NOT_FOUND /
//       PROVIDER_UNAVAILABLE → `unverifiable`.
//   2.  Bind the fetched bytes to the transaction reference — blake2b-256
//       over the body vs the requested hash, blake2b-256 over the auxiliary
//       data vs the body's auxiliary_data_hash; no surviving response →
//       TX_INTEGRITY_MISMATCH, `unverifiable` (provider-provable, never
//       record-attributable).
//   3.  Unwrap the auxiliary data (all three Conway envelope forms, dispatch
//       on type/tag only) and reassemble the label-309 chunk array. No
//       label-309 entry → METADATA_NOT_FOUND, `failed` (the absence is
//       proven by the integrity-bound transaction itself).
//   4.  Structurally validate (`validatePoeRecord`), with the validator role
//       matching the verifier mode: a run that will actually decrypt —
//       decryption credentials held AND the profile admits sealed decryption
//       — is a RECIPIENT verifier ('recipient_or_strict'); otherwise 'public'.
//   5.  Check confirmation depth — below threshold → INSUFFICIENT_CONFIRMATIONS,
//       verdict `pending`, pipeline halts (results computed against a
//       transaction that may yet be orphaned must not be presented as final).
//   6.  Verify record signatures (strict Ed25519, detached payload, verbatim
//       protected bytes, wallet-address network binding).
//   7.  Fetch and hash-check plain-item content and Merkle leaves-lists
//       (first-success-for-availability; integrity vs attribution vs
//       availability split; suppressed by `fetchContent: false`).
//   8.  Decrypt `enc`-bearing items with the keyring (recipient verifier),
//       including the post-decryption plaintext-hash recheck.
//   9.  (`supersedes` is an advisory pointer; this implementation performs
//       no existence hop.)
//   10. Emit the report: verdict ∈ valid | pending | unverifiable | failed,
//       exit codes 0 | 3 | 2 | 1 respectively, issues sorted by path then
//       registry order, one per-claim entry per item / commitment, and the
//       complete audit trail of every outbound call.
//
// `verifyResolved` runs the same pipeline from step 4 onward over
// caller-supplied record-body bytes plus an explorer-asserted block-info
// tuple.

import {
  SEVERITY,
  reassembleLabel309Value,
  validatePoeRecord,
  type ErrorCode,
  type PoeRecord,
  type ValidationIssue,
} from '@cardanowall/poe-standard';

import { defaultFetchOutbound, isDenyHostError, wrapFetchOutbound } from '../fetch/fetch-outbound';
import { ARWEAVE_GATEWAY_DEFAULTS, type ContentFetchContext } from './content';
import { sliceTxComponents, unwrapAuxiliaryData } from './cbor-walker';
import { decryptItem } from './decrypt';
import { checkItemContent } from './items';
import { IssueSink, issueOf, sortIssues } from './issues';
import { checkMerkleCommit, type MerkleCommitOutcome } from './merkle';
import { DEFAULT_PROFILE, planProfileSkips } from './profile';
import { resolveCardanoTx } from './resolve';
import { verifyRecordSignatures } from './signatures';
import { decodeTxSummary, decodeTxWitnesses } from './tx-witnesses';
import type {
  ExitCode,
  HttpCallRecord,
  ItemReportEntry,
  MerkleReportEntry,
  Profile,
  Verdict,
  VerifyReport,
  VerifyResolvedInput,
  VerifyTxInput,
} from './types';
import { EXIT_CODE_FOR_VERDICT, PROFILE_RANK } from './types';

export const CONFIRMATION_DEPTH_THRESHOLD_DEFAULT = 15;

// Error-severity codes that are NOT record-attributable: network, policy, and
// provider-integrity outcomes. They block a `valid` verdict but can never
// condemn the record — the verdict they produce is `unverifiable`. Every
// other error-severity code is record-attributable and produces `failed`.
const NETWORK_CLASS_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  'TX_NOT_FOUND',
  'PROVIDER_UNAVAILABLE',
  'TX_INTEGRITY_MISMATCH',
  'CONTENT_UNAVAILABLE',
  'CONTENT_FETCH_LIMIT_EXCEEDED',
  'CIPHERTEXT_UNAVAILABLE',
  'MERKLE_LEAVES_UNAVAILABLE',
  'URI_TARGET_FORBIDDEN',
]);

function verdictFromIssues(issues: ReadonlyArray<ValidationIssue>): Verdict {
  let sawNetworkError = false;
  for (const issue of issues) {
    if (issue.severity !== 'error') continue;
    if (!NETWORK_CLASS_CODES.has(issue.code)) return 'failed';
    sawNetworkError = true;
  }
  return sawNetworkError ? 'unverifiable' : 'valid';
}

interface ChainFacts {
  readonly confirmationDepth: number;
  readonly blockTime: number;
  readonly blockSlot?: number | undefined;
}

interface ReportSkeleton {
  readonly txHash: string;
  readonly network: string;
  readonly profile: Profile;
  readonly threshold: number;
  readonly auditTrail: HttpCallRecord[];
  readonly chainFacts?: ChainFacts | undefined;
  readonly txDescription: TxDescriptionFields;
}

function assembleReport(args: {
  readonly skeleton: ReportSkeleton;
  readonly issues: ReadonlyArray<ValidationIssue>;
  readonly verdict: Verdict;
  readonly items?: ReadonlyArray<ItemReportEntry>;
  readonly merkle?: ReadonlyArray<MerkleReportEntry>;
  readonly record?: PoeRecord | undefined;
  readonly signatures?: VerifyReport['signatures'] | undefined;
}): VerifyReport {
  const { skeleton } = args;
  const exitCode: ExitCode = EXIT_CODE_FOR_VERDICT[args.verdict];
  const facts = skeleton.chainFacts;
  return {
    verdict: args.verdict,
    exitCode,
    issues: sortIssues(args.issues),
    items: args.items ?? [],
    merkle: args.merkle ?? [],
    auditTrail: skeleton.auditTrail,
    network: skeleton.network,
    txHash: skeleton.txHash,
    profile: skeleton.profile,
    confirmationThreshold: skeleton.threshold,
    ...(facts !== undefined
      ? {
          confirmationDepth: facts.confirmationDepth,
          block_time: facts.blockTime,
          ...(facts.blockSlot !== undefined ? { block_slot: facts.blockSlot } : {}),
        }
      : {}),
    ...(args.record !== undefined ? { record: args.record } : {}),
    ...(args.signatures !== undefined && args.signatures.length > 0
      ? { signatures: args.signatures }
      : {}),
    ...skeleton.txDescription,
  };
}

export async function verifyTx(input: VerifyTxInput): Promise<VerifyReport> {
  const profile = input.profile ?? DEFAULT_PROFILE;
  const threshold = input.confirmationDepthThreshold ?? CONFIRMATION_DEPTH_THRESHOLD_DEFAULT;
  const cardanoNetwork = input.cardanoNetwork ?? 'mainnet';
  const auditTrail: HttpCallRecord[] = [];
  const fetchFn = wrapFetchOutbound(
    input.fetchOutbound ?? defaultFetchOutbound,
    auditTrail,
    input.denyHosts,
  );

  const baseSkeleton: ReportSkeleton = {
    txHash: input.txHash,
    network: `cardano:${cardanoNetwork}`,
    profile,
    threshold,
    auditTrail,
    txDescription: {},
  };

  try {
    return await runVerifyTx({ input, profile, threshold, cardanoNetwork, baseSkeleton, fetchFn });
  } catch (e) {
    // A RESOLVE-path call (explorer adapter) targeted a denyHosts entry: the
    // egress hard-failed it and the violation is terminal for the run — no
    // transaction was resolved, so there is nothing to verify. The report
    // carries one SERVICE_INDEPENDENCE_VIOLATION at the empty path, verdict
    // `failed`. Content-path deny-hits never reach here: the content engine
    // records them per attempt at the claim's uris[] path and continues.
    if (isDenyHostError(e)) {
      return assembleReport({
        skeleton: baseSkeleton,
        issues: [issueOf('SERVICE_INDEPENDENCE_VIOLATION', [], e.message)],
        verdict: 'failed',
      });
    }
    throw e;
  }
}

async function runVerifyTx(args: {
  readonly input: VerifyTxInput;
  readonly profile: Profile;
  readonly threshold: number;
  readonly cardanoNetwork: 'mainnet' | 'preprod';
  readonly baseSkeleton: ReportSkeleton;
  readonly fetchFn: ReturnType<typeof wrapFetchOutbound>;
}): Promise<VerifyReport> {
  const { input, profile, threshold, cardanoNetwork, baseSkeleton, fetchFn } = args;

  // Steps 1 + 2 — resolve via the explorer chain with the integrity binding
  // applied per response.
  const outcome = await resolveCardanoTx({
    txHash: input.txHash,
    cardanoGatewayChain: input.cardanoGatewayChain,
    blockfrostProjectId: input.blockfrostProjectId,
    fetchFn,
  });
  if (!outcome.ok) {
    const issues = [issueOf(outcome.code, [], outcome.message)];
    return assembleReport({
      skeleton: baseSkeleton,
      issues,
      verdict: verdictFromIssues(issues),
    });
  }
  const { resolved } = outcome;
  const skeleton: ReportSkeleton = {
    ...baseSkeleton,
    chainFacts: {
      confirmationDepth: resolved.confirmationDepth,
      blockTime: resolved.blockTime,
      blockSlot: resolved.blockSlot,
    },
    txDescription: decodeTxDescription(resolved.txCbor, cardanoNetwork),
  };

  // Step 3 — unwrap the bound auxiliary data and reassemble the record body.
  let label309: Uint8Array | null;
  try {
    label309 =
      resolved.components.auxiliaryData === null
        ? null
        : unwrapAuxiliaryData(resolved.components.auxiliaryData).label309;
  } catch (e) {
    const issues = [issueOf('MALFORMED_CBOR', [], e instanceof Error ? e.message : String(e))];
    return assembleReport({ skeleton, issues, verdict: 'failed' });
  }
  if (label309 === null) {
    const issues = [
      issueOf(
        'METADATA_NOT_FOUND',
        [],
        'the integrity-bound transaction carries no metadata under label 309',
      ),
    ];
    return assembleReport({ skeleton, issues, verdict: 'failed' });
  }
  const reassembly = reassembleLabel309Value(label309);
  if (!reassembly.ok) {
    return assembleReport({ skeleton, issues: [reassembly.issue], verdict: 'failed' });
  }

  return verifyRecordBody({
    skeleton,
    recordBody: reassembly.body,
    chainFacts: skeleton.chainFacts!,
    fetchFn,
    input: {
      profile,
      cardanoNetwork,
      threshold,
      fetchContent: input.fetchContent ?? true,
      maxFetchBytes: input.maxFetchBytes,
      decryption: input.decryption ?? [],
      ciphertextBytes: input.ciphertextBytes,
      merkleLeaves: input.merkleLeaves,
      arweaveGateways:
        input.arweaveGatewayChain && input.arweaveGatewayChain.length > 0
          ? input.arweaveGatewayChain
          : ARWEAVE_GATEWAY_DEFAULTS,
      ipfsGateways: input.ipfsGatewayChain ?? [],
    },
  });
}

/**
 * Sibling entry point: run the pipeline from the structural-validator step
 * onward over caller-supplied label-309 record-body bytes plus an
 * explorer-asserted block-info tuple — the path a server-rendered viewer uses
 * to display on-chain data without a render-time chain fetch. The caller is
 * responsible for the confidence that the bytes came from the label-309
 * metadata of a real Cardano transaction.
 */
export async function verifyResolved(input: VerifyResolvedInput): Promise<VerifyReport> {
  // The caller vouches for the block-info tuple, and a transaction in a block
  // has depth = tip − block + 1 ≥ 1 by definition — so a smaller (or
  // non-integer) confirmationDepth is a caller-input error, never a
  // verification outcome.
  if (!Number.isInteger(input.confirmationDepth) || input.confirmationDepth < 1) {
    throw new RangeError(
      `confirmationDepth must be an integer >= 1 (a transaction in the tip block has depth exactly 1); got ${input.confirmationDepth}`,
    );
  }
  const profile = input.profile ?? DEFAULT_PROFILE;
  const threshold = input.confirmationDepthThreshold ?? CONFIRMATION_DEPTH_THRESHOLD_DEFAULT;
  const cardanoNetwork = input.cardanoNetwork ?? 'mainnet';
  const auditTrail: HttpCallRecord[] = [];
  const fetchFn = wrapFetchOutbound(
    input.fetchOutbound ?? defaultFetchOutbound,
    auditTrail,
    input.denyHosts,
  );
  const skeleton: ReportSkeleton = {
    txHash: input.txHash,
    network: input.network ?? `cardano:${cardanoNetwork}`,
    profile,
    threshold,
    auditTrail,
    chainFacts: {
      confirmationDepth: input.confirmationDepth,
      blockTime: input.blockTime,
      blockSlot: input.blockSlot,
    },
    txDescription:
      input.txCbor !== undefined ? decodeTxDescription(input.txCbor, cardanoNetwork) : {},
  };
  // No resolve step runs here, and content-path deny-hits are recorded per
  // attempt inside the content engine, so no DenyHostError can escape.
  return verifyRecordBody({
    skeleton,
    recordBody: input.metadataCbor,
    chainFacts: skeleton.chainFacts!,
    fetchFn,
    input: {
      profile,
      cardanoNetwork,
      threshold,
      fetchContent: input.fetchContent ?? true,
      maxFetchBytes: input.maxFetchBytes,
      decryption: input.decryption ?? [],
      ciphertextBytes: input.ciphertextBytes,
      merkleLeaves: input.merkleLeaves,
      arweaveGateways:
        input.arweaveGatewayChain && input.arweaveGatewayChain.length > 0
          ? input.arweaveGatewayChain
          : ARWEAVE_GATEWAY_DEFAULTS,
      ipfsGateways: input.ipfsGatewayChain ?? [],
    },
  });
}

interface PipelineOptions {
  readonly profile: Profile;
  readonly cardanoNetwork: 'mainnet' | 'preprod';
  readonly threshold: number;
  readonly fetchContent: boolean;
  readonly maxFetchBytes: number | undefined;
  readonly decryption: ReadonlyArray<
    { readonly recipientSecretKey: Uint8Array } | { readonly passphrase: string }
  >;
  readonly ciphertextBytes: Readonly<Record<number, Uint8Array>> | undefined;
  readonly merkleLeaves: Readonly<Record<number, Uint8Array>> | undefined;
  readonly arweaveGateways: ReadonlyArray<string>;
  readonly ipfsGateways: ReadonlyArray<string>;
}

async function verifyRecordBody(args: {
  readonly skeleton: ReportSkeleton;
  readonly recordBody: Uint8Array;
  readonly chainFacts: ChainFacts;
  readonly fetchFn: ReturnType<typeof wrapFetchOutbound>;
  readonly input: PipelineOptions;
}): Promise<VerifyReport> {
  const { skeleton, input } = args;

  // Step 4 — structural validation, with the role matching the verifier
  // mode: a run that will actually decrypt (credentials held AND the profile
  // implements decryption) is a recipient verifier, whose validator
  // hard-rejects envelopes it cannot fully validate (ENC_UNSUPPORTED
  // escalates to error) — a sealed delivery is never processed under a
  // half-validated envelope. A lower profile never decrypts, so it keeps the
  // public reading even when credentials were supplied.
  const willDecrypt =
    input.decryption.length > 0 && PROFILE_RANK[input.profile] >= PROFILE_RANK['recipient-sealed'];
  const role = willDecrypt ? 'recipient_or_strict' : 'public';
  const validation = validatePoeRecord(args.recordBody, { role });
  if (!validation.valid) {
    return assembleReport({
      skeleton,
      issues: validation.issues,
      verdict: 'failed',
    });
  }
  const record = validation.record;
  const issues = new IssueSink();
  issues.pushAll(validation.warnings ?? []);
  issues.pushAll(validation.info ?? []);

  const items = record.items ?? [];
  const merkleCommits = record.merkle ?? [];

  // Step 5 — confirmation depth. Below threshold the record is well-formed
  // but not final: verdict `pending`, and the signature / content / decrypt
  // steps are skipped so nothing computed against a possibly-orphaned
  // transaction can be presented as final.
  if (args.chainFacts.confirmationDepth < input.threshold) {
    issues.add(
      'INSUFFICIENT_CONFIRMATIONS',
      [],
      `confirmation depth ${args.chainFacts.confirmationDepth} is below the threshold ${input.threshold}; signature, content, and decryption steps did not run`,
    );
    return assembleReport({
      skeleton,
      issues: issues.sorted(),
      verdict: 'pending',
      items: items.map(() => ({ contentCheck: 'not_checked' as const })),
      merkle: merkleCommits.map(() => ({ contentCheck: 'not_checked' as const })),
      record,
    });
  }

  // Profile gating: fields above the active profile are skipped with
  // OUT_OF_PROFILE_SKIPPED (info) — the record is never invalid solely
  // because this verifier does not implement a profile extension.
  const plan = planProfileSkips(input.profile, record);
  issues.pushAll(plan.skips);

  // Step 6 — record-level signatures.
  let signatures: VerifyReport['signatures'];
  if (plan.verifySignatures && (record.sigs?.length ?? 0) > 0) {
    signatures = verifyRecordSignatures({
      record,
      cardanoNetwork: input.cardanoNetwork,
      issues,
    });
  }

  // Steps 7 + 8 — content checks and sealed decryption.
  const ctx: ContentFetchContext = {
    fetchFn: args.fetchFn,
    arweaveGateways: input.arweaveGateways,
    ipfsGateways: input.ipfsGateways,
    maxFetchBytes: input.maxFetchBytes,
    issues,
  };

  const itemEntries: ItemReportEntry[] = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i]!;
    if (item.enc !== undefined && item.enc !== null) {
      if (input.decryption.length > 0 && plan.verifyDecrypt) {
        const result = await decryptItem({
          item,
          itemIndex: i,
          credentials: input.decryption,
          outOfBandCiphertext: input.ciphertextBytes?.[i],
          fetchContent: input.fetchContent,
          ctx,
        });
        itemEntries.push({ contentCheck: result.contentCheck, decryption: result.decryption });
      } else {
        // Public verifier (or a profile below recipient-sealed): a sealed
        // item's plaintext claim cannot be checked without decrypting, and
        // the URIs hold ciphertext, not the committed plaintext.
        itemEntries.push({ contentCheck: 'not_checked' });
      }
      continue;
    }
    const contentCheck = await checkItemContent({
      item,
      itemIndex: i,
      fetchContent: input.fetchContent,
      ctx,
    });
    itemEntries.push({ contentCheck });
  }

  const merkleOutcomes: MerkleCommitOutcome[] = [];
  for (let i = 0; i < merkleCommits.length; i++) {
    merkleOutcomes.push(
      await checkMerkleCommit({
        commit: merkleCommits[i]!,
        commitIndex: i,
        outOfBand: input.merkleLeaves?.[i],
        fetchContent: input.fetchContent,
        ctx,
      }),
    );
  }

  // The commitment floor resolves the dual severity of
  // MERKLE_LEAVES_UNAVAILABLE: warning when at least one other content
  // commitment of the record was verified in this run, error (network class,
  // verdict `unverifiable`) when the unavailability leaves the record with no
  // verified content commitment.
  const anyCommitmentVerified =
    itemEntries.some((e) => e.contentCheck === 'checked') ||
    merkleOutcomes.some((o) => o.contentCheck === 'checked');
  for (const outcomeEntry of merkleOutcomes) {
    if (outcomeEntry.unavailable === undefined) continue;
    if (outcomeEntry.unavailable.limitExceeded) {
      issues.add(
        'CONTENT_FETCH_LIMIT_EXCEEDED',
        outcomeEntry.unavailable.path,
        'a leaves-list fetch was aborted at the maxFetchBytes ceiling; the commitment is unchecked',
      );
      continue;
    }
    issues.add(
      'MERKLE_LEAVES_UNAVAILABLE',
      outcomeEntry.unavailable.path,
      anyCommitmentVerified
        ? 'no attributable leaves-list could be obtained; another content commitment of the record was verified'
        : 'no attributable leaves-list could be obtained and no content commitment of the record was verified',
      anyCommitmentVerified ? SEVERITY.MERKLE_LEAVES_UNAVAILABLE : 'error',
    );
  }

  // Step 10 — verdict + report.
  const sorted = issues.sorted();
  return assembleReport({
    skeleton,
    issues: sorted,
    verdict: verdictFromIssues(sorted),
    items: itemEntries,
    merkle: merkleOutcomes.map((o) => ({ contentCheck: o.contentCheck })),
    record,
    signatures,
  });
}

// ─── Transaction-level description ───────────────────────────────────────────
//
// Decode the witnesses / summary / co-published-labels view from raw tx CBOR.
// Purely informational: a decode failure degrades to omitting the affected
// fields and never propagates into the verdict. The label-309 record is
// validated separately from the record-body bytes; this view only describes
// the carrying transaction.

type TxDescriptionFields = Pick<VerifyReport, 'txWitnesses' | 'txSummary' | 'metadataLabels'>;

function decodeTxDescription(
  txCbor: Uint8Array,
  network: 'mainnet' | 'preprod',
): TxDescriptionFields {
  const out: { -readonly [K in keyof TxDescriptionFields]: TxDescriptionFields[K] } = {};
  let components;
  try {
    components = sliceTxComponents(txCbor);
  } catch {
    return out;
  }
  if (components.auxiliaryData !== null) {
    try {
      out.metadataLabels = unwrapAuxiliaryData(components.auxiliaryData).metadataLabels;
    } catch {
      // leave metadataLabels undefined
    }
  } else {
    out.metadataLabels = [];
  }
  try {
    out.txWitnesses = decodeTxWitnesses(components.witnessSet, components.txBody);
  } catch {
    // leave txWitnesses undefined
  }
  try {
    out.txSummary = decodeTxSummary(components.txBody, components.witnessSet, network);
  } catch {
    // leave txSummary undefined
  }
  return out;
}

// Convenience so callers can map verdicts to exit codes without importing the
// union shape.
export function exitCodeForVerdict(report: VerifyReport): ExitCode {
  return report.exitCode;
}

export type { Verdict, ExitCode };
