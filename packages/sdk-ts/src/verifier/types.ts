// Public types for the Label 309 standalone verifier.
//
// The verifier is service-independent: it depends only on the caller-supplied
// Cardano / Arweave / IPFS gateway chains and a `denyHosts` policy. Every
// outbound network call routes through `fetchOutbound` (the single recording
// egress point) and lands in `VerifyReport.auditTrail` for audit.
//
// `VerifyReport` implements the normative report contract: the required key
// set, the verdict / exit-code enums, the per-claim `contentCheck` states,
// and the audit-trail entry shape are all pinned by the published
// verify-report JSON Schema. The schema is a minimum — this implementation
// adds informational fields (`record`, `signatures`, transaction
// description) on top of it.

import type { PoeRecord, ValidationIssue } from '@cardanowall/poe-standard';

import type { FetchOutbound, HttpCallRecord } from '../fetch/fetch-outbound';

// -----------------------------------------------------------------------------
// Verdict / exit code
// -----------------------------------------------------------------------------
//
// `failed` is reserved for record-attributable outcomes — integrity,
// structural, signature, Merkle-mismatch, and service-independence-violation
// classes, including METADATA_NOT_FOUND (the absence is proven by the
// integrity-bound transaction itself). Provider misbehaviour can never
// manufacture it. `unverifiable` means no record-attributable error is
// present but a required check could not run — or could not be attributed —
// for network, policy, or provider-integrity reasons. `pending` is the
// below-confirmation-threshold outcome; no result from a pending record may
// be presented as final.

export type Verdict = 'valid' | 'pending' | 'unverifiable' | 'failed';

// valid → 0, failed → 1, unverifiable → 2, pending → 3. Exit codes 4+ denote
// verifier-host runtime failures and never correspond to a verdict.
export type ExitCode = 0 | 1 | 2 | 3;

export const EXIT_CODE_FOR_VERDICT: Readonly<Record<Verdict, ExitCode>> = Object.freeze({
  valid: 0,
  failed: 1,
  unverifiable: 2,
  pending: 3,
});

// -----------------------------------------------------------------------------
// Conformance profile
// -----------------------------------------------------------------------------
//
// Strict-superset order: each higher profile reads everything below it plus
// one additional surface. A verifier of a LOWER profile that sees a field
// belonging to a HIGHER profile MUST emit `OUT_OF_PROFILE_SKIPPED`
// (info severity) and continue — it MUST NOT report the record as invalid.

export type Profile = 'core' | 'signed' | 'sealed' | 'recipient-sealed';

export const PROFILE_RANK: Readonly<Record<Profile, number>> = Object.freeze({
  core: 0,
  signed: 1,
  sealed: 2,
  'recipient-sealed': 3,
});

// -----------------------------------------------------------------------------
// FetchOutbound (the verifier's only network egress point)
// -----------------------------------------------------------------------------

export type {
  FetchOutbound,
  FetchOutboundOptions,
  FetchOutboundResult,
  HttpCallRecord,
} from '../fetch/fetch-outbound';

// -----------------------------------------------------------------------------
// Verifier issue surface — re-exports the validator's `ValidationIssue` so
// downstream consumers dispatch on a single union (`ErrorCode` covers both
// Part A and Part B per `@cardanowall/poe-standard`).
// -----------------------------------------------------------------------------

export type { ValidationIssue } from '@cardanowall/poe-standard';

// -----------------------------------------------------------------------------
// Decryption keyring
// -----------------------------------------------------------------------------
//
// The verification run's keyring: a set of decryption credentials GLOBAL to
// the run, not positionally paired with encrypted items. For each
// `enc`-bearing item the verifier attempts every applicable credential
// independently — `recipientSecretKey` entries against the `enc.slots` path
// (a 32-byte X25519 scalar or a 32-byte X-Wing decapsulation seed; the KEM is
// dispatched from the envelope), `passphrase` entries against the
// `enc.passphrase` path. One credential may open several items; different
// credentials may succeed on different items. An `enc`-bearing item for which
// the keyring holds no credential of the applicable shape is reported with
// WRONG_DECRYPTION_INPUT_SHAPE.

export type DecryptionCredential =
  | { readonly recipientSecretKey: Uint8Array }
  | { readonly passphrase: string };

// -----------------------------------------------------------------------------
// VerifyTx input
// -----------------------------------------------------------------------------

export interface VerifyTxInput {
  readonly txHash: string; // lowercase hex, no 0x prefix
  readonly profile?: Profile; // default 'recipient-sealed' (full pipeline)
  readonly cardanoGatewayChain?: ReadonlyArray<string>; // Koios-compatible URLs, in order
  readonly blockfrostProjectId?: string; // enables Blockfrost fallback
  readonly arweaveGatewayChain?: ReadonlyArray<string>;
  readonly ipfsGatewayChain?: ReadonlyArray<string>;
  readonly confirmationDepthThreshold?: number; // default 15; deployment policy
  readonly denyHosts?: ReadonlyArray<string>; // service-independence guard
  // Master content-fetch switch (default true). When `false`, every outbound
  // content fetch — item URIs, Merkle leaves-lists, and ciphertext alike — is
  // suppressed, so a record renders offline from the chain-resolved CBOR
  // alone with the affected content claims reported `not_checked`.
  // Caller-supplied out-of-band bytes (`ciphertextBytes`, `merkleLeaves`) are
  // still verified: they require no egress and are attributable by
  // definition.
  readonly fetchContent?: boolean;
  // Per-URI fetch ceiling in bytes, enforced incrementally during streaming.
  // Deployment policy, not a wire rule: a fetch that reaches the ceiling is
  // aborted and surfaced as CONTENT_FETCH_LIMIT_EXCEEDED (network/policy
  // class — a statement about the verifier, never about the record).
  readonly maxFetchBytes?: number;
  // The decryption keyring (see DecryptionCredential). Non-empty ⇒ the run is
  // a RECIPIENT verifier: the structural validator runs in the
  // 'recipient_or_strict' role and sealed decryption is attempted.
  readonly decryption?: ReadonlyArray<DecryptionCredential>;
  // Out-of-band ciphertext bytes for `enc`-bearing items, keyed by item
  // index. Takes precedence over `items[i].uris[]` (no fetch is issued) and
  // counts as attributable for the integrity/attribution split.
  readonly ciphertextBytes?: Readonly<Record<number, Uint8Array>>;
  // Out-of-band Merkle leaves-list bytes keyed by `record.merkle[i]` index.
  // CBOR is the normative wire form. Attributable by definition.
  readonly merkleLeaves?: Readonly<Record<number, Uint8Array>>;
  // The network the configured explorer chain serves. Drives the report's
  // `network` identifier and the expected network-header byte recomputed for
  // wallet-path signature addresses — never echoed from the record body,
  // which carries no network value. Defaults to 'mainnet'.
  readonly cardanoNetwork?: 'mainnet' | 'preprod';
  // Injected for tests; defaults to the canonical egress primitive.
  readonly fetchOutbound?: FetchOutbound;
}

// -----------------------------------------------------------------------------
// Sibling entry point: caller-supplied record bytes + block-info tuple
// -----------------------------------------------------------------------------
//
// Runs the same pipeline from the structural-validator step onward — the path
// a server-rendered viewer uses to display on-chain data without a
// render-time chain fetch. The caller vouches that `metadataCbor` is the
// reassembled label-309 record body of a real transaction and supplies the
// explorer-asserted block-info tuple the chain fetch would have produced.

export interface VerifyResolvedInput {
  readonly txHash: string;
  // The reassembled canonical record-body bytes (the chunk-array transport
  // already concatenated). NOT re-derived from `txCbor`.
  readonly metadataCbor: Uint8Array;
  // Explorer-asserted confirmation depth in blocks (tip − block + 1; a tx in
  // the tip block has depth exactly 1). Must be an integer >= 1 — a smaller
  // value is impossible for a transaction in a block and is rejected as a
  // caller-input error (RangeError), never folded into a report outcome.
  readonly confirmationDepth: number;
  // POSIX seconds UTC of the slot of the including block.
  readonly blockTime: number;
  readonly blockSlot?: number;
  // Raw on-chain transaction CBOR. When supplied, the report also carries the
  // transaction-level description (txWitnesses, txSummary, metadataLabels);
  // the label-309 record is always taken from `metadataCbor`.
  readonly txCbor?: Uint8Array;
  readonly network?: string;
  readonly cardanoNetwork?: 'mainnet' | 'preprod';
  readonly profile?: Profile;
  readonly confirmationDepthThreshold?: number;
  readonly arweaveGatewayChain?: ReadonlyArray<string>;
  readonly ipfsGatewayChain?: ReadonlyArray<string>;
  readonly fetchOutbound?: FetchOutbound;
  readonly denyHosts?: ReadonlyArray<string>;
  readonly fetchContent?: boolean;
  readonly maxFetchBytes?: number;
  readonly decryption?: ReadonlyArray<DecryptionCredential>;
  readonly ciphertextBytes?: Readonly<Record<number, Uint8Array>>;
  readonly merkleLeaves?: Readonly<Record<number, Uint8Array>>;
}

// -----------------------------------------------------------------------------
// Per-claim report entries
// -----------------------------------------------------------------------------

// Three-state per-claim status, so an unchecked claim can never masquerade as
// a verified one. `checked` — bytes were obtained and every committed digest
// matched; `mismatched` — attributable fetched (or decrypted) bytes failed a
// commitment (record-attributable); `not_checked` — the claim was not checked
// (`fetchContent` off, availability failure, unattributable fetched bytes, or
// the per-URI fetch ceiling).
export type ContentCheck = 'checked' | 'mismatched' | 'not_checked';

// The recipient-verifier outcome for one `enc`-bearing item after every
// applicable keyring credential was attempted independently.
export interface DecryptionOutcome {
  readonly decrypted: boolean;
  // The post-decryption recheck: every digest in the item's `hashes` map
  // recomputed over the recovered plaintext. A concrete boolean whenever
  // decryption ran to completion; `false` raises URI_INTEGRITY_MISMATCH and
  // forces the record's verdict to `failed`.
  readonly plaintextHashOk?: boolean;
  // The typed code describing why decryption did not succeed; the same code
  // also appears in the issue list when it affects the verdict.
  readonly code?: string;
}

export interface ItemReportEntry {
  readonly contentCheck: ContentCheck;
  readonly decryption?: DecryptionOutcome;
}

export interface MerkleReportEntry {
  readonly contentCheck: ContentCheck;
}

// -----------------------------------------------------------------------------
// Record-signature results (informational extra; failures also raise issues)
// -----------------------------------------------------------------------------

export type SignatureVerdict = 'valid' | 'invalid' | 'unsupported' | 'unresolved';
export type SignatureFailureReason =
  | 'MALFORMED_SIG_COSE_SIGN1'
  | 'SIGNATURE_UNSUPPORTED'
  | 'SIGNER_KEY_UNRESOLVED'
  | 'SIGNATURE_INVALID'
  | 'WALLET_ADDRESS_MISMATCH';

export type SignerType = 'in-signature-kid' | 'wallet-inline-key';

export interface VerifyRecordSignature {
  readonly index: number;
  readonly verdict: SignatureVerdict;
  readonly signerPub?: string; // lowercase hex of the resolved 32-byte Ed25519 pubkey
  readonly signerType?: SignerType;
  readonly reason?: SignatureFailureReason;
}

// -----------------------------------------------------------------------------
// Transaction-level description — DISTINCT from record-level authorship.
// -----------------------------------------------------------------------------
//
// These surfaces describe the Cardano transaction that carried the PoE: which
// wallet vkey(s) authorised/paid for it, the fee, and the outputs. This is
// the "who submitted and paid for this anchoring" view — orthogonal to
// `signatures`, the optional record-level authorship claim. A failed
// `signature_valid` here is INFORMATIONAL: it never changes the verdict (the
// content claim does not depend on who paid the fee).

export interface VerifyTxWitness {
  readonly type: 'vkey';
  readonly vkey: string; // hex 32B Ed25519 pubkey
  readonly key_hash: string; // hex 28B Blake2b-224(vkey)
  readonly signature_valid: boolean; // Ed25519.verify(sig, blake2b256(tx_body), vkey)
}

export interface VerifyTxOutput {
  readonly address: string; // bech32
  readonly lovelace: string; // decimal string
}

export interface VerifyTxSummary {
  readonly fee_lovelace: string; // decimal string
  readonly input_count: number;
  readonly output_count: number;
  readonly outputs: ReadonlyArray<VerifyTxOutput>;
  readonly total_output_lovelace: string; // decimal string
  readonly script_witness_count: number;
  readonly invalid_before?: number;
  readonly invalid_hereafter?: number;
  readonly required_signer_key_hashes?: ReadonlyArray<string>;
  readonly network_id?: number;
}

// -----------------------------------------------------------------------------
// VerifyReport
// -----------------------------------------------------------------------------

export interface VerifyReport {
  // ── Normative minimum (the published report schema) ──────────────────────
  readonly verdict: Verdict;
  readonly exitCode: ExitCode;
  // The structural-validation issue list plus every verifier-layer code
  // raised by the run, sorted segment-wise by path (integer segments
  // numerically, text segments by bytewise UTF-8 order, integer before text
  // where kinds differ, prefix before extension); identical paths tie-break
  // by error-code-registry order. Run-level codes carry an empty path.
  readonly issues: ReadonlyArray<ValidationIssue>;
  // One entry per record `items[]` element, positionally aligned. Empty
  // exactly when the record carries no `items` array (including every
  // outcome where no record was parsed).
  readonly items: ReadonlyArray<ItemReportEntry>;
  // One entry per record `merkle[]` element, positionally aligned.
  readonly merkle: ReadonlyArray<MerkleReportEntry>;
  // Every outbound network call of the run — success, failure, retry —
  // captured by the single recording egress wrapper.
  readonly auditTrail: ReadonlyArray<HttpCallRecord>;
  // Network of the resolved transaction (e.g. `cardano:mainnet`), as
  // established by the explorer chain the verifier is configured against.
  readonly network: string;
  // Explorer-asserted depth in blocks; present whenever the transaction
  // resolved (always, for valid/pending).
  readonly confirmationDepth?: number;
  readonly confirmationThreshold?: number;
  // POSIX seconds UTC of the slot of the including block — the time T in
  // "this content existed on or before T".
  readonly block_time?: number;
  readonly block_slot?: number;

  // ── Implementation extras (the schema is an open map) ────────────────────
  readonly txHash: string;
  readonly profile: Profile;
  readonly record?: PoeRecord;
  readonly signatures?: ReadonlyArray<VerifyRecordSignature>;
  // Present only when raw tx CBOR is available to the pipeline (the live
  // `verifyTx` path always has it; `verifyResolved` only when `txCbor` is
  // passed).
  readonly txWitnesses?: ReadonlyArray<VerifyTxWitness>;
  readonly txSummary?: VerifyTxSummary;
  readonly metadataLabels?: ReadonlyArray<number>; // ascending; all aux metadata labels
}
