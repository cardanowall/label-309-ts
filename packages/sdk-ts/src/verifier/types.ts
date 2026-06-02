// Public types for the CIP-309 standalone verifier.
//
// The verifier is service-independent: it depends only on the operator-supplied
// Cardano / Arweave / IPFS gateway chains and a `denyHosts` policy. Every
// outbound network call routes through `fetchOutbound` (single egress point)
// and lands in `VerifyReport.httpCalls` for audit.

import type { PoeRecord, ValidationIssue } from '@cardanowall/poe-standard';

import type { FetchOutbound, HttpCallRecord } from '../fetch/fetch-outbound';

// -----------------------------------------------------------------------------
// Verdict / exit-code
// -----------------------------------------------------------------------------
//
// `'valid'`   → exit 0 — every check returned ok.
// `'pending'` → exit 3 — INSUFFICIENT_CONFIRMATIONS (record well-formed but
//               below the verifier's reorg-safety threshold).
// `'failed'`  → exit 1 — integrity / structural / signature class.
//             → exit 2 — network class (CONTENT_UNAVAILABLE, PROVIDER_UNAVAILABLE).

export type Verdict = 'valid' | 'pending' | 'failed';
export type ExitCode = 0 | 1 | 2 | 3;

// -----------------------------------------------------------------------------
// Conformance profile
// -----------------------------------------------------------------------------
//
// Strict-superset order: each higher profile reads everything below it plus
// one additional surface. A verifier of a LOWER profile that sees a field
// belonging to a HIGHER profile MUST emit `OUT_OF_PROFILE_SKIPPED`
// (info-severity) and continue — it MUST NOT report the record as invalid.

export type Profile = 'core' | 'signed' | 'sealed' | 'recipient-sealed';

// -----------------------------------------------------------------------------
// Network identifier — mainnet-only policy.
// -----------------------------------------------------------------------------
//
// Cardano mainnet only; testnet is explicitly out-of-scope by project
// policy. The literal `'cardano:mainnet'` is the wire-canonical
// identifier surfaced in every VerifyReport so a downstream consumer never has
// to infer which network the record was anchored on.

export type Network = 'cardano:mainnet';

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
// downstream consumers can dispatch on a single union (`ErrorCode` covers
// both Part A and Part B per `@cardanowall/poe-standard`).
// -----------------------------------------------------------------------------

export type { ValidationIssue } from '@cardanowall/poe-standard';

// -----------------------------------------------------------------------------
// VerifyTx input — discriminated decryption union.
// -----------------------------------------------------------------------------

export interface VerifyTxInput {
  readonly txHash: string; // lowercase hex, no 0x prefix
  readonly profile?: Profile; // default 'recipient-sealed' (full pipeline)
  readonly cardanoGatewayChain?: ReadonlyArray<string>; // Koios-compatible URLs, in order
  readonly blockfrostProjectId?: string; // enables Blockfrost fallback
  readonly arweaveGatewayChain?: ReadonlyArray<string>;
  readonly ipfsGatewayChain?: ReadonlyArray<string>;
  readonly confirmationDepthThreshold?: number; // default 15; verifier-policy floor
  readonly denyHosts?: ReadonlyArray<string>; // service-independence guard
  // Master offline switch for the verifier's outbound URI fetches. When
  // `false`, the verifier neither fetches a sealed item's `uris[]` ciphertext
  // (decryption falls back to caller-supplied `ciphertextBytes` only) nor the
  // Merkle list-commitment leaves-list — so a Merkle-bearing or sealed record
  // verifies with ZERO egress beyond the chain/indexer resolve step. The
  // on-record `record.merkle[]` / `items[].uris[]` data round-trips through
  // `record` unchanged; only the verifier's defence-in-depth recompute and the
  // ciphertext download are suppressed. Defaults to `true` (full pipeline).
  // Server-rendered pages flip this to `false` so hash-only / merkle-only /
  // sealed records render from indexed CBOR alone, with the leaves-list and
  // ciphertext fetches deferred to a user-initiated client-side action.
  readonly verifyMerkle?: boolean;
  // Out-of-band sealed-PoE decryption attempts. The verifier dispatches by
  // inspecting `items[i].enc.slots` vs `items[i].enc.passphrase` presence; a
  // mismatched entry surfaces as WRONG_DECRYPTION_INPUT_SHAPE.
  readonly decryption?: ReadonlyArray<
    | { readonly itemIndex: number; readonly recipientSecretKey: Uint8Array }
    | { readonly itemIndex: number; readonly passphrase: string }
  >;
  // Out-of-band ciphertext bytes (keyed by item index). When supplied, takes
  // precedence over `items[i].uris[]` (no network fetch is issued).
  readonly ciphertextBytes?: Readonly<Record<number, Uint8Array>>;
  // Out-of-band Merkle leaves-list bytes (keyed by `record.merkle[i]` index).
  // CBOR is the normative wire form.
  readonly merkleLeaves?: Readonly<Record<number, Uint8Array>>;
  // For stake-address binding (path-2 wallet signatures). The
  // verifier recomputes `network_header || Blake2b-224(pubkey)` and compares
  // to the protected-header `address` field; mismatch emits
  // WALLET_ADDRESS_MISMATCH. Defaults to 'mainnet' when omitted; 'preprod' is
  // supplied only by callers running against the Cardano preprod testnet
  // (worker dev mode, future receiver-side scanner on preprod). The
  // wire-canonical `VerifyReport.network` field stays pinned to
  // 'cardano:mainnet' — this input only governs the stake-byte used for
  // path-2 address derivation.
  readonly cardanoNetwork?: 'mainnet' | 'preprod';
  // Injected for tests; defaults to fetchOutbound (the single egress point).
  readonly fetchOutbound?: FetchOutbound;
}

// -----------------------------------------------------------------------------
// VerifyReport shape.
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
  readonly signer_pub?: string; // lowercase hex of 32-byte Ed25519 pubkey when resolved
  readonly signer_type?: SignerType;
  readonly reason?: SignatureFailureReason;
}

export type DecryptionVerdict =
  | 'decrypted'
  | 'wrong-key'
  | 'tampered-header'
  | 'tampered-ciphertext'
  | 'wrong-input-shape'
  | 'no-enc-envelope'
  | 'ciphertext-unavailable'
  | 'content-unavailable'
  | 'skipped'
  | 'kdf-failed';

export interface VerifyItemDecryption {
  readonly item_index: number;
  readonly verdict: DecryptionVerdict;
  // True iff every content-hash entry in `items[i].hashes` recomputes to the
  // recovered plaintext. Always a concrete boolean on `verdict === 'decrypted'`.
  readonly plaintext_hash_ok?: boolean;
  readonly reason?: string;
}

export type ItemHashCheck = {
  readonly item_index: number;
  readonly alg: string;
  readonly ok: boolean;
};

export type MerkleVerdict =
  | 'valid'
  | 'mismatch'
  | 'unavailable'
  | 'format-unsupported'
  | 'unsupported';

export interface VerifyMerkleCheck {
  readonly merkle_index: number;
  readonly alg: string;
  readonly verdict: MerkleVerdict;
  readonly root_recomputed?: Uint8Array;
  readonly reason?: string;
}

export interface VerifyUriCheck {
  readonly item_index: number;
  readonly uri: string;
  readonly ok: boolean;
  readonly reason?: string;
}

// -----------------------------------------------------------------------------
// Transaction-level description — DISTINCT from record-level authorship.
// -----------------------------------------------------------------------------
//
// These surfaces describe the Cardano transaction that carried the PoE: which
// wallet vkey(s) authorised/paid for it, the fee, and the outputs. This is the
// "who submitted and paid for this anchoring" view — orthogonal to
// `record_signatures`, which is the optional CIP-309 record-level authorship
// claim. A failed `signature_valid` here is INFORMATIONAL: it never changes the
// verifier's verdict (the content claim does not depend on who paid the fee).

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

// VerifyReport is snake_case end-to-end: the wire shape, the SDK's in-memory
// representation, and every consumer-facing field share the same identifier
// grammar. No transformer layer between the verifier and the API response —
// `VerifyReport` IS the wire body for `POST /api/v1/records/{tx_hash}/verify`.
export interface VerifyReport {
  readonly tx_hash: string;
  readonly network: Network;
  readonly verdict: Verdict;
  readonly exit_code: ExitCode;
  readonly profile: Profile;
  readonly num_confirmations: number;
  readonly confirmation_depth_threshold: number;
  readonly block_time?: number;
  readonly block_slot?: number;
  readonly metadata_present: boolean;
  readonly validation: {
    readonly valid: boolean;
    readonly issues?: ReadonlyArray<ValidationIssue>;
    readonly warnings?: ReadonlyArray<ValidationIssue>;
    readonly info?: ReadonlyArray<ValidationIssue>;
  };
  readonly record?: PoeRecord;
  readonly record_signatures?: ReadonlyArray<VerifyRecordSignature>;
  // Transaction-level description (present only when raw tx CBOR is available
  // to the pipeline — the live `verifyTx` path always has it; the DB-first
  // `verifyResolved` path has it only when the caller passes `txCbor`).
  readonly tx_witnesses?: ReadonlyArray<VerifyTxWitness>;
  readonly tx_summary?: VerifyTxSummary;
  readonly metadata_labels?: ReadonlyArray<number>; // sorted ascending; all aux metadata label keys
  readonly item_hash_checks?: ReadonlyArray<ItemHashCheck>;
  readonly item_decryptions?: ReadonlyArray<VerifyItemDecryption>;
  readonly merkle_checks?: ReadonlyArray<VerifyMerkleCheck>;
  readonly uri_checks?: ReadonlyArray<VerifyUriCheck>;
  readonly supersedes_resolved?: { readonly tx: string; readonly exists: boolean };
  readonly http_calls: ReadonlyArray<HttpCallRecord>;
}
