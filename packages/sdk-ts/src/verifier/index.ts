// Public surface of the Label 309 standalone verifier. Named exports only.

export * from './types';
export {
  verifyTx,
  verifyResolved,
  CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
  exitCodeForVerdict,
} from './verify';
export { verifyRecordSignatures } from './signatures';
export { tryDecryptions } from './decrypt';
export { verifyMerkleCommitments } from './merkle';
export { DEFAULT_PROFILE, profileImplements, planProfileSkips } from './profile';
export {
  BLOCKFROST_MAINNET_HOST,
  KOIOS_MAINNET_URL,
  NotALabel309RecordError,
  extractLabel309Metadata,
  resolveCardanoTx,
} from './resolve';
export type { ResolvedTx } from './resolve';
export { sliceLabel309Value, sliceTxComponents } from './cbor-walker';
export type { TxComponents } from './cbor-walker';
export { decodeTxWitnesses, decodeTxSummary } from './tx-witnesses';

// Canonical fetch primitives re-exported from `./fetch.ts` for convenience.
export {
  BodyTooLargeError,
  DEFAULT_OUTBOUND_MAX_BYTES,
  defaultFetchOutbound,
  DENY_HOSTS_DEFAULT,
  DenyHostError,
  fetchItemCiphertext,
  fetchOutbound,
  OutboundExhaustedError,
  UnsupportedMethodError,
  UnsupportedProtocolError,
  wrapFetchOutbound,
} from './fetch';
export type { RetryConfig, WrapFetchOutboundConfig } from './fetch';

export { verifyReportToDict } from './serialize';
