// Public surface of the Label 309 standalone verifier. Named exports only.

export * from './types';
export {
  verifyTx,
  verifyResolved,
  CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
  exitCodeForVerdict,
} from './verify';
export { verifyRecordSignatures } from './signatures';
export {
  DEFAULT_PROFILE,
  detectConformanceProfile,
  profileImplements,
  planProfileSkips,
} from './profile';
export { BLOCKFROST_MAINNET_HOST, KOIOS_MAINNET_URL, resolveCardanoTx } from './resolve';
export type { ResolvedTx, ResolveOutcome, ResolveFailureCode } from './resolve';
export { bindTransactionBytes } from './tx-binding';
export type { TxBindingResult } from './tx-binding';
export { auxiliaryDataHashFromTxBody, sliceTxComponents, unwrapAuxiliaryData } from './cbor-walker';
export type { TxComponents, UnwrappedAuxiliaryData } from './cbor-walker';
export { decodeTxWitnesses, decodeTxSummary } from './tx-witnesses';
export { parseCid, verifyIpfsCidBinding } from './cid';
export type { ParsedCid, CidBindingOutcome } from './cid';
export { ARWEAVE_GATEWAY_DEFAULTS } from './content';
export { compareIssuePaths, IssueSink, issueOf, sortIssues } from './issues';
export type { IssuePath } from './issues';

// Canonical fetch primitives re-exported for convenience.
export {
  BodyTooLargeError,
  DEFAULT_OUTBOUND_MAX_BYTES,
  defaultFetchOutbound,
  DENY_HOSTS_DEFAULT,
  DenyHostError,
  fetchOutbound,
  isBodyTooLargeError,
  isDenyHostError,
  OutboundExhaustedError,
  UnsupportedMethodError,
  UnsupportedProtocolError,
  wrapFetchOutbound,
} from '../fetch/fetch-outbound';
export type { RetryConfig, WrapFetchOutboundConfig } from '../fetch/fetch-outbound';

export { verifyReportToDict } from './serialize';
