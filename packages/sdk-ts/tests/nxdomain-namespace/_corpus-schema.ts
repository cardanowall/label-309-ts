// Zod schema for the bundled mainnet corpus shape.
//
// Confirmation captures use the MODERN gateway shape: Koios `/tx_info` carries
// `block_height` (no `num_confirmations`), and a separate `koios_tip` capture
// carries the tip `block_height`, so the verifier derives confirmations as
// `max(0, tipHeight - txHeight + 1)` (blocks + 1). A record may instead declare
// `provider: "blockfrost"`, in which case the replay routes through the
// Blockfrost resolver and answers `blockfrost_tx_cbor` / `blockfrost_tx` /
// `blockfrost_blocks_latest` rather than the Koios captures.

import { z } from 'zod';

// Modern Koios `/tx_info` row — `block_height` drives the blocks+1 derivation.
// `num_confirmations` is intentionally absent (current Koios no longer returns
// it); `.passthrough()` tolerates extra gateway fields the verifier ignores.
const KoiosTxInfoSchema = z
  .object({
    tx_hash: z.string(),
    block_height: z.number().int().nonnegative(),
    tx_timestamp: z.number().int().nonnegative(),
    absolute_slot: z.number().int().nonnegative(),
  })
  .passthrough();

// Koios `/tip` row — the chain tip block height.
const KoiosTipSchema = z
  .object({
    block_height: z.number().int().nonnegative(),
  })
  .passthrough();

const KoiosTxCborSchema = z.object({
  tx_hash: z.string(),
  cbor: z.string(),
});

// Blockfrost confirmation-path captures (only present on `provider: "blockfrost"`
// records). `txs/{hash}/cbor` → `{cbor}`, `txs/{hash}` → `{block_time, slot,
// block_height}`, `blocks/latest` → `{height, slot}`.
const BlockfrostTxCborSchema = z.object({ cbor: z.string() }).passthrough();
const BlockfrostTxSchema = z
  .object({
    block_time: z.number().int().nonnegative(),
    slot: z.number().int().nonnegative(),
    block_height: z.number().int().nonnegative(),
  })
  .passthrough();
const BlockfrostBlocksLatestSchema = z
  .object({
    height: z.number().int().nonnegative(),
    slot: z.number().int().nonnegative(),
  })
  .passthrough();

// Out-of-band recipient secret keys (hex) the replay feeds into `verifyTx`'s
// `decryption` keyring so a sealed record's `items[].decryption` is populated.
const RecipientSecretKeySchema = z.object({
  item_index: z.number().int().nonnegative(),
  secret_key: z.string(),
});

export const MainnetCorpusRecordSchema = z.object({
  tx_hash: z.string().length(64),
  expected_verdict: z.enum(['valid', 'pending', 'unverifiable', 'failed']),
  // Which gateway the replay resolves through. Defaults to Koios; only the
  // dedicated Blockfrost-coverage record sets "blockfrost".
  provider: z.enum(['koios', 'blockfrost']).optional(),
  captured_gateway_responses: z.object({
    koios_tx_info: z.array(KoiosTxInfoSchema).optional(),
    koios_tip: z.array(KoiosTipSchema).optional(),
    koios_tx_cbor: z.array(KoiosTxCborSchema).optional(),
    blockfrost_tx_cbor: BlockfrostTxCborSchema.optional(),
    blockfrost_tx: BlockfrostTxSchema.optional(),
    blockfrost_blocks_latest: BlockfrostBlocksLatestSchema.optional(),
    // Captured Arweave gateway bodies, keyed by txid (hex bytes): plain item
    // content, Merkle leaves-list documents, and sealed-PoE ciphertext alike.
    arweave_responses: z.record(z.string(), z.string()).optional(),
  }),
  // Recipient X25519 secrets the replay plumbs into `verifyTx({ decryption })`
  // so sealed records produce a real recipient decrypt in their golden.
  recipient_secret_keys: z.array(RecipientSecretKeySchema).optional(),
  notes: z.string().optional(),
});

export const MainnetCorpusSchema = z.object({
  $schema: z.string(),
  generated: z.string(),
  generator: z.string(),
  records: z.array(MainnetCorpusRecordSchema).min(1),
});

export type MainnetCorpusRecord = z.infer<typeof MainnetCorpusRecordSchema>;
export type MainnetCorpus = z.infer<typeof MainnetCorpusSchema>;
