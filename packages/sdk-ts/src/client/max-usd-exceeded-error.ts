// Raised by the priced publish helpers (`submitSealed`, `publishSealed`,
// `publishMerkle`) when the gateway's quoted price exceeds the caller's
// `maxUsdMicros` cap. Nothing has been spent when the initial quote breaches
// the cap; a breach detected on a post-upload quote refresh surfaces inside a
// `SubmitSealedError` that carries the completed upload receipts.

/**
 * The quoted price exceeds the caller's price cap.
 *
 * Money stays an integer in-process and a decimal string on the wire:
 * `quotedUsdMicros` is the gateway's decimal micro-USD `amount` string,
 * `maxUsdMicros` the caller's cap (1 USD = 1,000,000 micro-USD).
 */
export class MaxUsdExceededError extends Error {
  /** The quoted total, as the gateway's decimal micro-USD string. */
  readonly quotedUsdMicros: string;
  /** The caller's cap in USD micro-cents. */
  readonly maxUsdMicros: bigint;

  constructor(args: { quotedUsdMicros: string; maxUsdMicros: bigint }) {
    super(
      `MAX_USD_EXCEEDED: quoted price ${args.quotedUsdMicros} micro-USD exceeds the ` +
        `${args.maxUsdMicros} micro-USD cap`,
    );
    this.name = 'MaxUsdExceededError';
    this.quotedUsdMicros = args.quotedUsdMicros;
    this.maxUsdMicros = args.maxUsdMicros;
  }
}
