#!/usr/bin/env node
// Conformance CLI: single-tx verification against the CIP-309 standalone
// verifier.
//
// Exit codes (extended with 4 for CLI input errors):
//   0 = valid, 1 = failed (integrity), 2 = failed (network),
//   3 = pending, 4 = CLI input error

import { KOIOS_MAINNET_URL, exitCodeForVerdict, verifyTx } from '../verifier/index';

const VERSION = '0.1.0';

interface ParsedArgs {
  readonly txHash: string | undefined;
  readonly gateways: ReadonlyArray<string>;
  readonly threshold: number | undefined;
  readonly json: boolean;
  readonly showHelp: boolean;
  readonly showVersion: boolean;
  readonly error: string | undefined;
}

export function parseArgs(args: ReadonlyArray<string>): ParsedArgs {
  let txHash: string | undefined;
  const gateways: string[] = [];
  let threshold: number | undefined;
  let json = true;
  let showHelp = false;
  let showVersion = false;
  let error: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--help' || arg === '-h') {
      showHelp = true;
    } else if (arg === '--version' || arg === '-V') {
      showVersion = true;
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--gateway') {
      const v = args[++i];
      if (v === undefined) {
        error = '--gateway requires a value';
        break;
      }
      gateways.push(v);
    } else if (arg === '--threshold') {
      const v = args[++i];
      const n = Number(v);
      if (v === undefined || !Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
        error = '--threshold requires a non-negative integer';
        break;
      }
      threshold = n;
    } else if (arg.startsWith('-')) {
      error = `unknown flag: ${arg}`;
      break;
    } else if (txHash === undefined) {
      txHash = arg;
    } else {
      error = `unexpected positional argument: ${arg}`;
      break;
    }
  }

  return { txHash, gateways, threshold, json, showHelp, showVersion, error };
}

const USAGE = `Usage: cardanowall-sdk-conformance <tx-hash> [--gateway <url>] [--threshold <n>] [--json]
       cardanowall-sdk-conformance --version
       cardanowall-sdk-conformance --help

Runs the @cardanowall/sdk-ts standalone CIP-309 verifier against a single
Cardano transaction. Exit codes:
  0 = valid, 1 = failed (integrity), 2 = failed (network), 3 = pending,
  4 = CLI input error.`;

export interface RunIO {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export async function run(args: ReadonlyArray<string>, io: RunIO): Promise<number> {
  const parsed = parseArgs(args);
  if (parsed.showHelp) {
    io.stdout(USAGE + '\n');
    return 0;
  }
  if (parsed.showVersion) {
    io.stdout(`cardanowall-sdk-conformance ${VERSION}\n`);
    return 0;
  }
  if (parsed.error !== undefined) {
    io.stderr(`cardanowall-sdk-conformance: ${parsed.error}\n`);
    io.stderr(USAGE + '\n');
    return 4;
  }
  if (parsed.txHash === undefined) {
    io.stderr('cardanowall-sdk-conformance: <tx-hash> is required\n');
    io.stderr(USAGE + '\n');
    return 4;
  }
  if (!/^[0-9a-f]{64}$/i.test(parsed.txHash)) {
    io.stderr(
      `cardanowall-sdk-conformance: invalid tx-hash (expected 64 hex chars): ${parsed.txHash}\n`,
    );
    return 4;
  }

  const gateways = parsed.gateways.length > 0 ? parsed.gateways : [KOIOS_MAINNET_URL];

  try {
    const report = await verifyTx({
      txHash: parsed.txHash.toLowerCase(),
      cardanoGatewayChain: gateways,
      ...(parsed.threshold !== undefined ? { confirmationDepthThreshold: parsed.threshold } : {}),
    });
    io.stdout(JSON.stringify(report, null, 2) + '\n');
    return exitCodeForVerdict(report);
  } catch (err) {
    io.stderr(
      `cardanowall-sdk-conformance: verifier error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 2;
  }
}

// Only run as a script when invoked directly (not when imported by tests).
if (/cli\.(c?js|ts)$/.test(process.argv[1] ?? '')) {
  void run(process.argv.slice(2), {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
  }).then((code) => process.exit(code));
}
