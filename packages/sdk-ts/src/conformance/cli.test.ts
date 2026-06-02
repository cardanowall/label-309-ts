// Unit tests for the conformance CLI dispatcher.

import { describe, expect, it, vi } from 'vitest';

import { parseArgs, run } from './cli';

// Mock `verifyTx` so the CLI's exit-code branches are exercised without
// actually reaching out to Koios. We stub the verifier module at the import
// boundary using vi.hoisted + vi.mock.
const verifyTxMock = vi.hoisted(() => vi.fn());
vi.mock('../verifier/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../verifier/index')>();
  return {
    ...actual,
    verifyTx: verifyTxMock,
  };
});

function makeIO(): {
  stdout: string[];
  stderr: string[];
  io: { stdout: (s: string) => void; stderr: (s: string) => void };
} {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    io: {
      stdout: (s) => stdout.push(s),
      stderr: (s) => stderr.push(s),
    },
  };
}

const VALID_TX = 'a'.repeat(64);

function fakeReport(overrides: Record<string, unknown>): unknown {
  return {
    verdict: 'valid',
    exit_code: 0,
    tx_hash: VALID_TX,
    profile: 'recipient-sealed',
    network: 'cardano:mainnet',
    confirmations: 100,
    items: [],
    signatures: [],
    http_calls: [],
    info: [],
    warnings: [],
    ...overrides,
  };
}

describe('parseArgs', () => {
  it('extracts tx hash as first positional', () => {
    const out = parseArgs([VALID_TX]);
    expect(out.txHash).toBe(VALID_TX);
  });

  it('rejects unknown flag', () => {
    const out = parseArgs(['--bogus']);
    expect(out.error).toMatch(/unknown flag/);
  });

  it('parses --gateway URLs (repeatable)', () => {
    const out = parseArgs([VALID_TX, '--gateway', 'http://g1', '--gateway', 'http://g2']);
    expect(out.gateways).toEqual(['http://g1', 'http://g2']);
  });

  it('parses --threshold as integer', () => {
    const out = parseArgs([VALID_TX, '--threshold', '30']);
    expect(out.threshold).toBe(30);
  });

  it('rejects non-integer --threshold', () => {
    const out = parseArgs([VALID_TX, '--threshold', '1.5']);
    expect(out.error).toMatch(/non-negative integer/);
  });

  it('captures --help / --version flags', () => {
    expect(parseArgs(['--help']).showHelp).toBe(true);
    expect(parseArgs(['--version']).showVersion).toBe(true);
  });
});

describe('run — exit codes', () => {
  it('exits 0 on valid verdict', async () => {
    verifyTxMock.mockResolvedValueOnce(fakeReport({ verdict: 'valid', exit_code: 0 }));
    const { io, stdout } = makeIO();
    const code = await run([VALID_TX], io);
    expect(code).toBe(0);
    expect(stdout.join('')).toContain('"verdict": "valid"');
  });

  it('exits 1 on integrity failure', async () => {
    verifyTxMock.mockResolvedValueOnce(fakeReport({ verdict: 'failed', exit_code: 1 }));
    const { io } = makeIO();
    expect(await run([VALID_TX], io)).toBe(1);
  });

  it('exits 2 on network failure', async () => {
    verifyTxMock.mockResolvedValueOnce(fakeReport({ verdict: 'failed', exit_code: 2 }));
    const { io } = makeIO();
    expect(await run([VALID_TX], io)).toBe(2);
  });

  it('exits 3 on pending verdict', async () => {
    verifyTxMock.mockResolvedValueOnce(fakeReport({ verdict: 'pending', exit_code: 3 }));
    const { io } = makeIO();
    expect(await run([VALID_TX], io)).toBe(3);
  });

  it('exits 4 when tx-hash is missing', async () => {
    const { io, stderr } = makeIO();
    const code = await run([], io);
    expect(code).toBe(4);
    expect(stderr.join('')).toMatch(/tx-hash.*required/i);
  });

  it('exits 4 when tx-hash is malformed', async () => {
    const { io, stderr } = makeIO();
    const code = await run(['not-a-hex'], io);
    expect(code).toBe(4);
    expect(stderr.join('')).toMatch(/invalid tx-hash/i);
  });

  it('exits 4 on unknown flag', async () => {
    const { io } = makeIO();
    expect(await run(['--bogus', VALID_TX], io)).toBe(4);
  });

  it('exits 2 when verifyTx throws (network class catch-all)', async () => {
    verifyTxMock.mockRejectedValueOnce(new Error('network down'));
    const { io, stderr } = makeIO();
    expect(await run([VALID_TX], io)).toBe(2);
    expect(stderr.join('')).toMatch(/verifier error/);
  });

  it('--version exits 0 and prints version', async () => {
    const { io, stdout } = makeIO();
    expect(await run(['--version'], io)).toBe(0);
    expect(stdout.join('')).toMatch(/cardanowall-sdk-conformance/);
  });

  it('--help exits 0 and prints usage', async () => {
    const { io, stdout } = makeIO();
    expect(await run(['--help'], io)).toBe(0);
    expect(stdout.join('')).toMatch(/Usage:/);
  });
});
