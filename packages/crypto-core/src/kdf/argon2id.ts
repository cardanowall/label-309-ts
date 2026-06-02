import { argon2id } from 'hash-wasm';

export interface Argon2idParams {
  readonly memSizeKB: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly outBytes: number;
}

export interface Argon2idV13Opts {
  readonly password: Uint8Array;
  readonly salt: Uint8Array;
  readonly memSizeKB: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly outBytes: number;
}

export async function argon2idV13(opts: Argon2idV13Opts): Promise<Uint8Array> {
  return (await argon2id({
    password: opts.password,
    salt: opts.salt,
    parallelism: opts.parallelism,
    iterations: opts.iterations,
    memorySize: opts.memSizeKB,
    hashLength: opts.outBytes,
    outputType: 'binary',
  })) as Uint8Array;
}
