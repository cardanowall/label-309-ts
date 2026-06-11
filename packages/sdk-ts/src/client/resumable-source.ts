// A runtime-neutral view of the bytes a resumable upload reads from. The
// helper needs three things from its source and nothing else:
//
//   1. the total byte length (declared to the gateway at session create),
//   2. an ordered byte stream over the whole input (to compute the whole-file
//      SHA-256 without buffering it), and
//   3. random-access slices by byte range (to read one chunk at a time).
//
// A browser `Blob`/`File` satisfies all three natively (`.size`, `.stream()`,
// `.slice()`), and streams from disk rather than loading into memory. On the
// server the same contract is met by a byte array, a filesystem path, or a Node
// readable stream — each adapted to the same `ResumableSource` shape here, so
// the protocol driver never branches on the runtime.

// `node:fs/promises` is imported lazily, never at module top level: this package
// is browser-safe and apps bundle it for the browser, so a static `node:` import
// would pull a Node builtin into every browser build and break it. Only the
// filesystem-path source actually needs it, and that branch runs only in Node;
// the Blob/File/Uint8Array sources (the browser cases) never reach this loader.
type FsPromisesOpen = (typeof import('node:fs/promises'))['open'];

let openHandlePromise: Promise<FsPromisesOpen> | undefined;
async function loadOpen(): Promise<FsPromisesOpen> {
  // Cache the dynamic import so repeated path-source reads share one resolution.
  if (openHandlePromise === undefined) {
    openHandlePromise = import('node:fs/promises').then((fs) => fs.open);
  }
  return openHandlePromise;
}

/** The runtime-neutral source contract the resumable uploader drives. */
export interface ResumableSource {
  /** Total number of bytes in the input. */
  readonly size: number;
  /**
   * Read the half-open byte range `[start, end)`. May resolve synchronously or
   * asynchronously; callers always `await` the result. The returned array owns
   * its bytes (callers may transfer it into a request body).
   */
  slice(start: number, end: number): Uint8Array | Promise<Uint8Array>;
  /**
   * An ordered async stream over the whole input, used once to compute the
   * whole-file digest. Implementations stream in bounded chunks so a multi-GB
   * input is never materialised in full.
   */
  stream(): AsyncIterable<Uint8Array>;
}

/**
 * Any value `toResumableSource` knows how to adapt:
 *  - a `ResumableSource` (passed through),
 *  - a browser `Blob`/`File` (uses native `.slice()`/`.stream()`),
 *  - a `Uint8Array`/`Buffer` (in-memory bytes),
 *  - a filesystem path string (read in bounded slices, never fully buffered).
 */
export type ResumableSourceInput = ResumableSource | Blob | Uint8Array | string;

// Default stream chunk for the whole-file hash pass. Independent of the upload
// chunk size: this only bounds the hashing read buffer, so a small value keeps
// peak memory low without affecting wire behaviour.
const HASH_STREAM_CHUNK_BYTES = 1024 * 1024;

function isResumableSource(value: unknown): value is ResumableSource {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ResumableSource).size === 'number' &&
    typeof (value as ResumableSource).slice === 'function' &&
    typeof (value as ResumableSource).stream === 'function' &&
    // A Blob/File shares all three members but exposes `.arrayBuffer`; exclude it
    // here so the adapter contract is unambiguous regardless of check order. A
    // Blob is handled by its own branch, which adapts `.slice`/`.stream` to bytes.
    typeof (value as { arrayBuffer?: unknown }).arrayBuffer !== 'function'
  );
}

// A `Blob` is detected structurally (not via `instanceof Blob`) so the check
// holds across realms and runtimes that expose a Blob-shaped object without the
// same constructor identity.
function isBlobLike(value: unknown): value is Blob {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Blob).size === 'number' &&
    typeof (value as Blob).slice === 'function' &&
    typeof (value as Blob).arrayBuffer === 'function'
  );
}

async function blobSlice(blob: Blob, start: number, end: number): Promise<Uint8Array> {
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

async function* blobStream(blob: Blob): AsyncIterable<Uint8Array> {
  // `Blob.stream()` yields from disk in the browser and from the in-memory
  // buffer in Node; either way it never copies the whole blob into one array.
  const reader = blob.stream().getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) yield value as Uint8Array;
    }
  } finally {
    reader.releaseLock();
  }
}

function fromBlob(blob: Blob): ResumableSource {
  return {
    size: blob.size,
    slice: (start, end) => blobSlice(blob, start, end),
    stream: () => blobStream(blob),
  };
}

function fromBytes(bytes: Uint8Array): ResumableSource {
  return {
    size: bytes.byteLength,
    slice: (start, end) => bytes.subarray(start, end),
    stream: async function* () {
      for (let offset = 0; offset < bytes.byteLength; offset += HASH_STREAM_CHUNK_BYTES) {
        yield bytes.subarray(offset, Math.min(offset + HASH_STREAM_CHUNK_BYTES, bytes.byteLength));
      }
    },
  };
}

async function fromPath(path: string): Promise<ResumableSource> {
  const open = await loadOpen();
  // Read each slice with a positional read so the file is never buffered whole;
  // the whole-file hash pass streams it in bounded chunks for the same reason.
  const sliceAt = async (start: number, end: number): Promise<Uint8Array> => {
    const length = end - start;
    if (length <= 0) return new Uint8Array(0);
    const handle = await open(path, 'r');
    try {
      const buffer = new Uint8Array(length);
      // A single positional read may return fewer bytes than requested (a short
      // read is allowed by the OS even mid-file), so loop until the slice is
      // filled or we hit real EOF. Emitting a short chunk for a non-final index
      // would corrupt the assembled file, since the gateway places each chunk at
      // its deterministic offset; only the final chunk may legitimately be short.
      let filled = 0;
      while (filled < length) {
        const { bytesRead } = await handle.read(buffer, filled, length - filled, start + filled);
        if (bytesRead === 0) break; // real EOF: the file is shorter than declared
        filled += bytesRead;
      }
      return filled === length ? buffer : buffer.subarray(0, filled);
    } finally {
      await handle.close();
    }
  };
  const streamFile = async function* (): AsyncIterable<Uint8Array> {
    const handle = await open(path, 'r');
    try {
      const buffer = new Uint8Array(HASH_STREAM_CHUNK_BYTES);
      let position = 0;
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (bytesRead === 0) break;
        position += bytesRead;
        // Copy out the filled prefix; the buffer is reused on the next read.
        yield buffer.slice(0, bytesRead);
      }
    } finally {
      await handle.close();
    }
  };
  const { size } = await statSize(path);
  return { size, slice: sliceAt, stream: streamFile };
}

async function statSize(path: string): Promise<{ size: number }> {
  const open = await loadOpen();
  // `readFile().byteLength` would buffer the whole file; use the handle's stat
  // instead so a large file's size is read without touching its bytes.
  const handle = await open(path, 'r');
  try {
    const stats = await handle.stat();
    return { size: stats.size };
  } finally {
    await handle.close();
  }
}

/**
 * Adapt any supported input to the runtime-neutral {@link ResumableSource}
 * contract. Returns a promise because a filesystem-path source must stat the
 * file before its size is known. Throws `TypeError` for unsupported inputs.
 *
 * The path branch is the only one that touches `node:fs`; a browser caller
 * passes a `Blob`/`File` or `Uint8Array` and never reaches it.
 */
export async function toResumableSource(input: ResumableSourceInput): Promise<ResumableSource> {
  if (typeof input === 'string') return fromPath(input);
  if (input instanceof Uint8Array) return fromBytes(input);
  // A `Blob`/`File` is checked BEFORE the generic `ResumableSource` shape: a Blob
  // also has `.size`/`.slice`/`.stream`, but its `.slice` returns a `Blob` (not a
  // `Uint8Array`) and its `.stream` is a `ReadableStream`, so passing it through
  // as a `ResumableSource` would hand the uploader Blobs where it expects byte
  // arrays. `isBlobLike` keys on `.arrayBuffer`, which a real adapter never has.
  if (isBlobLike(input)) return fromBlob(input);
  if (isResumableSource(input)) return input;
  throw new TypeError(
    'uploadResumable: unsupported source. Pass a Blob/File, a Uint8Array, a ' +
      'filesystem path string, or a ResumableSource.',
  );
}
