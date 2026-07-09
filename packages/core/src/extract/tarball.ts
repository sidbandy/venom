import { createWriteStream, mkdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep, dirname } from 'node:path';
import { Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';
import { extract as tarExtract, type Headers as TarHeaders } from 'tar-stream';

/**
 * Raised when a tarball entry attempts something a legitimate package never
 * would — escaping the extraction directory, or expanding past sane size limits.
 * This is treated as a hard, loud failure: it is itself a signal that the package
 * may be malicious.
 */
export class TarballSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TarballSecurityError';
  }
}

export interface ExtractOptions {
  /** Cap on total uncompressed bytes across all files. Default 100 MiB. */
  maxTotalBytes?: number;
  /** Cap on a single file's uncompressed bytes. Default 50 MiB. */
  maxFileBytes?: number;
  /** Cap on number of files. Default 20000. */
  maxFileCount?: number;
  /**
   * Leading path components to strip. npm/PyPI sdists wrap everything in a single
   * top-level directory (`package/`, `name-version/`), so this defaults to 1.
   */
  stripComponents?: number;
}

/** An entry that was refused for safety, surfaced so callers can report on it. */
export interface SkippedEntry {
  name: string;
  type: string;
  reason: string;
}

export interface ExtractResult {
  /** Absolute path to the extracted contents (a fresh temp directory). */
  extractedPath: string;
  totalBytes: number;
  fileCount: number;
  /** Non-file entries (symlinks, devices, …) that were skipped rather than written. */
  skipped: SkippedEntry[];
  /** Remove the temp directory. Callers MUST invoke this when done. */
  dispose(): Promise<void>;
}

const DEFAULTS = {
  maxTotalBytes: 100 * 1024 * 1024,
  maxFileBytes: 50 * 1024 * 1024,
  maxFileCount: 20_000,
  stripComponents: 1,
};

const FILE_TYPES = new Set<string | null | undefined>(['file', 'contiguous-file']);

/**
 * Safely extract a gzip-compressed tarball (a `.tgz`, as served by npm and PyPI)
 * into a fresh temp directory **without executing any of its contents**
 * (SPEC.md §4 M3). Guards enforced:
 *   - path traversal / zip-slip: every entry must resolve inside the target dir,
 *   - symlinks, hardlinks, and device nodes are skipped (they can point outside),
 *   - decompression bombs: total, per-file, and file-count limits are enforced
 *     while streaming, so an oversized archive is aborted early.
 */
export async function extractTarball(
  data: Buffer,
  options: ExtractOptions = {},
): Promise<ExtractResult> {
  const opts = { ...DEFAULTS, ...options };
  const targetDir = await mkdtemp(join(tmpdir(), 'venom-pkg-'));

  const cleanup = () => rm(targetDir, { recursive: true, force: true });

  let totalBytes = 0;
  let fileCount = 0;
  const skipped: SkippedEntry[] = [];

  try {
    await new Promise<void>((resolvePromise, rejectPromise) => {
      const ex = tarExtract();
      let settled = false;

      const fail = (err: Error): void => {
        if (settled) return;
        settled = true;
        ex.destroy();
        rejectPromise(err);
      };

      const handleEntry = (
        headers: TarHeaders,
        stream: NodeJS.ReadableStream,
        next: (error?: unknown) => void,
      ): void => {
        // Drain-and-skip helper for entries we won't write.
        const skip = (reason: string): void => {
          skipped.push({ name: headers.name, type: String(headers.type), reason });
          stream.on('end', next);
          stream.resume();
        };

        // Only regular files and directories are ever written. Everything else
        // (symlink/link/char-device/block-device/fifo) is a potential escape vector.
        if (!FILE_TYPES.has(headers.type) && headers.type !== 'directory') {
          skip(`unsupported entry type "${String(headers.type)}"`);
          return;
        }

        const rel = stripComponents(headers.name, opts.stripComponents);
        if (!rel) {
          skip('empty path after strip');
          return;
        }

        const dest = resolve(targetDir, rel);
        if (dest !== targetDir && !dest.startsWith(targetDir + sep)) {
          fail(new TarballSecurityError(`Path traversal in tarball entry: "${headers.name}"`));
          return;
        }

        if (headers.type === 'directory') {
          mkdirSync(dest, { recursive: true });
          stream.on('end', next);
          stream.resume();
          return;
        }

        fileCount += 1;
        if (fileCount > opts.maxFileCount) {
          fail(
            new TarballSecurityError(
              `Tarball exceeds file-count limit (${opts.maxFileCount}); possible archive bomb`,
            ),
          );
          return;
        }

        mkdirSync(dirname(dest), { recursive: true });
        const ws = createWriteStream(dest);
        let fileBytes = 0;

        stream.on('data', (chunk: Buffer) => {
          fileBytes += chunk.length;
          totalBytes += chunk.length;
          if (fileBytes > opts.maxFileBytes || totalBytes > opts.maxTotalBytes) {
            fail(
              new TarballSecurityError(
                'Tarball exceeds uncompressed size limit; possible decompression bomb',
              ),
            );
          }
        });
        stream.on('error', fail);
        ws.on('error', fail);
        ws.on('finish', () => next());
        stream.pipe(ws);
      };

      ex.on('entry', (headers, stream, next) => {
        if (settled) return;
        try {
          handleEntry(headers, stream, next);
        } catch (err) {
          fail(err instanceof Error ? err : new Error(String(err)));
        }
      });
      ex.on('finish', () => {
        if (!settled) {
          settled = true;
          resolvePromise();
        }
      });
      ex.on('error', fail);

      const gunzip = createGunzip();
      gunzip.on('error', fail);
      Readable.from(data).on('error', fail).pipe(gunzip).pipe(ex);
    });
  } catch (err) {
    await cleanup();
    throw err;
  }

  return {
    extractedPath: targetDir,
    totalBytes,
    fileCount,
    skipped,
    dispose: cleanup,
  };
}

/** Drop the first `n` path components; normalize away `.` and empty segments. */
function stripComponents(name: string, n: number): string {
  const parts = name.split('/').filter((p) => p.length > 0 && p !== '.');
  return parts.slice(n).join('/');
}
