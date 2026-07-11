import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.venom-cache',
  'coverage',
  '.next',
]);

/**
 * List a project's files as repo-relative paths. Prefers version-controlled files
 * (`git ls-files`) so generated/ignored content is skipped; falls back to a
 * filesystem walk for non-git projects.
 */
export async function listProjectFiles(root: string): Promise<string[]> {
  const tracked = await gitLsFiles(root);
  return tracked.length > 0 ? tracked : walk(root);
}

/** Filter a file list to a set of extensions (e.g. `['.ts', '.js']`). */
export function withExtensions(files: string[], extensions: Set<string>): string[] {
  return files.filter((f) => {
    const dot = f.lastIndexOf('.');
    return dot >= 0 && extensions.has(f.slice(dot));
  });
}

function gitLsFiles(root: string): Promise<string[]> {
  return new Promise((resolve) => {
    const child = spawn('git', ['-C', root, 'ls-files', '-z'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    child.on('error', () => resolve([]));
    let buf = '';
    child.stdout.on('data', (d: Buffer) => (buf += d.toString('utf8')));
    child.on('close', (code) => resolve(code === 0 ? buf.split('\0').filter(Boolean) : []));
  });
}

async function walk(root: string, dir = root, out: string[] = []): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (out.length >= 50_000) break;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) await walk(root, full, out);
    } else if (entry.isFile()) {
      out.push(relative(root, full));
    }
  }
  return out;
}
