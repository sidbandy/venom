import { spawn } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { join, relative } from 'node:path';
import { scanContent, type RawSecretMatch } from './scan-content';
import type { IgnoreMatcher } from './ignore';

export interface FileSecretMatch extends RawSecretMatch {
  /** Repo-relative file path. */
  file: string;
  /** Commit sha when the match comes from git history; absent for the working tree. */
  commit?: string;
}

export interface GitScanOptions {
  /** Stop after this many matches (protects against pathological histories). */
  maxMatches?: number;
  /** Files whose path matches are skipped (from `.venomignore`). */
  ignore?: IgnoreMatcher;
}

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', '.venom-cache', 'coverage']);

/**
 * Scan the current working tree for secrets (SPEC.md §4 M4). Prefers the set of
 * version-controlled files (`git ls-files`) so generated/ignored content isn't
 * scanned; falls back to a filesystem walk when the directory isn't a git repo.
 */
export async function scanWorkingTree(
  root: string,
  options: GitScanOptions = {},
): Promise<FileSecretMatch[]> {
  const maxMatches = options.maxMatches ?? 10_000;
  const ignore = options.ignore ?? (() => false);
  let files = await listTrackedFiles(root);
  if (files.length === 0) files = await walkFiles(root);

  const matches: FileSecretMatch[] = [];
  for (const rel of files) {
    if (matches.length >= maxMatches) break;
    if (ignore(rel)) continue;
    let text: string;
    try {
      text = await readFile(join(root, rel), 'utf8');
    } catch {
      continue;
    }
    for (const raw of scanContent(text)) matches.push({ ...raw, file: rel });
  }
  return matches;
}

/**
 * Walk the **entire git history** (every commit, every branch) for secrets that
 * were committed and later removed — still permanently recoverable by anyone who
 * clones the repo (SPEC.md §4 M4). Streams `git log -p` rather than buffering it.
 */
export async function scanGitHistory(
  root: string,
  options: GitScanOptions = {},
): Promise<FileSecretMatch[]> {
  const maxMatches = options.maxMatches ?? 10_000;
  const ignore = options.ignore ?? (() => false);
  return new Promise((resolve) => {
    const matches: FileSecretMatch[] = [];
    const seen = new Set<string>();
    const child = spawn(
      'git',
      ['-C', root, 'log', '--all', '-p', '-U0', '--no-color', '--diff-filter=AM'],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
    child.on('error', () => resolve([])); // git not installed / not a repo

    let commit = '';
    let file = '';
    let skipFile = false;
    let newLine = 0;

    const rl = createInterface({ input: child.stdout });
    rl.on('line', (line) => {
      if (matches.length >= maxMatches) return;
      if (line.startsWith('commit ')) {
        commit = line.slice(7, 47);
      } else if (line.startsWith('+++ b/')) {
        file = line.slice(6);
        skipFile = ignore(file);
      } else if (line.startsWith('@@')) {
        const m = /\+(\d+)/.exec(line);
        newLine = m ? Number(m[1]) : 0;
      } else if (!skipFile && line.startsWith('+') && !line.startsWith('+++')) {
        for (const raw of scanContent(line.slice(1))) {
          const key = `${raw.patternId}:${raw.value}:${file}`;
          if (!seen.has(key)) {
            seen.add(key);
            matches.push({ ...raw, file, commit, line: newLine });
          }
        }
        newLine++;
      } else if (line.startsWith(' ')) {
        newLine++;
      }
    });
    rl.on('close', () => resolve(matches));
  });
}

/** `git ls-files` — the version-controlled file set (empty if not a git repo). */
function listTrackedFiles(root: string): Promise<string[]> {
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

/** Fallback filesystem walk for non-git projects. */
async function walkFiles(root: string, dir = root, out: string[] = []): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (out.length >= 20_000) break;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) await walkFiles(root, full, out);
    } else if (entry.isFile()) {
      out.push(relative(root, full));
    }
  }
  return out;
}
