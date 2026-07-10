import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { scanSource, type AstSignal } from './ast-scan';
import { findHighEntropyTokens } from './entropy';

const SOURCE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx']);

export interface SourceFileFinding {
  /** Path relative to the scanned root. */
  file: string;
  astSignals: AstSignal[];
  entropyHits: Array<{ line: number; entropy: number }>;
}

export interface ScanSourceTreeOptions {
  maxFiles?: number;
  maxFileBytes?: number;
}

/**
 * Walk an extracted package directory and run the AST + entropy analyzers over
 * its JavaScript/TypeScript source (SPEC.md §4 M3). Never executes anything — it
 * only reads files as text. Bounded by file count and size so a hostile package
 * can't make the scan run away.
 */
export async function scanSourceTree(
  root: string,
  options: ScanSourceTreeOptions = {},
): Promise<SourceFileFinding[]> {
  const maxFiles = options.maxFiles ?? 300;
  const maxFileBytes = options.maxFileBytes ?? 512 * 1024;

  const files: string[] = [];
  await collectSourceFiles(root, files, maxFiles);

  const findings: SourceFileFinding[] = [];
  for (const file of files) {
    let code: string;
    try {
      const info = await stat(file);
      if (info.size > maxFileBytes) continue;
      code = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    const astSignals = scanSource(code);
    const entropyHits = findHighEntropyTokens(code).map((h) => ({
      line: h.line,
      entropy: Number(h.entropy.toFixed(2)),
    }));
    if (astSignals.length > 0 || entropyHits.length > 0) {
      findings.push({ file: relative(root, file), astSignals, entropyHits });
    }
  }
  return findings;
}

async function collectSourceFiles(dir: string, out: string[], maxFiles: number): Promise<void> {
  if (out.length >= maxFiles) return;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= maxFiles) return;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip nested dependency dirs — we scan the package's own code.
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      await collectSourceFiles(full, out, maxFiles);
    } else if (entry.isFile() && hasSourceExtension(entry.name)) {
      out.push(full);
    }
  }
}

function hasSourceExtension(name: string): boolean {
  const dot = name.lastIndexOf('.');
  return dot >= 0 && SOURCE_EXTENSIONS.has(name.slice(dot));
}
