import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export type IgnoreMatcher = (relativePath: string) => boolean;

/**
 * Load `.venomignore` from the project root — a gitignore-style list of glob
 * patterns for files the secrets scanner should skip (test fixtures, sample
 * configs, documentation with example credentials). Supports `#` comments and
 * `*` / `**` / `?` globs. Absent file → matches nothing.
 */
export async function loadIgnore(root: string): Promise<IgnoreMatcher> {
  let content: string;
  try {
    content = await readFile(join(root, '.venomignore'), 'utf8');
  } catch {
    return () => false;
  }
  const patterns = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
    .map(globToRegExp);
  return (relativePath) => patterns.some((re) => re.test(relativePath));
}

/** Convert a gitignore-style glob to an anchored RegExp (`**`, `*`, `?`). */
function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
        if (glob[i + 1] === '/') i++;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '.';
    } else if ('\\^$.|+()[]{}'.includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}
