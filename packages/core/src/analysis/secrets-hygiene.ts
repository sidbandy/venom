import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding } from '../types/finding';

export interface HygieneResult {
  findings: Finding[];
}

/** Files that commonly hold secrets and should be git-ignored. */
const SHOULD_IGNORE = ['.env', '*.pem', '*.key', 'credentials.json'];

/**
 * Secrets-hygiene check (SPEC.md §5): even with zero currently-leaked secrets, is
 * the project set up to avoid leaking them? Verifies `.gitignore` covers common
 * secret-bearing files and that a `.env.example` documents required variables.
 * Purely local file checks.
 */
export async function checkSecretsHygiene(projectRoot: string): Promise<HygieneResult> {
  const findings: Finding[] = [];

  const gitignore = await readTextOrNull(join(projectRoot, '.gitignore'));
  if (gitignore === null) {
    findings.push(
      hygiene(
        'venom/hygiene-gitignore',
        'warning',
        'No .gitignore',
        '.gitignore',
        'This project has no .gitignore — secret files can be committed by accident.',
      ),
    );
  } else {
    const lines = gitignore.split(/\r?\n/).map((l) => l.trim());
    for (const pattern of SHOULD_IGNORE) {
      const covered = lines.some(
        (l) => l === pattern || l === `/${pattern}` || l === `**/${pattern}`,
      );
      if (!covered) {
        findings.push(
          hygiene(
            'venom/hygiene-gitignore',
            'note',
            `.gitignore missing "${pattern}"`,
            '.gitignore',
            `.gitignore does not cover "${pattern}", a common secret-bearing file.`,
          ),
        );
      }
    }
  }

  const hasEnv = await exists(join(projectRoot, '.env'));
  const hasEnvExample =
    (await exists(join(projectRoot, '.env.example'))) ||
    (await exists(join(projectRoot, '.env.sample')));
  if (hasEnv && !hasEnvExample) {
    findings.push(
      hygiene(
        'venom/hygiene-env-example',
        'note',
        'No .env.example',
        '.env.example',
        'Project uses a .env but has no .env.example documenting required variables (without real values).',
      ),
    );
  }

  return { findings };
}

function hygiene(
  ruleId: string,
  level: Finding['level'],
  title: string,
  uri: string,
  message: string,
): Finding {
  return {
    ruleId,
    level,
    category: 'hygiene',
    title,
    message,
    locations: [{ uri }],
    fingerprint: `${ruleId}:${title}`,
  };
}

async function readTextOrNull(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return null;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
