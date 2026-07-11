import type { ScanContext } from '../types/context';
import type { Finding } from '../types/finding';
import type { Secret } from '../types/secret';
import { scanGitHistory, scanWorkingTree, type FileSecretMatch } from './git-scan';
import { checkPassword } from './hibp';
import { loadIgnore } from './ignore';

export interface SecretsScanResult {
  secrets: Secret[];
  findings: Finding[];
}

export interface SecretsScanOptions {
  /** Walk full git history in addition to the working tree. Default true. */
  history?: boolean;
  /** Run HIBP breach checks on password-type secrets. Default true. */
  breachCheck?: boolean;
}

/**
 * Module 4 entry point: scan the working tree and full git history for committed
 * credentials, then breach-check any password-type findings via HIBP (SPEC.md
 * §4 M4). Produces structured {@link Secret}s and SARIF-ready {@link Finding}s.
 */
export async function scanSecrets(
  root: string,
  ctx: ScanContext,
  options: SecretsScanOptions = {},
): Promise<SecretsScanResult> {
  const ignore = await loadIgnore(root);
  const tree = await scanWorkingTree(root, { ignore });
  const history = options.history === false ? [] : await scanGitHistory(root, { ignore });

  // Dedup by pattern+value+file, preferring the working-tree occurrence (a secret
  // still live in the tree is a current exposure; history-only means it was removed
  // but remains recoverable).
  const byKey = new Map<string, { match: FileSecretMatch; inHistory: boolean }>();
  for (const m of tree) byKey.set(keyOf(m), { match: m, inHistory: false });
  for (const m of history) {
    const key = keyOf(m);
    if (!byKey.has(key)) byKey.set(key, { match: m, inHistory: true });
  }

  const secrets: Secret[] = [];
  const breachCache = new Map<string, { breached: boolean; count: number }>();

  for (const { match, inHistory } of byKey.values()) {
    let breach: { breached: boolean; count: number } | undefined;
    if (match.password && options.breachCheck !== false) {
      breach = breachCache.get(match.value);
      if (!breach) {
        breach = await checkPassword(match.value, ctx);
        breachCache.set(match.value, breach);
      }
    }

    secrets.push({
      kind: match.kind,
      description: match.description,
      preview: match.preview,
      entropy: match.entropy,
      location: {
        file: match.file,
        line: match.line,
        inHistory,
        ...(match.commit ? { commit: match.commit } : {}),
      },
      ...(breach ? { breached: breach.breached } : {}),
      ...(breach && breach.count ? { breachCount: breach.count } : {}),
    });
  }

  secrets.sort(compareSecrets);
  return { secrets, findings: secrets.map(toFinding) };
}

export function summarizeSecrets(secrets: Secret[]): {
  total: number;
  inWorkingTree: number;
  inHistoryOnly: number;
  breached: number;
} {
  let inWorkingTree = 0;
  let breached = 0;
  for (const s of secrets) {
    if (!s.location.inHistory) inWorkingTree += 1;
    if (s.breached) breached += 1;
  }
  return {
    total: secrets.length,
    inWorkingTree,
    inHistoryOnly: secrets.length - inWorkingTree,
    breached,
  };
}

function keyOf(m: FileSecretMatch): string {
  return `${m.patternId}:${m.value}:${m.file}`;
}

function toFinding(secret: Secret): Finding {
  const loc = secret.location;
  const where = loc.inHistory ? ' (git history)' : '';
  const breachNote = secret.breached
    ? ` It appears in ${secret.breachCount ?? 'known'} public breaches.`
    : '';
  const historyNote = loc.inHistory
    ? ' Present in git history — it is permanently recoverable and must be rotated.'
    : ' Rotate this credential and remove it from the codebase.';

  return {
    ruleId: `venom/secret-${secret.kind}`,
    level: 'error',
    category: 'secret',
    title: `${secret.description} in ${loc.file}${where}`,
    message: `${secret.description} detected (${secret.preview}).${breachNote}${historyNote}`,
    locations: [{ uri: loc.file, ...(loc.line ? { startLine: loc.line } : {}) }],
    fingerprint: `${secret.kind}:${secret.preview}:${loc.file}:${loc.commit ?? 'worktree'}`,
    remediation:
      'Rotate the credential; to remove it from history rewrite it (e.g. git filter-repo).',
    properties: {
      kind: secret.kind,
      inHistory: loc.inHistory,
      ...(loc.commit ? { commit: loc.commit } : {}),
      ...(secret.breached !== undefined ? { breached: secret.breached } : {}),
      ...(secret.breachCount ? { breachCount: secret.breachCount } : {}),
    },
  };
}

function compareSecrets(a: Secret, b: Secret): number {
  // Working-tree secrets before history-only; then by file, then line.
  if (a.location.inHistory !== b.location.inHistory) return a.location.inHistory ? 1 : -1;
  const byFile = a.location.file.localeCompare(b.location.file);
  if (byFile !== 0) return byFile;
  return (a.location.line ?? 0) - (b.location.line ?? 0);
}
