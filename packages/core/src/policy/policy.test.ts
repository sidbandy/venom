import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditResult } from '../audit';
import type { Vulnerability } from '../types/vulnerability';
import type { Secret } from '../types/secret';
import type { Finding } from '../types/finding';
import { loadPolicy } from './load';
import { evaluatePolicy } from './evaluate';

const tmpDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function tmpWith(file: string, content: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'venom-policy-'));
  tmpDirs.push(dir);
  await writeFile(join(dir, file), content);
  return dir;
}

describe('loadPolicy', () => {
  it('maps snake_case .venom.yml to the camelCase Policy', async () => {
    const dir = await tmpWith(
      '.venom.yml',
      'policy:\n  max_cvss_severity: 7\n  block_on_kev: true\n  license_denylist:\n    - AGPL-3.0\n',
    );
    expect(await loadPolicy(dir)).toEqual({
      maxCvssSeverity: 7,
      blockOnKev: true,
      licenseDenylist: ['AGPL-3.0'],
    });
  });

  it('returns undefined when no policy file exists', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'venom-policy-'));
    tmpDirs.push(dir);
    expect(await loadPolicy(dir)).toBeUndefined();
  });

  it('throws on a malformed policy', async () => {
    const dir = await tmpWith('.venom.yml', 'policy:\n  max_cvss_severity: "high"\n');
    await expect(loadPolicy(dir)).rejects.toThrow(/Invalid/);
  });
});

function auditResult(overrides: Partial<AuditResult>): AuditResult {
  return {
    graph: { root: { name: 'x', path: '/x' }, ecosystems: ['npm'], nodes: new Map() },
    summary: {
      total: 0,
      direct: 0,
      transitive: 0,
      ecosystems: ['npm'],
      maxDepth: 0,
      byEcosystem: {},
    },
    vulnerabilities: [],
    assessments: [],
    secrets: [],
    updatePlan: [],
    unusedDependencies: [],
    healthScore: { score: 100, grade: 'A', components: [], computedAt: '2026-07-11T00:00:00Z' },
    findings: [],
    ...overrides,
  };
}

const kevVuln: Vulnerability = {
  id: 'CVE-2026-1',
  aliases: [],
  severity: 'critical',
  knownExploited: true,
  cvss: { version: '3.1', vectorString: '', baseScore: 9.8 },
  affected: { ecosystem: 'npm', name: 'x', version: '1.0.0' },
  fixedVersions: [],
  references: [],
};

const secret: Secret = {
  kind: 'aws-access-key',
  description: 'AWS key',
  preview: 'AKIA****',
  location: { file: 'a.js', inHistory: false },
};

const denylistFinding: Finding = {
  ruleId: 'venom/license-denylist',
  level: 'error',
  category: 'license',
  title: 'x: AGPL-3.0',
  message: 'denied',
  locations: [],
  fingerprint: 'x',
};

describe('evaluatePolicy', () => {
  it('blocks on secrets, KEV, CVSS threshold, and denylisted licenses', () => {
    expect(
      evaluatePolicy(auditResult({ secrets: [secret] }), { blockOnSecrets: true }).passed,
    ).toBe(false);
    expect(
      evaluatePolicy(auditResult({ vulnerabilities: [kevVuln] }), { blockOnKev: true }).passed,
    ).toBe(false);
    expect(
      evaluatePolicy(auditResult({ vulnerabilities: [kevVuln] }), { maxCvssSeverity: 7 }).passed,
    ).toBe(false);
    expect(
      evaluatePolicy(auditResult({ findings: [denylistFinding] }), {
        licenseDenylist: ['AGPL-3.0'],
      }).passed,
    ).toBe(false);
  });

  it('passes a clean project under a full policy', () => {
    const evaln = evaluatePolicy(auditResult({}), {
      blockOnSecrets: true,
      blockOnKev: true,
      maxCvssSeverity: 7,
      licenseDenylist: ['AGPL-3.0'],
    });
    expect(evaln.passed).toBe(true);
    expect(evaln.violations).toEqual([]);
  });

  it('treats min_maintainers as a warning, not a block', () => {
    const result = auditResult({
      assessments: [
        {
          ref: { ecosystem: 'npm', name: 'solo', version: '1.0.0' },
          verdict: 'caution',
          reasons: [],
          findings: [
            {
              ruleId: 'venom/maintainer-risk',
              level: 'warning',
              category: 'maintainer-risk',
              title: 'solo',
              message: 'Single maintainer',
              locations: [],
              fingerprint: 'solo',
            },
          ],
        },
      ],
    });
    const evaln = evaluatePolicy(result, { minMaintainers: 2 });
    expect(evaln.passed).toBe(true);
    expect(evaln.warnings.length).toBe(1);
  });
});
