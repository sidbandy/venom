import { describe, expect, it } from 'vitest';
import type { AuditResult } from '../audit';
import type { DependencyNode } from '../types/graph';
import { analyzeApiSurface, serviceForPackage } from './api-surface';

function node(name: string, version: string): DependencyNode {
  return {
    ref: { ecosystem: 'npm', name, version },
    direct: true,
    depth: 1,
    scopes: ['production'],
    dependencies: [],
    parents: [],
  };
}

function auditResult(nodes: DependencyNode[], overrides: Partial<AuditResult> = {}): AuditResult {
  const map = new Map(nodes.map((n) => [`${n.ref.ecosystem}:${n.ref.name}@${n.ref.version}`, n]));
  return {
    graph: { root: { name: 'x', path: '/x' }, ecosystems: ['npm'], nodes: map },
    summary: {
      total: nodes.length,
      direct: nodes.length,
      transitive: 0,
      ecosystems: ['npm'],
      maxDepth: 1,
      byEcosystem: { npm: nodes.length },
    },
    vulnerabilities: [],
    assessments: [],
    secrets: [],
    updatePlan: [],
    unusedDependencies: [],
    reachablePackages: new Set(),
    reachableVulnerabilities: [],
    healthScore: { score: 100, grade: 'A', components: [], computedAt: '2026-07-13T00:00:00Z' },
    findings: [],
    ...overrides,
  };
}

describe('serviceForPackage', () => {
  it('maps SDK packages (exact and scoped-prefix) to services', () => {
    expect(serviceForPackage('stripe')).toBe('Stripe');
    expect(serviceForPackage('@aws-sdk/client-s3')).toBe('AWS');
    expect(serviceForPackage('@octokit/rest')).toBe('GitHub');
    expect(serviceForPackage('left-pad')).toBeUndefined();
  });
});

describe('analyzeApiSurface', () => {
  it('groups SDKs by service with CVE, freshness, and leaked-key status', () => {
    const result = auditResult([node('stripe', '8.0.0'), node('@aws-sdk/client-s3', '3.0.0')], {
      vulnerabilities: [
        {
          id: 'CVE-2026-9',
          aliases: ['CVE-2026-9'],
          severity: 'high',
          knownExploited: false,
          affected: { ecosystem: 'npm', name: 'stripe', version: '8.0.0' },
          fixedVersions: ['12.0.0'],
          references: [],
        },
      ],
      updatePlan: [
        {
          current: { ecosystem: 'npm', name: 'stripe', version: '8.0.0' },
          targetVersion: '12.0.0',
          tier: 'risky',
          fixesVulnerabilities: ['CVE-2026-9'],
          breaking: true,
          reason: 'major',
        },
      ],
      secrets: [
        {
          kind: 'stripe-secret',
          description: 'Stripe key',
          preview: 'sk_live_****',
          location: { file: 'config.js', inHistory: false },
        },
      ],
    });

    const { entries, leakedKeysByService } = analyzeApiSurface(result);
    const stripe = entries.find((e) => e.service === 'Stripe')!;
    expect(stripe).toMatchObject({ package: 'stripe', majorBehind: true, outdated: true });
    expect(stripe.cves).toContain('CVE-2026-9');
    expect(entries.find((e) => e.service === 'AWS')?.package).toBe('@aws-sdk/client-s3');
    expect(leakedKeysByService['Stripe']).toBe(1);
  });
});
