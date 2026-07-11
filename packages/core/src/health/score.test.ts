import { describe, expect, it } from 'vitest';
import type { InventorySummary } from '../inventory/build-graph';
import type { Vulnerability } from '../types/vulnerability';
import type { Secret } from '../types/secret';
import { computeHealthScore, type HealthInputs } from './score';

const summary: InventorySummary = {
  total: 10,
  direct: 5,
  transitive: 5,
  ecosystems: ['npm'],
  maxDepth: 3,
  byEcosystem: { npm: 10 },
};

function inputs(overrides: Partial<HealthInputs> = {}): HealthInputs {
  return {
    summary,
    vulnerabilities: [],
    assessments: [],
    secrets: [],
    updatePlan: [],
    ...overrides,
  };
}

const criticalVuln: Vulnerability = {
  id: 'CVE-2026-0001',
  aliases: ['CVE-2026-0001'],
  severity: 'critical',
  knownExploited: true,
  affected: { ecosystem: 'npm', name: 'bad', version: '1.0.0' },
  fixedVersions: [],
  references: [],
};

const liveSecret: Secret = {
  kind: 'aws-access-key',
  description: 'AWS access key ID',
  preview: 'AKIA****',
  location: { file: 'config.js', inHistory: false },
};

describe('computeHealthScore', () => {
  it('gives a clean project a top grade', () => {
    const result = computeHealthScore(inputs(), { now: new Date('2026-07-11T00:00:00Z') });
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
    expect(result.components.map((c) => c.id)).toContain('cve-exposure');
  });

  it('drops the score for a critical CVE and a live secret', () => {
    const clean = computeHealthScore(inputs()).score;
    const dirty = computeHealthScore(
      inputs({ vulnerabilities: [criticalVuln], secrets: [liveSecret] }),
    ).score;
    expect(dirty).toBeLessThan(clean);
    // CVE (40% penalty on 0.35) + secret (40% penalty on 0.25) should move it well down.
    expect(dirty).toBeLessThan(85);
  });

  it('weights components to sum to 1 and clamps subscores to 0–100', () => {
    const result = computeHealthScore(inputs({ vulnerabilities: Array(20).fill(criticalVuln) }));
    const totalWeight = result.components.reduce((s, c) => s + c.weight, 0);
    expect(totalWeight).toBeCloseTo(1);
    for (const c of result.components) {
      expect(c.score).toBeGreaterThanOrEqual(0);
      expect(c.score).toBeLessThanOrEqual(100);
    }
  });

  it('omits the freshness component when no update plan is provided', () => {
    const result = computeHealthScore(inputs({ updatePlan: undefined }));
    expect(result.components.map((c) => c.id)).not.toContain('dependency-freshness');
    expect(result.components.reduce((s, c) => s + c.weight, 0)).toBeCloseTo(0.85);
  });
});
