import { describe, expect, it } from 'vitest';
import type { Finding } from '../types/finding';
import { toSarif } from './sarif';

const findings: Finding[] = [
  {
    ruleId: 'venom/CVE-2021-23337',
    level: 'error',
    category: 'vulnerability',
    title: 'CVE-2021-23337 in lodash@4.17.20',
    message: 'Command injection.',
    locations: [{ uri: 'pkg:npm/lodash@4.17.20' }],
    fingerprint: 'CVE-2021-23337::npm:lodash@4.17.20',
    properties: { severity: 'high' },
  },
  {
    ruleId: 'venom/secret-aws-access-key',
    level: 'error',
    category: 'secret',
    title: 'AWS access key ID in config.js',
    message: 'AWS access key ID detected.',
    locations: [{ uri: 'config.js', startLine: 3 }],
    fingerprint: 'aws-access-key:AKIA****:config.js:worktree',
  },
];

describe('toSarif', () => {
  it('produces a valid SARIF 2.1.0 skeleton', () => {
    const log = toSarif(findings, { toolVersion: '0.1.0' });
    expect(log.version).toBe('2.1.0');
    expect(log.runs).toHaveLength(1);
    expect(log.runs[0]?.tool.driver.name).toBe('Venom');
    expect(log.runs[0]?.results).toHaveLength(2);
  });

  it('registers one rule per distinct ruleId with a security-severity', () => {
    const rules = toSarif(findings).runs[0]!.tool.driver.rules;
    expect(rules.map((r) => r.id).sort()).toEqual([
      'venom/CVE-2021-23337',
      'venom/secret-aws-access-key',
    ]);
    expect(rules[0]?.properties['security-severity']).toBe('8.0');
  });

  it('carries locations, levels, and fingerprints onto results', () => {
    const result = toSarif(findings).runs[0]!.results[1]!;
    expect(result.level).toBe('error');
    expect(result.locations[0]?.physicalLocation.artifactLocation.uri).toBe('config.js');
    expect(result.locations[0]?.physicalLocation.region?.startLine).toBe(3);
    expect(result.partialFingerprints.venomFingerprint).toBe(
      'aws-access-key:AKIA****:config.js:worktree',
    );
  });

  it('references only rules that are declared (referential integrity)', () => {
    const log = toSarif(findings);
    const ruleIds = new Set(log.runs[0]!.tool.driver.rules.map((r) => r.id));
    for (const result of log.runs[0]!.results) {
      expect(ruleIds.has(result.ruleId)).toBe(true);
    }
  });
});
