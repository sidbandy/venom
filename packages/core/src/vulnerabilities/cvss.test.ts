import { describe, expect, it } from 'vitest';
import { computeBaseScore, cvssFromVector, cvssVersionOf, severityFromScore } from './cvss';

describe('computeBaseScore (CVSS 3.1)', () => {
  it('scores canonical vectors correctly', () => {
    // The textbook "worst case" — network, no privileges/interaction, full impact.
    expect(computeBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
    // Local, low privileges, full impact.
    expect(computeBaseScore('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H')).toBe(7.8);
    // No impact → 0.0.
    expect(computeBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(0);
  });

  it('returns undefined for versions it does not score numerically', () => {
    expect(computeBaseScore('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeUndefined();
    expect(computeBaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H')).toBeUndefined();
  });
});

describe('cvss helpers', () => {
  it('detects the vector version', () => {
    expect(cvssVersionOf('CVSS:3.0/AV:N')).toBe('3.0');
    expect(cvssVersionOf('CVSS:3.1/AV:N')).toBe('3.1');
    expect(cvssVersionOf('nonsense')).toBe('3.1');
  });

  it('maps scores to severity buckets', () => {
    expect(severityFromScore(9.8)).toBe('critical');
    expect(severityFromScore(7.0)).toBe('high');
    expect(severityFromScore(4.0)).toBe('medium');
    expect(severityFromScore(0.1)).toBe('low');
    expect(severityFromScore(0)).toBe('none');
  });

  it('builds a structured CvssScore from a scorable vector', () => {
    const cvss = cvssFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(cvss).toEqual({
      version: '3.1',
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      baseScore: 9.8,
    });
  });
});
