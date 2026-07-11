import { describe, expect, it } from 'vitest';
import { classifyBump, compareVersions, isPrerelease } from './version';

describe('compareVersions', () => {
  it('orders npm semver correctly (incl. numeric, not lexical)', () => {
    expect(compareVersions('1.2.3', '1.2.10', 'npm')).toBe(-1);
    expect(compareVersions('2.0.0', '1.9.9', 'npm')).toBe(1);
    expect(compareVersions('1.0.0', '1.0.0', 'npm')).toBe(0);
  });
  it('falls back to numeric compare for PyPI', () => {
    expect(compareVersions('3.0.0', '3.0.1', 'pypi')).toBe(-1);
    expect(compareVersions('10.0', '9.0', 'pypi')).toBe(1);
  });
});

describe('classifyBump', () => {
  it('tiers by the size of the jump', () => {
    expect(classifyBump('1.2.3', '1.2.5', 'npm')).toEqual({ tier: 'safe', breaking: false });
    expect(classifyBump('1.2.3', '1.4.0', 'npm')).toEqual({ tier: 'recommended', breaking: false });
    expect(classifyBump('1.2.3', '2.0.0', 'npm')).toEqual({ tier: 'risky', breaking: true });
  });
  it('handles PyPI component bumps', () => {
    expect(classifyBump('3.0.0', '3.0.4', 'pypi').tier).toBe('safe');
    expect(classifyBump('3.0.0', '4.0.0', 'pypi').tier).toBe('risky');
  });
});

describe('isPrerelease', () => {
  it('detects pre-release versions', () => {
    expect(isPrerelease('1.0.0-rc.1', 'npm')).toBe(true);
    expect(isPrerelease('1.0.0', 'npm')).toBe(false);
    expect(isPrerelease('2.0.0b1', 'pypi')).toBe(true);
    expect(isPrerelease('2.0.0', 'pypi')).toBe(false);
  });
});
