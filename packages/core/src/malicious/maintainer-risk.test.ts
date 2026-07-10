import { describe, expect, it } from 'vitest';
import type { RegistryMetadata } from '../types/registry';
import { assessMaintainerRisk } from './maintainer-risk';

const NOW = new Date('2026-07-09T00:00:00Z');

function meta(partial: Partial<RegistryMetadata>): RegistryMetadata {
  return {
    ref: { ecosystem: 'npm', name: 'x', version: '1.0.0' },
    maintainers: [{ username: 'a' }, { username: 'b' }],
    ...partial,
  };
}

function kinds(m: RegistryMetadata): string[] {
  return assessMaintainerRisk(m, { now: NOW }).map((s) => s.kind);
}

describe('assessMaintainerRisk', () => {
  it('flags a single maintainer', () => {
    expect(kinds(meta({ maintainers: [{ username: 'solo' }] }))).toContain('single-maintainer');
  });

  it('treats an empty maintainer list as unknown, not zero', () => {
    // Registries like PyPI's JSON API don't expose maintainer accounts; absence
    // must not be reported as a risk signal.
    expect(kinds(meta({ maintainers: [] }))).not.toContain('single-maintainer');
  });

  it('flags a recently-registered package', () => {
    expect(kinds(meta({ createdAt: '2026-07-05T00:00:00Z' }))).toContain('recently-registered');
  });

  it('flags a stale package', () => {
    expect(kinds(meta({ lastPublishAt: '2020-01-01T00:00:00Z' }))).toContain('stale');
  });

  it('flags a deprecated package', () => {
    expect(kinds(meta({ deprecated: true }))).toContain('deprecated');
  });

  it('is quiet for a healthy, actively-maintained package', () => {
    expect(
      kinds(meta({ createdAt: '2019-01-01T00:00:00Z', lastPublishAt: '2026-06-01T00:00:00Z' })),
    ).toEqual([]);
  });
});
