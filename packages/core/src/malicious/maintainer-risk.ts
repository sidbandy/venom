import type { RegistryMetadata } from '../types/registry';

export type MaintainerRiskKind =
  'single-maintainer' | 'recently-registered' | 'stale' | 'deprecated';

export interface MaintainerRiskSignal {
  kind: MaintainerRiskKind;
  detail: string;
  /** Suggested finding level for this signal. */
  level: 'warning' | 'note';
}

export interface MaintainerRiskOptions {
  /** Clock injection for deterministic tests. Defaults to now. */
  now?: Date;
  /** A package first published within this many days is "recently registered". */
  recentDays?: number;
  /** A package not published in this many days is "stale". */
  staleDays?: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Score maintainer/ownership risk from registry metadata (SPEC.md §4 M3). The
 * canonical failure mode is `event-stream`: a single maintainer with no backup
 * hands the package off. We also flag brand-new packages (typosquat/one-off
 * attack shape), long-abandoned ones, and deprecations.
 */
export function assessMaintainerRisk(
  meta: RegistryMetadata,
  options: MaintainerRiskOptions = {},
): MaintainerRiskSignal[] {
  const now = options.now ?? new Date();
  const recentDays = options.recentDays ?? 30;
  const staleDays = options.staleDays ?? 540; // ~18 months
  const signals: MaintainerRiskSignal[] = [];

  // An empty list means "unknown" (some registries — notably PyPI's JSON API —
  // don't expose maintainer accounts), NOT "zero maintainers". We only emit a
  // signal when we positively know there is exactly one.
  if (meta.maintainers.length === 1) {
    signals.push({
      kind: 'single-maintainer',
      detail: 'Single maintainer — a single point of compromise or burnout-driven handoff',
      level: 'warning',
    });
  }

  const ageDays = daysBetween(meta.createdAt, now);
  if (ageDays !== undefined && ageDays <= recentDays) {
    signals.push({
      kind: 'recently-registered',
      detail: `Package first published ${Math.round(ageDays)} day(s) ago`,
      level: 'warning',
    });
  }

  const sinceUpdate = daysBetween(meta.lastPublishAt, now);
  if (sinceUpdate !== undefined && sinceUpdate >= staleDays) {
    signals.push({
      kind: 'stale',
      detail: `Last published ${Math.round(sinceUpdate / 30)} month(s) ago`,
      level: 'note',
    });
  }

  if (meta.deprecated) {
    signals.push({ kind: 'deprecated', detail: 'Package is deprecated', level: 'warning' });
  }

  return signals;
}

function daysBetween(iso: string | undefined, now: Date): number | undefined {
  if (!iso) return undefined;
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return undefined;
  return (now.getTime() - then) / DAY_MS;
}
