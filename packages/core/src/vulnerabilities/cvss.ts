import type { CvssScore, CvssVersion, VulnSeverity } from '../types/vulnerability';

/**
 * A minimal, dependency-free CVSS base-score calculator. Advisories (via OSV)
 * carry a CVSS *vector string* but not always a numeric base score, and policy
 * gating (`.venom.yml` max_cvss_severity) needs the number. We compute CVSS
 * v3.0/3.1 base scores precisely from the vector; other versions fall back to a
 * severity bucket derived elsewhere.
 */

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
const AC = { L: 0.77, H: 0.44 } as const;
const UI = { N: 0.85, R: 0.62 } as const;
const IMPACT_METRIC = { H: 0.56, L: 0.22, N: 0 } as const;

/** Parse a CVSS vector string into its metric map, e.g. `AV:N` → `{ AV: 'N' }`. */
export function parseCvssVector(vector: string): Record<string, string> {
  const metrics: Record<string, string> = {};
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (!key || value === undefined) continue;
    if (key === 'CVSS') continue; // version prefix, handled separately
    metrics[key] = value;
  }
  return metrics;
}

/** Detect the CVSS version declared in a vector string (defaults to 3.1). */
export function cvssVersionOf(vector: string): CvssVersion {
  const match = /^CVSS:(\d\.\d)/.exec(vector);
  const v = match?.[1];
  if (v === '2.0' || v === '3.0' || v === '3.1' || v === '4.0') return v;
  // v2 vectors are frequently bare (no CVSS: prefix); the `Au:` metric is v2-only.
  if (/(?:^|\/)Au:/.test(vector)) return '2.0';
  return '3.1';
}

/**
 * Compute a CVSS base score from a vector string. Supports v2.0 and v3.0/3.1
 * precisely; returns `undefined` for v4 (whose scoring is materially more complex)
 * or malformed input.
 */
export function computeBaseScore(vector: string): number | undefined {
  const version = cvssVersionOf(vector);
  if (version === '2.0') return computeBaseScoreV2(vector);
  if (version !== '3.0' && version !== '3.1') return undefined;

  const m = parseCvssVector(vector);
  const scopeChanged = m.S === 'C';

  const av = AV[m.AV as keyof typeof AV];
  const ac = AC[m.AC as keyof typeof AC];
  const ui = UI[m.UI as keyof typeof UI];
  const pr = privilegesRequired(m.PR, scopeChanged);
  const c = IMPACT_METRIC[m.C as keyof typeof IMPACT_METRIC];
  const i = IMPACT_METRIC[m.I as keyof typeof IMPACT_METRIC];
  const a = IMPACT_METRIC[m.A as keyof typeof IMPACT_METRIC];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return undefined;

  const iscBase = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * (iscBase - 0.02) ** 15
    : 6.42 * iscBase;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av! * ac! * ui! * pr!;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp(raw);
}

// --- CVSS v2 ---
const V2_AV = { L: 0.395, A: 0.646, N: 1.0 } as const;
const V2_AC = { H: 0.35, M: 0.61, L: 0.71 } as const;
const V2_AU = { M: 0.45, S: 0.56, N: 0.704 } as const;
const V2_IMPACT = { N: 0.0, P: 0.275, C: 0.66 } as const;

/** Compute a CVSS v2.0 base score from its vector (the classic pre-v3 formula). */
function computeBaseScoreV2(vector: string): number | undefined {
  const m = parseCvssVector(vector);
  const av = V2_AV[m.AV as keyof typeof V2_AV];
  const ac = V2_AC[m.AC as keyof typeof V2_AC];
  const au = V2_AU[m.Au as keyof typeof V2_AU];
  const c = V2_IMPACT[m.C as keyof typeof V2_IMPACT];
  const i = V2_IMPACT[m.I as keyof typeof V2_IMPACT];
  const a = V2_IMPACT[m.A as keyof typeof V2_IMPACT];
  if ([av, ac, au, c, i, a].some((x) => x === undefined)) return undefined;

  const impact = 10.41 * (1 - (1 - c!) * (1 - i!) * (1 - a!));
  const exploitability = 20 * av! * ac! * au!;
  const fImpact = impact === 0 ? 0 : 1.176;
  const base = (0.6 * impact + 0.4 * exploitability - 1.5) * fImpact;
  return Math.round(base * 10) / 10;
}

function privilegesRequired(value: string | undefined, scopeChanged: boolean): number | undefined {
  switch (value) {
    case 'N':
      return 0.85;
    case 'L':
      return scopeChanged ? 0.68 : 0.62;
    case 'H':
      return scopeChanged ? 0.5 : 0.27;
    default:
      return undefined;
  }
}

/** CVSS 3.1 Roundup: round up to one decimal place, float-safe (per the spec). */
function roundUp(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** Map a numeric base score to the qualitative severity buckets (CVSS 3.1 ranges). */
export function severityFromScore(score: number): VulnSeverity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

/** Map a textual severity label (as OSV `database_specific.severity`) to a bucket. */
export function severityFromLabel(label: string | undefined): VulnSeverity {
  switch (label?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'unknown';
  }
}

/** Build a structured {@link CvssScore} from a vector string, if scorable. */
export function cvssFromVector(vector: string): CvssScore | undefined {
  const baseScore = computeBaseScore(vector);
  if (baseScore === undefined) return undefined;
  return { version: cvssVersionOf(vector), vectorString: vector, baseScore };
}
