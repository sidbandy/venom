/**
 * One weighted input to the composite Supply Chain Health Score (SPEC.md §5).
 * Each component is scored 0–100 in isolation, then combined by `weight`.
 */
export interface HealthComponent {
  /** e.g. `cve-exposure`, `dependency-freshness`, `maintainer-health`. */
  id: string;
  label: string;
  /** This component's subscore, 0–100. */
  score: number;
  /** Relative weight in the composite (weights across components sum to 1). */
  weight: number;
  /** One-line explanation of what drove this subscore. */
  summary: string;
}

export type HealthGrade = 'A' | 'B' | 'C' | 'D' | 'F';

/**
 * The single number that makes Venom "useful every run" (SPEC.md §3.2, §5).
 * Persisted to local SQLite per run to build a trend line.
 */
export interface HealthScore {
  /** Composite score, 0–100. Nobody gets 100 — the point is direction of travel. */
  score: number;
  grade: HealthGrade;
  components: HealthComponent[];
  /** ISO 8601 timestamp of when the score was computed. */
  computedAt: string;
}
