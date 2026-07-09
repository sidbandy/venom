/**
 * The kind of credential a match represents. A curated set of well-known kinds
 * plus an open `string` escape hatch for the long tail of the 100+ patterns and
 * generic high-entropy hits (SPEC.md §4 M4).
 */
export type SecretKind =
  | 'aws-access-key'
  | 'aws-secret-key'
  | 'github-pat'
  | 'gitlab-pat'
  | 'stripe-secret'
  | 'google-api-key'
  | 'slack-token'
  | 'private-key'
  | 'jwt'
  | 'generic-password'
  | 'generic-high-entropy'
  | (string & {});

export interface SecretLocation {
  /** Repo-relative path (or the historical path if only present in old commits). */
  file: string;
  line?: number;
  /** Commit sha where found; omitted when the hit is in the working tree. */
  commit?: string;
  /** True when the secret exists only in git history, not the current tree. */
  inHistory: boolean;
}

/**
 * A discovered credential (Module 4). `preview` is always masked — Venom never
 * writes a raw secret to disk, logs, or reports; only a truncated/redacted
 * fragment for human recognition.
 */
export interface Secret {
  kind: SecretKind;
  description: string;
  /** Masked preview, e.g. `AKIA****************`. Never the raw value. */
  preview: string;
  /** Shannon entropy of the candidate, when entropy-based detection applied. */
  entropy?: number;
  location: SecretLocation;
  /** HIBP k-anonymity result for password-like secrets (SPEC.md §4 M4). */
  breached?: boolean;
  breachCount?: number;
}
