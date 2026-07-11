/**
 * Mask a secret value for display. Venom never writes a raw credential to logs,
 * reports, or disk — only a short, recognizable fragment. The masked form keeps
 * enough of the prefix (which is usually the non-secret type marker, e.g. `AKIA`)
 * to identify the finding without disclosing the secret.
 */
export function redact(value: string): string {
  if (value.length <= 4) return '*'.repeat(value.length);
  const visible = Math.min(4, Math.floor(value.length / 3));
  return value.slice(0, visible) + '*'.repeat(Math.min(16, value.length - visible));
}
