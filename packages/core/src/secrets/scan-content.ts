import type { SecretKind } from '../types/secret';
import { shannonEntropy } from '../malicious/entropy';
import { SECRET_PATTERNS } from './patterns';
import { redact } from './redact';

export interface RawSecretMatch {
  patternId: string;
  kind: SecretKind;
  description: string;
  /** Raw value — used transiently for dedup/breach checks, never written to output. */
  value: string;
  /** Redacted preview safe to display. */
  preview: string;
  entropy: number;
  line: number;
  password: boolean;
}

export interface ScanContentOptions {
  /** Skip content larger than this many characters. Default 1 MiB. */
  maxBytes?: number;
}

const NUL = String.fromCharCode(0);

// Common placeholder/dummy values. Entropy alone can't filter dictionary-word
// placeholders (they have moderate entropy), so generic password/secret matches
// are additionally checked against this list. Structured tokens (AWS, GitHub, …)
// are NOT filtered — a real key with a distinctive prefix is real even if it
// happens to contain one of these words.
const PLACEHOLDER_RE =
  /example|changeme|placeholder|your[_-]?|x{4,}|<[a-z]|\{\{|todo|fixme|dummy|sample|redacted|^password$|^secret$|test|foobar|123456|abcdef/i;

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value);
}

/**
 * Scan a text blob for credential patterns (SPEC.md §4 M4). Binary content and
 * oversized blobs are skipped; entropy-gated patterns reject low-entropy
 * placeholders (`password = "changeme"`). Returns raw matches with redacted
 * previews and line numbers.
 */
export function scanContent(text: string, options: ScanContentOptions = {}): RawSecretMatch[] {
  const maxBytes = options.maxBytes ?? 1024 * 1024;
  // Skip oversized blobs and binary content (detected by a NUL byte).
  if (text.length > maxBytes || text.includes(NUL)) return [];

  const results: RawSecretMatch[] = [];
  const seen = new Set<string>();
  const lineStarts = computeLineStarts(text);

  for (const pattern of SECRET_PATTERNS) {
    for (const match of text.matchAll(pattern.regex)) {
      const value = match[1] ?? match[0];
      if (!value) continue;
      const entropy = shannonEntropy(value);
      if (pattern.minEntropy !== undefined && entropy < pattern.minEntropy) continue;
      // Filter obvious placeholders on the loosely-structured generic patterns only.
      if ((pattern.password || pattern.id === 'generic-secret') && isPlaceholder(value)) continue;

      const index = match.index ?? 0;
      const key = `${pattern.id}:${value}:${index}`;
      if (seen.has(key)) continue;
      seen.add(key);

      results.push({
        patternId: pattern.id,
        kind: pattern.kind,
        description: pattern.description,
        value,
        preview: redact(value),
        entropy: Number(entropy.toFixed(2)),
        line: lineOf(lineStarts, index),
        password: pattern.password ?? false,
      });
    }
  }
  return results;
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/** 1-based line number for a character offset (binary search over line starts). */
function lineOf(lineStarts: number[], index: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  let ans = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (lineStarts[mid]! <= index) {
      ans = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return ans + 1;
}
