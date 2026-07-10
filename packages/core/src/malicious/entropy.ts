/**
 * Shannon entropy in bits per symbol (SPEC.md §4 M3). Normal source code and
 * English sit around 4.0–4.5; base64/encrypted/compressed blobs sit at 5.5–6.0+
 * because they look like structureless noise. An entropy spike in a source file
 * is a strong signal of a hidden encoded payload.
 */
export function shannonEntropy(input: string | Buffer): number {
  const length = input.length;
  if (length === 0) return 0;

  const counts = new Map<number, number>();
  if (typeof input === 'string') {
    for (let i = 0; i < length; i++) increment(counts, input.charCodeAt(i));
  } else {
    for (let i = 0; i < length; i++) increment(counts, input[i]!);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function increment(counts: Map<number, number>, symbol: number): void {
  counts.set(symbol, (counts.get(symbol) ?? 0) + 1);
}

/** Default threshold above which a chunk of source is considered a suspicious blob. */
export const HIGH_ENTROPY_THRESHOLD = 5.2;

/**
 * Scan text for high-entropy runs. Rather than averaging over a whole file
 * (which dilutes a single embedded blob), we look at long, unbroken non-whitespace
 * tokens — the shape an encoded payload takes. Returns the worst offenders.
 */
export function findHighEntropyTokens(
  text: string,
  options: { minTokenLength?: number; threshold?: number; limit?: number } = {},
): Array<{ token: string; entropy: number; line: number }> {
  const minLen = options.minTokenLength ?? 40;
  const threshold = options.threshold ?? HIGH_ENTROPY_THRESHOLD;
  const limit = options.limit ?? 10;

  const hits: Array<{ token: string; entropy: number; line: number }> = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    for (const token of lines[i]!.split(/[\s'"`,;(){}[\]]+/)) {
      if (token.length < minLen) continue;
      const entropy = shannonEntropy(token);
      if (entropy >= threshold) hits.push({ token, entropy, line: i + 1 });
    }
  }
  return hits.sort((a, b) => b.entropy - a.entropy).slice(0, limit);
}
