/**
 * Levenshtein (edit) distance between two strings — the number of single-character
 * insertions, deletions, or substitutions to turn one into the other. Used for
 * typosquat detection (SPEC.md §4 M3): a tiny distance between an unknown package
 * and a hugely popular one is a strong red flag.
 *
 * Includes an early-exit `max`: if the distance provably exceeds `max`, returns
 * `max + 1` without finishing — this makes scanning a name against thousands of
 * popular names cheap.
 */
export function levenshtein(a: string, b: string, max = Infinity): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  if (Math.abs(a.length - b.length) > max) return max + 1;

  // Two-row dynamic programming (O(min) memory).
  let prev = new Array<number>(b.length + 1);
  let curr = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
      if (curr[j]! < rowMin) rowMin = curr[j]!;
    }
    // If the best achievable on this row already exceeds max, stop early.
    if (rowMin > max) return max + 1;
    [prev, curr] = [curr, prev];
  }
  return prev[b.length]!;
}
